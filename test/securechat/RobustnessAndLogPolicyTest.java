package securechat;

import securechat.client.Client;
import securechat.common.CertUtil;
import securechat.common.Constants;
import securechat.common.Messages;
import securechat.common.SecureLog;
import securechat.server.Server;

import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Testes automatizados da T10 (Robustez do servidor contra clientes malformados/maliciosos,
 * limite {@code MAX_CLIENTS} e auditoria automática da política de logs).
 */
public final class RobustnessAndLogPolicyTest {

    private RobustnessAndLogPolicyTest() {
    }

    /**
     * T10.1: Servidor sobrevive a conexões que enviam EOF imediato, cabeçalhos truncados,
     * payloads truncados, bytes aleatórios no socket e tipos de frame inválidos, mantendo
     * as sessões legítimas ativas.
     */
    public static void testServerSurvivesRandomBytesEofAndMalformedTraffic() throws Exception {
        CertUtil.ServerIdentity identity = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinned = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        try (Server server = new Server(0, identity, 20, 2000);
             Client alice = new Client(pinned);
             Client bob = new Client(pinned)) {

            server.start();
            int port = server.getPort();

            alice.connect("127.0.0.1", port);
            bob.connect("127.0.0.1", port);
            Assert.assertTrue(alice.awaitInitialSync(3000), "Alice sincroniza");
            Assert.assertTrue(bob.awaitInitialSync(3000), "Bob sincroniza");

            // Ataque 1: conexão que fecha imediatamente (EOF limpo antes de qualquer byte)
            try (Socket s1 = new Socket("127.0.0.1", port)) {
                Assert.assertTrue(s1.isConnected(), "s1 conectou");
            }

            // Ataque 2: cabeçalho de 4 bytes truncado (apenas 2 bytes enviados antes do EOF)
            try (Socket s2 = new Socket("127.0.0.1", port)) {
                s2.getOutputStream().write(new byte[]{0x00, 0x10});
                s2.getOutputStream().flush();
            }

            // Ataque 3: tamanho declarado = 120 bytes, mas envia apenas 10 bytes e fecha (EOF no meio)
            try (Socket s3 = new Socket("127.0.0.1", port);
                 DataOutputStream out = new DataOutputStream(s3.getOutputStream())) {
                out.writeInt(120);
                out.write(new byte[10]);
                out.flush();
            }

            // Ataque 4: enxurrada de bytes pseudoaleatórios no socket
            SecureRandom rng = new SecureRandom();
            for (int i = 0; i < 5; i++) {
                try (Socket s4 = new Socket("127.0.0.1", port)) {
                    byte[] garbage = new byte[256];
                    rng.nextBytes(garbage);
                    s4.getOutputStream().write(garbage);
                    s4.getOutputStream().flush();
                } catch (IOException ignored) {
                    // Servidor pode fechar o socket assim que ler os primeiros 4 bytes inválidos
                }
            }

            // Ataque 5: tamanho de frame válido (65 bytes), mas byte type = 0x7F inválido no handshake
            try (Socket s5 = new Socket("127.0.0.1", port);
                 DataOutputStream out = new DataOutputStream(s5.getOutputStream())) {
                out.writeInt(65);
                out.writeByte(0x7F);
                out.write(new byte[64]);
                out.flush();
            }

            // Verifica que o servidor continua vivo e roteando mensagens E2E entre Alice e Bob
            awaitCondition(() -> alice.peerTable().get(bob.selfId()) != null, 3000);
            CompletableFuture<String> bobGot = new CompletableFuture<>();
            bob.setMessageListener((from, msg) -> bobGot.complete(msg));

            alice.sendMessage(bob.selfId(), "Servidor sobreviveu a trafego malicioso!");
            Assert.assertEquals(
                    "Servidor sobreviveu a trafego malicioso!",
                    bobGot.get(3, TimeUnit.SECONDS),
                    "Bob deve receber a mensagem E2E normalmente após os ataques de bytes aleatórios");
        }
    }

    /**
     * T10.2: Servidor impõe {@code MAX_CLIENTS} enviando {@code CONTROL(ERROR, ERR_SERVER_FULL)}
     * à conexão excedente sem afetar os clientes já ativos, e libera a vaga após desconexão.
     */
    public static void testServerMaxClientsLimitAndRecovery() throws Exception {
        CertUtil.ServerIdentity identity = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinned = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        try (Server server = new Server(0, identity, 2, 3000);
             Client c1 = new Client(pinned);
             Client c3 = new Client(pinned);
             Client c4 = new Client(pinned)) {

            server.start();
            int port = server.getPort();

            c1.connect("127.0.0.1", port);
            Assert.assertTrue(c1.awaitInitialSync(3000), "c1 sincroniza");

            try (Client c2 = new Client(pinned)) {
                c2.connect("127.0.0.1", port);
                Assert.assertTrue(c2.awaitInitialSync(3000), "c2 sincroniza");
                Assert.assertEquals(2, server.registry().size(), "2 sessões ativas no limite MAX_CLIENTS=2");

                // 3º cliente excede MAX_CLIENTS=2 -> deve receber CONTROL(ERROR, ERR_SERVER_FULL)
                CompletableFuture<Messages.ErrorMsg> errFuture = new CompletableFuture<>();
                c3.setErrorListener(errFuture::complete);
                c3.connect("127.0.0.1", port);

                Messages.ErrorMsg err = errFuture.get(3, TimeUnit.SECONDS);
                Assert.assertEquals(Constants.ERR_SERVER_FULL, err.errorCode(),
                        "c3 deve receber código ERR_SERVER_FULL");
            }
            // Ao sair do bloco try-with-resources acima, c2 desconectou e liberou 1 vaga no semáforo
            awaitCondition(() -> server.registry().size() == 1, 3000);

            c4.connect("127.0.0.1", port);
            Assert.assertTrue(c4.awaitInitialSync(3000), "c4 sincroniza após liberação de vaga");
            awaitCondition(() -> c1.peerTable().get(c4.selfId()) != null, 3000);

            CompletableFuture<String> c4Got = new CompletableFuture<>();
            c4.setMessageListener((from, text) -> c4Got.complete(text));
            c1.sendMessage(c4.selfId(), "Vaga liberada com sucesso");
            Assert.assertEquals("Vaga liberada com sucesso", c4Got.get(3, TimeUnit.SECONDS),
                    "c4 recebe mensagem E2E de c1");
        }
    }

    /**
     * T10.3: Auditoria automatizada da política de logs no código-fonte ({@code src/}):
     * <ul>
     *   <li>Nenhum arquivo fora de {@code SecureLog.java} e {@code Cli.java} pode conter
     *       {@code System.out}, {@code System.err}, {@code printStackTrace} ou {@code Logger}.</li>
     *   <li>{@link SecureLog} não pode expor nenhum método público que receba {@code byte[]}.</li>
     * </ul>
     */
    public static void testSourceCodeLogPolicyAudit() throws Exception {
        for (Method m : SecureLog.class.getDeclaredMethods()) {
            if (Modifier.isPublic(m.getModifiers())) {
                for (Class<?> paramType : m.getParameterTypes()) {
                    Assert.assertFalse(paramType.equals(byte[].class),
                            "SecureLog não pode ter método público que aceite byte[] arbitrário: " + m.getName());
                }
            }
        }

        List<Path> javaFiles;
        try (Stream<Path> walk = Files.walk(Path.of("src"))) {
            javaFiles = walk.filter(p -> p.toString().endsWith(".java")).toList();
        }
        Assert.assertTrue(!javaFiles.isEmpty(), "Deve encontrar arquivos .java em src/");

        for (Path file : javaFiles) {
            String fileName = file.getFileName().toString();
            String content = Files.readString(file, StandardCharsets.UTF_8);

            Assert.assertFalse(content.contains("printStackTrace"),
                    "Proibido printStackTrace em " + file);
            Assert.assertFalse(content.contains("System.err"),
                    "Proibido System.err em " + file);
            Assert.assertFalse(content.contains("java.util.logging"),
                    "Proibido java.util.logging em " + file);
            Assert.assertFalse(content.contains("System.Logger"),
                    "Proibido System.Logger em " + file);

            if (!fileName.equals("SecureLog.java") && !fileName.equals("Cli.java")) {
                Assert.assertFalse(content.contains("System.out"),
                        "Proibido System.out fora de SecureLog.java e Cli.java (encontrado em " + file + ")");
            }
        }
    }

    private static void awaitCondition(BooleanSupplierWithException cond, long timeoutMs)
            throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (cond.getAsBoolean()) {
                return;
            }
            Thread.sleep(25);
        }
        Assert.assertTrue(false, "Condição não atingida dentro de " + timeoutMs + " ms");
    }

    @FunctionalInterface
    private interface BooleanSupplierWithException {
        boolean getAsBoolean() throws Exception;
    }
}
