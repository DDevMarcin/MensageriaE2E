package securechat.tools;

import securechat.client.Client;
import securechat.common.Bytes;
import securechat.common.CertUtil;
import securechat.common.Constants;
import securechat.common.ProtocolException;
import securechat.common.SecureLog;
import securechat.server.Server;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Executor automatizado de demonstrações ao vivo para apresentação ao professor (T11).
 *
 * <p>Permite rodar cada cenário obrigatório com logs visíveis passo a passo via {@link SecureLog}:</p>
 * <ul>
 *   <li>{@code e2e}: sobe o Servidor, o {@link TamperProxy} em modo {@code SNIFF} e 3 clientes
 *       (Alice, Bob e Carol), exibindo fingerprints das chaves públicas e trocando mensagens
 *       cifradas ponta-a-ponta entre todos eles.</li>
 *   <li>{@code bitflip}: sobe Servidor, {@link TamperProxy} em modo {@code BITFLIP} e 2 clientes
 *       (Alice e Bob); demonstra a rejeição da 1ª mensagem adulterada por falha na tag GCM sem
 *       avançar {@code seqRecv} e a entrega normal da 2ª mensagem.</li>
 *   <li>{@code replay}: sobe Servidor, {@link TamperProxy} em modo {@code REPLAY} e 2 clientes
 *       (Alice e Bob); demonstra que a cópia duplicada da 1ª mensagem é descartada pelo contador
 *       monotônico {@code seq_no <= seqRecv}.</li>
 *   <li>{@code badframe}: sobe Servidor, {@link TamperProxy} em modo {@code BADFRAME} e 3 clientes
 *       (Alice via proxy, Bob e Carol diretos); demonstra que um frame com tamanho inválido
 *       desconecta apenas o cliente infrator e preserva a conversa E2E entre Bob e Carol.</li>
 *   <li>{@code all}: executa os 4 cenários em sequência.</li>
 * </ul>
 */
public final class DemoScenarioRunner {

    private DemoScenarioRunner() {
    }

    public static void main(String[] args) {
        SecureLog.setSilent(false);
        String scenario = args.length >= 1 ? args[0].trim().toLowerCase(Locale.ROOT) : "all";

        try {
            switch (scenario) {
                case "e2e" -> runDemoE2e();
                case "bitflip" -> runDemoBitflip();
                case "replay" -> runDemoReplay();
                case "badframe" -> runDemoBadframe();
                case "all" -> {
                    runDemoE2e();
                    runDemoBitflip();
                    runDemoReplay();
                    runDemoBadframe();
                }
                default -> {
                    SecureLog.error("Cenário desconhecido: " + scenario,
                            "Use: e2e | bitflip | replay | badframe | all");
                    System.exit(1);
                }
            }
        } catch (Exception e) {
            SecureLog.error("Falha durante execução da demo (" + scenario + ")", e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Cenário 1: Mensageria E2E multi-cliente (Alice, Bob e Carol) + Sniff no fio.
     */
    public static void runDemoE2e() throws Exception {
        SecureLog.info("==================================================================");
        SecureLog.info("DEMO 1: Mensageria E2E Multi-Cliente (Alice, Bob, Carol) + SNIFF");
        SecureLog.info("==================================================================");

        CertUtil.ServerIdentity identity = loadServerIdentity();
        X509Certificate pinned = loadPinnedCert();

        try (Server server = new Server(0, identity);
             TamperProxy sniffProxy = new TamperProxy(
                     TamperProxy.Mode.SNIFF, 0, "127.0.0.1", server.getPort());
             Client alice = new Client(pinned);
             Client bob = new Client(pinned);
             Client carol = new Client(pinned)) {

            server.start();
            sniffProxy.start();

            alice.setMessageListener((from, msg) ->
                    SecureLog.info("[Alice recebeu E2E de " + from.shortHex() + "]: \"" + msg + "\""));
            bob.setMessageListener((from, msg) ->
                    SecureLog.info("[Bob recebeu E2E de " + from.shortHex() + "]: \"" + msg + "\""));
            carol.setMessageListener((from, msg) ->
                    SecureLog.info("[Carol recebeu E2E de " + from.shortHex() + "]: \"" + msg + "\""));

            alice.connect("127.0.0.1", sniffProxy.getListenPort());
            bob.connect("127.0.0.1", server.getPort());
            carol.connect("127.0.0.1", server.getPort());

            alice.awaitInitialSync(3000);
            bob.awaitInitialSync(3000);
            carol.awaitInitialSync(3000);
            waitForPeer(alice, bob);
            waitForPeer(alice, carol);
            waitForPeer(bob, carol);

            SecureLog.info("Clientes conectados e sincronizados:");
            SecureLog.info("  Alice id=" + alice.selfId().shortHex()
                    + " pk_fp=" + Bytes.fingerprint(alice.pkClient()));
            SecureLog.info("  Bob   id=" + bob.selfId().shortHex()
                    + " pk_fp=" + Bytes.fingerprint(bob.pkClient()));
            SecureLog.info("  Carol id=" + carol.selfId().shortHex()
                    + " pk_fp=" + Bytes.fingerprint(carol.pkClient()));

            CompletableFuture<String> bobGot = new CompletableFuture<>();
            CompletableFuture<String> aliceGot = new CompletableFuture<>();
            CompletableFuture<String> carolGot = new CompletableFuture<>();

            bob.setMessageListener((from, msg) -> {
                SecureLog.info("[Bob decifrou de " + from.shortHex() + "]: \"" + msg + "\"");
                bobGot.complete(msg);
            });
            alice.setMessageListener((from, msg) -> {
                SecureLog.info("[Alice decifrou de " + from.shortHex() + "]: \"" + msg + "\"");
                aliceGot.complete(msg);
            });
            carol.setMessageListener((from, msg) -> {
                SecureLog.info("[Carol decifrou de " + from.shortHex() + "]: \"" + msg + "\"");
                carolGot.complete(msg);
            });

            alice.sendMessage(bob.selfId(), "Ola Bob! Mensagem cifrada com AES-128-GCM ponta-a-ponta.");
            bobGot.get(3, TimeUnit.SECONDS);

            bob.sendMessage(alice.selfId(), "Oi Alice! Recebido com integridade verificada.");
            aliceGot.get(3, TimeUnit.SECONDS);

            alice.sendMessage(carol.selfId(), "Ola Carol! Chave E2E independente por par de clientes.");
            carolGot.get(3, TimeUnit.SECONDS);

            SecureLog.info("Resultado DEMO 1: 3 clientes trocaram mensagens E2E; o servidor apenas roteou bytes cifrados.");
        }
    }

    /**
     * Cenário 2: Adulteração de 1 bit no trânsito (BITFLIP) detectada pela tag GCM.
     */
    public static void runDemoBitflip() throws Exception {
        SecureLog.info("==================================================================");
        SecureLog.info("DEMO 2: Ataque BITFLIP (Integridade AES-GCM 128 bits)");
        SecureLog.info("==================================================================");

        CertUtil.ServerIdentity identity = loadServerIdentity();
        X509Certificate pinned = loadPinnedCert();

        try (Server server = new Server(0, identity);
             TamperProxy bitflipProxy = new TamperProxy(
                     TamperProxy.Mode.BITFLIP, 0, "127.0.0.1", server.getPort());
             Client alice = new Client(pinned);
             Client bob = new Client(pinned)) {

            bitflipProxy.setTamperFirstE2eOnly(true);
            server.start();
            bitflipProxy.start();

            CompletableFuture<String> rejectedReason = new CompletableFuture<>();
            CompletableFuture<String> secondMsg = new CompletableFuture<>();

            bob.setRejectionListener(reason -> {
                SecureLog.info("[Bob detectou adulteracao]: " + reason);
                rejectedReason.complete(reason);
            });
            bob.setMessageListener((from, msg) -> {
                SecureLog.info("[Bob decifrou mensagem integra de " + from.shortHex() + "]: \"" + msg + "\"");
                secondMsg.complete(msg);
            });

            alice.connect("127.0.0.1", bitflipProxy.getListenPort());
            bob.connect("127.0.0.1", server.getPort());
            alice.awaitInitialSync(3000);
            bob.awaitInitialSync(3000);
            waitForPeer(alice, bob);

            SecureLog.info("Passo 1: Alice envia 1ª mensagem passando pelo TamperProxy (BITFLIP)...");
            alice.sendMessage(bob.selfId(), "Transferir R$ 100,00");
            rejectedReason.get(3, TimeUnit.SECONDS);

            SecureLog.info("Passo 2: Alice envia 2ª mensagem sem adulteração (seqRecv de Bob permaneceu intacto)...");
            alice.sendMessage(bob.selfId(), "Segunda mensagem integra entregue!");
            secondMsg.get(3, TimeUnit.SECONDS);

            SecureLog.info("Resultado DEMO 2: Bitflip rejeitado pela tag GCM; sessão continuou saudável.");
        }
    }

    /**
     * Cenário 3: Reenvio de frame capturado (REPLAY) bloqueado pelo seq_no monotônico.
     */
    public static void runDemoReplay() throws Exception {
        SecureLog.info("==================================================================");
        SecureLog.info("DEMO 3: Ataque de REPLAY (Proteção por seq_no monotônico)");
        SecureLog.info("==================================================================");

        CertUtil.ServerIdentity identity = loadServerIdentity();
        X509Certificate pinned = loadPinnedCert();

        try (Server server = new Server(0, identity);
             TamperProxy replayProxy = new TamperProxy(
                     TamperProxy.Mode.REPLAY, 0, "127.0.0.1", server.getPort());
             Client alice = new Client(pinned);
             Client bob = new Client(pinned)) {

            replayProxy.setTamperFirstE2eOnly(true);
            server.start();
            replayProxy.start();

            CompletableFuture<String> firstMsg = new CompletableFuture<>();
            CompletableFuture<String> replayRejected = new CompletableFuture<>();
            CompletableFuture<String> secondMsg = new CompletableFuture<>();

            bob.setMessageListener((from, msg) -> {
                SecureLog.info("[Bob decifrou de " + from.shortHex() + "]: \"" + msg + "\"");
                if (!firstMsg.isDone()) {
                    firstMsg.complete(msg);
                } else {
                    secondMsg.complete(msg);
                }
            });
            bob.setRejectionListener(reason -> {
                SecureLog.info("[Bob descartou replay]: " + reason);
                replayRejected.complete(reason);
            });

            alice.connect("127.0.0.1", replayProxy.getListenPort());
            bob.connect("127.0.0.1", server.getPort());
            alice.awaitInitialSync(3000);
            bob.awaitInitialSync(3000);
            waitForPeer(alice, bob);

            SecureLog.info("Passo 1: Alice envia 1ª mensagem (seq=0); TamperProxy duplica o frame no fio...");
            alice.sendMessage(bob.selfId(), "Autorizo operacao unica #001");
            firstMsg.get(3, TimeUnit.SECONDS);
            replayRejected.get(3, TimeUnit.SECONDS);

            SecureLog.info("Passo 2: Alice envia 2ª mensagem (seq=1)...");
            alice.sendMessage(bob.selfId(), "Nova mensagem com seq=1");
            secondMsg.get(3, TimeUnit.SECONDS);

            SecureLog.info("Resultado DEMO 3: Cópia duplicada descartada por seq_no <= seqRecv.");
        }
    }

    /**
     * Cenário 4: Framing inválido (BADFRAME) desconecta infrator sem derrubar o servidor.
     */
    public static void runDemoBadframe() throws Exception {
        SecureLog.info("==================================================================");
        SecureLog.info("DEMO 4: Framing Inválido (BADFRAME) e Sobrevivência do Servidor");
        SecureLog.info("==================================================================");

        CertUtil.ServerIdentity identity = loadServerIdentity();
        X509Certificate pinned = loadPinnedCert();

        try (Server server = new Server(0, identity);
             TamperProxy badFrameProxy = new TamperProxy(
                     TamperProxy.Mode.BADFRAME, 0, "127.0.0.1", server.getPort());
             Client alice = new Client(pinned);
             Client bob = new Client(pinned);
             Client carol = new Client(pinned)) {

            server.start();
            badFrameProxy.start();

            alice.connect("127.0.0.1", badFrameProxy.getListenPort());
            bob.connect("127.0.0.1", server.getPort());
            carol.connect("127.0.0.1", server.getPort());

            alice.awaitInitialSync(3000);
            bob.awaitInitialSync(3000);
            carol.awaitInitialSync(3000);
            waitForPeer(alice, bob);
            waitForPeer(bob, carol);

            SecureLog.info("Passo 1: Alice tenta enviar mensagem via TamperProxy (BADFRAME injeta len=-42)...");
            alice.sendMessage(bob.selfId(), "Este frame sera substituido por prefixo invalido");

            SecureLog.info("Passo 2: Bob e Carol continuam conversando normalmente pelo servidor...");
            CompletableFuture<String> carolGot = new CompletableFuture<>();
            carol.setMessageListener((from, msg) -> {
                SecureLog.info("[Carol decifrou de " + from.shortHex() + "]: \"" + msg + "\"");
                carolGot.complete(msg);
            });
            bob.sendMessage(carol.selfId(), "Servidor continua firme apos desconectar o infrator!");
            carolGot.get(3, TimeUnit.SECONDS);

            SecureLog.info("Resultado DEMO 4: Infrator desconectado com segurança; servidor e demais clientes intactos.");
        }
    }

    private static CertUtil.ServerIdentity loadServerIdentity()
            throws ProtocolException, IOException {
        return CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
    }

    private static X509Certificate loadPinnedCert() throws ProtocolException, IOException {
        return CertUtil.loadPinnedCertificate(Path.of(Constants.DEFAULT_CERT_PATH));
    }

    private static void waitForPeer(Client a, Client b) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 3000;
        while (System.currentTimeMillis() < deadline) {
            if (a.peerTable().get(b.selfId()) != null && b.peerTable().get(a.selfId()) != null) {
                return;
            }
            Thread.sleep(25);
        }
    }
}

