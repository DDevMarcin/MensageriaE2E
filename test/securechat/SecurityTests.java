package securechat;

import securechat.client.Client;
import securechat.client.PeerState;
import securechat.common.AesGcm;
import securechat.common.Bytes;
import securechat.common.CertUtil;
import securechat.common.ClientId;
import securechat.common.Constants;
import securechat.common.Messages;
import securechat.common.X25519Util;
import securechat.server.Server;
import securechat.tools.TamperProxy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Testes obrigatórios de segurança da T09 ({@code docs/03} §2):
 * <ol>
 *   <li>Confidencialidade via {@link TamperProxy} em modo {@code SNIFF}.</li>
 *   <li>Integridade (adulteração / bitflip) via {@link TamperProxy} em modo {@code BITFLIP}.</li>
 *   <li>Anti-replay via {@link TamperProxy} em modo {@code REPLAY}.</li>
 *   <li>Framing inválido via {@link TamperProxy} em modo {@code BADFRAME} sem derrubar o servidor.</li>
 *   <li>Anti-spoof de {@code sender_id} no servidor.</li>
 *   <li>Reconexão completa fim-a-fim com o mesmo {@code client_id}.</li>
 * </ol>
 */
public final class SecurityTests {

    private SecurityTests() {
        // Classe de testes não instanciável.
    }

    /**
     * 1. Modo SNIFF: Verifica que o tráfego capturado na rede entre A e B não contém o
     * texto claro da mensagem, mas B decifra perfeitamente.
     */
    public static void testSniffModeConfidentiality() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        BlockingQueue<String> inboxB = new LinkedBlockingQueue<>();
        BlockingQueue<ClientId> joinedOnA = new LinkedBlockingQueue<>();

        try (Server server = new Server(0, serverId);
             TamperProxy proxy = new TamperProxy(
                     TamperProxy.Mode.SNIFF, 0, "127.0.0.1", server.getPort());
             Client clientA = new Client(pinnedCert);
             Client clientB = new Client(pinnedCert)) {

            server.start();
            proxy.start();

            clientA.setPeerJoinedListener(joinedOnA::add);
            clientB.setMessageListener((from, text) -> inboxB.add(text));

            // Cliente A conecta através do TamperProxy; Cliente B conecta ao Servidor
            clientA.connect("127.0.0.1", proxy.getListenPort());
            Assert.assertTrue(clientA.awaitInitialSync(5000));

            clientB.connect("127.0.0.1", server.getPort());
            Assert.assertTrue(clientB.awaitInitialSync(5000));
            Assert.assertEquals(clientB.selfId(), joinedOnA.poll(5, TimeUnit.SECONDS));

            String secretText = "SEGREDO_CONFIDENCIAL_E2E_2026";
            clientA.sendMessage(clientB.selfId(), secretText);

            Assert.assertEquals(secretText, inboxB.poll(5, TimeUnit.SECONDS),
                    "Destinatário B deve decifrar o texto claro");
            Assert.assertEquals(1, proxy.capturedE2ePayloads().size(),
                    "Proxy deve ter capturado 1 frame E2E");

            String rawWireLatin1 = new String(
                    proxy.capturedE2ePayloads().get(0), StandardCharsets.ISO_8859_1);
            Assert.assertFalse(rawWireLatin1.contains("SEGREDO_CONFIDENCIAL"),
                    "Bytes no fio jamais podem conter o texto claro legível");
        }
    }

    /**
     * 2. Modo BITFLIP (Integridade): O {@link TamperProxy} inverte 1 bit do ciphertext
     * do 1º frame E2E em trânsito. O destinatário B rejeita por falha na tag GCM
     * ({@code tag mismatch}), não entrega texto corrompido e não atualiza {@code seqRecv}.
     */
    public static void testBitflipRejectedByRecipient() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        BlockingQueue<String> inboxB = new LinkedBlockingQueue<>();
        BlockingQueue<String> rejectionsB = new LinkedBlockingQueue<>();
        BlockingQueue<ClientId> joinedOnA = new LinkedBlockingQueue<>();

        try (Server server = new Server(0, serverId);
             TamperProxy proxy = new TamperProxy(
                     TamperProxy.Mode.BITFLIP, 0, "127.0.0.1", server.getPort());
             Client clientA = new Client(pinnedCert);
             Client clientB = new Client(pinnedCert)) {

            proxy.setTamperFirstE2eOnly(true);
            server.start();
            proxy.start();

            clientA.setPeerJoinedListener(joinedOnA::add);
            clientB.setMessageListener((from, text) -> inboxB.add(text));
            clientB.setRejectionListener(rejectionsB::add);

            clientA.connect("127.0.0.1", proxy.getListenPort());
            clientA.awaitInitialSync(5000);
            clientB.connect("127.0.0.1", server.getPort());
            clientB.awaitInitialSync(5000);
            joinedOnA.poll(5, TimeUnit.SECONDS);

            // 1ª mensagem sofre bitflip no proxy -> deve ser rejeitada por B
            clientA.sendMessage(clientB.selfId(), "Mensagem que sera adulterada");

            String reason = rejectionsB.poll(5, TimeUnit.SECONDS);
            Assert.assertTrue(reason != null && reason.contains("tag mismatch"),
                    "Destinatário B deve rejeitar por 'tag mismatch', mas obteve: " + reason);

            PeerState stateAOnB = clientB.peerTable().get(clientA.selfId());
            Assert.assertEquals(-1L, stateAOnB.seqRecv(),
                    "seqRecv de B deve continuar -1 após falha na tag GCM (Regra de Ouro 5)");
            Assert.assertTrue(inboxB.isEmpty(), "Nenhuma mensagem adulterada pode chegar ao inbox");

            // 2ª mensagem (seq_no = 1) passa sem adulteração e deve ser aceita normalmente!
            clientA.sendMessage(clientB.selfId(), "Segunda mensagem integra");
            Assert.assertEquals("Segunda mensagem integra", inboxB.poll(5, TimeUnit.SECONDS));
            Assert.assertEquals(1L, stateAOnB.seqRecv());
        }
    }

    /**
     * 3. Modo REPLAY (Anti-replay): O {@link TamperProxy} duplica o frame E2E em trânsito.
     * O destinatário B aceita o primeiro e rejeita a cópia repetida porque {@code seq_no <= seqRecv}.
     */
    public static void testReplayRejectedByRecipient() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        BlockingQueue<String> inboxB = new LinkedBlockingQueue<>();
        BlockingQueue<String> rejectionsB = new LinkedBlockingQueue<>();
        BlockingQueue<ClientId> joinedOnA = new LinkedBlockingQueue<>();

        try (Server server = new Server(0, serverId);
             TamperProxy proxy = new TamperProxy(
                     TamperProxy.Mode.REPLAY, 0, "127.0.0.1", server.getPort());
             Client clientA = new Client(pinnedCert);
             Client clientB = new Client(pinnedCert)) {

            server.start();
            proxy.start();

            clientA.setPeerJoinedListener(joinedOnA::add);
            clientB.setMessageListener((from, text) -> inboxB.add(text));
            clientB.setRejectionListener(rejectionsB::add);

            clientA.connect("127.0.0.1", proxy.getListenPort());
            clientA.awaitInitialSync(5000);
            clientB.connect("127.0.0.1", server.getPort());
            clientB.awaitInitialSync(5000);
            joinedOnA.poll(5, TimeUnit.SECONDS);

            // A envia 1 mensagem; o proxy envia 2 vezes o mesmo frame (seq 0)
            clientA.sendMessage(clientB.selfId(), "Transferir R$ 100");

            Assert.assertEquals("Transferir R$ 100", inboxB.poll(5, TimeUnit.SECONDS),
                    "Primeira entrega legítima deve ser aceita");

            String replayReason = rejectionsB.poll(5, TimeUnit.SECONDS);
            Assert.assertTrue(replayReason != null && replayReason.contains("replay"),
                    "Segunda cópia deve ser rejeitada por replay, mas obteve: " + replayReason);
            Assert.assertTrue(inboxB.isEmpty(),
                    "Mensagem reenviada (replay) jamais pode ser entregue uma segunda vez");
        }
    }

    /**
     * 4. Modo BADFRAME (Robustez de Framing): O {@link TamperProxy} injeta um tamanho de
     * frame negativo no servidor. O servidor desconecta com segurança a sessão infratora
     * (notificando {@code PEER_LEFT} aos demais) e continua operando perfeitamente para B e C.
     */
    public static void testBadFrameDisconnectsSafelyWithoutCrashingServer() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        BlockingQueue<ClientId> leftOnB = new LinkedBlockingQueue<>();
        BlockingQueue<String> inboxC = new LinkedBlockingQueue<>();
        BlockingQueue<ClientId> joinedOnB = new LinkedBlockingQueue<>();

        try (Server server = new Server(0, serverId);
             TamperProxy proxy = new TamperProxy(
                     TamperProxy.Mode.BADFRAME, 0, "127.0.0.1", server.getPort());
             Client clientA = new Client(pinnedCert);
             Client clientB = new Client(pinnedCert);
             Client clientC = new Client(pinnedCert)) {

            server.start();
            proxy.start();

            clientB.setPeerLeftListener(leftOnB::add);
            clientB.setPeerJoinedListener(joinedOnB::add);
            clientC.setMessageListener((from, text) -> inboxC.add(text));

            clientB.connect("127.0.0.1", server.getPort());
            clientB.awaitInitialSync(5000);

            clientC.connect("127.0.0.1", server.getPort());
            clientC.awaitInitialSync(5000);
            Assert.assertEquals(clientC.selfId(), joinedOnB.poll(5, TimeUnit.SECONDS));

            // A conecta via proxy BADFRAME
            clientA.connect("127.0.0.1", proxy.getListenPort());
            clientA.awaitInitialSync(5000);
            Assert.assertEquals(clientA.selfId(), joinedOnB.poll(5, TimeUnit.SECONDS));

            // Quando A tenta enviar, o proxy injeta len = -42 no servidor
            clientA.sendMessage(clientB.selfId(), "Disparando badframe");

            // O servidor desconecta A com segurança e envia PEER_LEFT(A) para B
            ClientId disconnectedId = leftOnB.poll(5, TimeUnit.SECONDS);
            Assert.assertEquals(clientA.selfId(), disconnectedId,
                    "Servidor deve desconectar A após framing inválido e notificar PEER_LEFT");

            // B e C continuam trocando mensagens normalmente (servidor segue vivo e saudável)
            clientB.sendMessage(clientC.selfId(), "Servidor continua firme apos badframe!");
            Assert.assertEquals("Servidor continua firme apos badframe!",
                    inboxC.poll(5, TimeUnit.SECONDS));
        }
    }

    /**
     * 5. Anti-spoof de {@code sender_id}: Se um cliente A tentar enviar um frame E2E cujo
     * campo {@code sender_id} finge ser C, o servidor descarta o frame imediatamente.
     */
    public static void testForgedSenderIdDiscardedByServer() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        BlockingQueue<String> inboxB = new LinkedBlockingQueue<>();
        BlockingQueue<ClientId> joinedOnA = new LinkedBlockingQueue<>();

        try (Server server = new Server(0, serverId);
             Client clientA = new Client(pinnedCert);
             Client clientB = new Client(pinnedCert)) {

            server.start();
            int port = server.getPort();

            clientA.setPeerJoinedListener(joinedOnA::add);
            clientB.setMessageListener((from, text) -> inboxB.add(text));

            clientA.connect("127.0.0.1", port);
            clientA.awaitInitialSync(5000);
            clientB.connect("127.0.0.1", port);
            clientB.awaitInitialSync(5000);
            joinedOnA.poll(5, TimeUnit.SECONDS);

            // A monta um frame E2E com sender_id = fakeId (!= clientA.selfId())
            ClientId fakeSender = ClientId.random();
            byte[] nonce = Messages.buildE2eNonce(Bytes.randomBytes(4), 0L);
            byte[] aad = Messages.buildE2eAad(fakeSender, clientB.selfId(), 0L);
            byte[] ct = AesGcm.encrypt(
                    Bytes.randomBytes(16), nonce, aad, "forjado".getBytes(StandardCharsets.UTF_8));
            Messages.E2eFrame forged = new Messages.E2eFrame(
                    nonce, fakeSender, clientB.selfId(), 0L, ct);
            clientA.sendRawE2ePayload(Messages.packE2eFrame(forged));

            // Em seguida A envia uma mensagem legítima com seu próprio sender_id
            clientA.sendMessage(clientB.selfId(), "Mensagem legitima de A");

            Assert.assertEquals("Mensagem legitima de A", inboxB.poll(5, TimeUnit.SECONDS));
            Assert.assertTrue(inboxB.isEmpty(), "Frame com sender_id forjado deve ter sido descartado");
        }
    }

    /**
     * 6. Reconexão fim-a-fim com o mesmo {@code client_id}: A conecta, troca mensagem com B,
     * desconecta, e depois reconecta com o mesmo {@code client_id} e novo par X25519; B
     * substitui o estado antigo em {@code PEER_JOINED} e conversa com A usando as novas chaves.
     */
    public static void testEndToEndReconnectionWithSameClientId() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        ClientId fixedIdA = ClientId.random();
        BlockingQueue<String> inboxB = new LinkedBlockingQueue<>();
        BlockingQueue<ClientId> joinedOnB = new LinkedBlockingQueue<>();
        BlockingQueue<ClientId> leftOnB = new LinkedBlockingQueue<>();

        try (Server server = new Server(0, serverId);
             Client clientB = new Client(pinnedCert)) {

            server.start();
            int port = server.getPort();

            clientB.setMessageListener((from, text) -> inboxB.add(text));
            clientB.setPeerJoinedListener(joinedOnB::add);
            clientB.setPeerLeftListener(leftOnB::add);

            clientB.connect("127.0.0.1", port);
            clientB.awaitInitialSync(5000);

            byte[] firstKeyRecvOnB;
            // 1ª execução de A com fixedIdA
            try (Client clientA1 = new Client(fixedIdA, X25519Util.generateKeyPair(), pinnedCert)) {
                clientA1.connect("127.0.0.1", port);
                clientA1.awaitInitialSync(5000);
                Assert.assertEquals(fixedIdA, joinedOnB.poll(5, TimeUnit.SECONDS));

                firstKeyRecvOnB = clientB.peerTable().get(fixedIdA).keyRecv();
                clientA1.sendMessage(clientB.selfId(), "Sessao 1 de A");
                Assert.assertEquals("Sessao 1 de A", inboxB.poll(5, TimeUnit.SECONDS));
            }

            // Aguarda B processar PEER_LEFT de A1
            Assert.assertEquals(fixedIdA, leftOnB.poll(5, TimeUnit.SECONDS));

            // 2ª execução de A com o MESMO fixedIdA, mas novo par X25519 efêmero
            try (Client clientA2 = new Client(fixedIdA, X25519Util.generateKeyPair(), pinnedCert)) {
                clientA2.connect("127.0.0.1", port);
                clientA2.awaitInitialSync(5000);
                Assert.assertEquals(fixedIdA, joinedOnB.poll(5, TimeUnit.SECONDS));

                byte[] secondKeyRecvOnB = clientB.peerTable().get(fixedIdA).keyRecv();
                Assert.assertFalse(Bytes.constantTimeEquals(firstKeyRecvOnB, secondKeyRecvOnB),
                        "Reconexão deve derivar chaves E2E novas");

                clientA2.sendMessage(clientB.selfId(), "Sessao 2 de A (chaves novas!)");
                Assert.assertEquals("Sessao 2 de A (chaves novas!)", inboxB.poll(5, TimeUnit.SECONDS));
            }
        }
    }
}

