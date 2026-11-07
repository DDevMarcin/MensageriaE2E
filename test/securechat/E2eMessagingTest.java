package securechat;

import securechat.client.Cli;
import securechat.client.Client;
import securechat.client.PeerState;
import securechat.common.AesGcm;
import securechat.common.Bytes;
import securechat.common.CertUtil;
import securechat.common.ClientId;
import securechat.common.Constants;
import securechat.common.Messages;
import securechat.common.ProtocolException;
import securechat.server.Server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Testes automatizados da T08: mensageria ponta-a-ponta (envio, relay pelo servidor sem
 * decifrar, recebimento com validações D3 e anti-replay), limite de 4096 bytes, erro de
 * destinatário inexistente e comandos do {@link Cli}.
 */
public final class E2eMessagingTest {

    private E2eMessagingTest() {
        // Classe de testes não instanciável.
    }

    private record ReceivedMsg(ClientId from, String text) {}

    /**
     * Critério 1 da T08: Clientes A e B conectam ao servidor, descobrem-se mutuamente via
     * canal de controle, derivam chaves E2E e trocam múltiplas mensagens nos dois sentidos
     * (A->B e B->A), aprendendo e validando {@code IV_base_recv} (Decisão D3) e incrementando
     * {@code seqSend}/{@code seqRecv}.
     */
    public static void testBidirectionalE2eMessagingAndCli() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        BlockingQueue<ReceivedMsg> inboxA = new LinkedBlockingQueue<>();
        BlockingQueue<ReceivedMsg> inboxB = new LinkedBlockingQueue<>();
        BlockingQueue<ClientId> joinedOnA = new LinkedBlockingQueue<>();

        try (Server server = new Server(0, serverId);
             Client clientA = new Client(pinnedCert);
             Client clientB = new Client(pinnedCert)) {

            server.start();
            int port = server.getPort();

            clientA.setMessageListener((from, text) -> inboxA.add(new ReceivedMsg(from, text)));
            clientA.setPeerJoinedListener(joinedOnA::add);
            clientB.setMessageListener((from, text) -> inboxB.add(new ReceivedMsg(from, text)));

            clientA.connect("127.0.0.1", port);
            Assert.assertTrue(clientA.awaitInitialSync(5000), "Cliente A deve concluir sync inicial");

            clientB.connect("127.0.0.1", port);
            Assert.assertTrue(clientB.awaitInitialSync(5000), "Cliente B deve concluir sync inicial");

            // Aguarda A receber PEER_JOINED de B
            ClientId joinedId = joinedOnA.poll(5, TimeUnit.SECONDS);
            Assert.assertEquals(clientB.selfId(), joinedId, "A deve receber PEER_JOINED de B");

            // Envio A -> B via método direto e via CLI (/msg <prefixo> <texto>)
            clientA.sendMessage(clientB.selfId(), "Oi B, primeira mensagem de A!");

            ByteArrayOutputStream cliOutBytes = new ByteArrayOutputStream();
            Cli cliA = new Cli(
                    clientA,
                    new ByteArrayInputStream(new byte[0]),
                    new PrintStream(cliOutBytes, true, StandardCharsets.UTF_8));
            Assert.assertTrue(cliA.handleCommandLine("/peers"));
            Assert.assertTrue(cliA.handleCommandLine(
                    "/msg " + clientB.selfId().shortHex() + " Segunda mensagem via CLI!"));
            Assert.assertFalse(cliA.handleCommandLine("/quit"));

            ReceivedMsg msg1OnB = inboxB.poll(5, TimeUnit.SECONDS);
            ReceivedMsg msg2OnB = inboxB.poll(5, TimeUnit.SECONDS);
            Assert.assertEquals(clientA.selfId(), msg1OnB.from());
            Assert.assertEquals("Oi B, primeira mensagem de A!", msg1OnB.text());
            Assert.assertEquals("Segunda mensagem via CLI!", msg2OnB.text());

            // Envio no sentido inverso B -> A
            clientB.sendMessage(clientA.selfId(), "Oi A, recebi tudo perfeitamente!");
            ReceivedMsg msgOnA = inboxA.poll(5, TimeUnit.SECONDS);
            Assert.assertEquals(clientB.selfId(), msgOnA.from());
            Assert.assertEquals("Oi A, recebi tudo perfeitamente!", msgOnA.text());

            // Confere contadores e IV_base_recv aprendido (D3)
            PeerState stateBOnA = clientA.peerTable().get(clientB.selfId());
            PeerState stateAOnB = clientB.peerTable().get(clientA.selfId());
            Assert.assertEquals(2L, stateBOnA.seqSend(), "A enviou 2 mensagens para B");
            Assert.assertEquals(1L, stateAOnB.seqRecv(), "B recebeu até seq_no 1 de A");
            Assert.assertArrayEquals(stateBOnA.ivBaseSend(), stateAOnB.ivBaseRecv(),
                    "B deve ter aprendido o IV_base_send de A no primeiro frame válido (D3)");
        }
    }

    /**
     * Critério 2 da T08: Mensagem com plaintext > 4096 bytes é recusada localmente pelo
     * cliente com {@link ProtocolException}, sem enviar ao servidor e sem incrementar
     * {@code seqSend}. Mensagem com exatamente 4096 bytes é aceita.
     */
    public static void testMaxPlaintextLimitEnforcedOnClient() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        BlockingQueue<ReceivedMsg> inboxB = new LinkedBlockingQueue<>();
        BlockingQueue<ClientId> joinedOnA = new LinkedBlockingQueue<>();

        try (Server server = new Server(0, serverId);
             Client clientA = new Client(pinnedCert);
             Client clientB = new Client(pinnedCert)) {

            server.start();
            int port = server.getPort();

            clientA.setPeerJoinedListener(joinedOnA::add);
            clientB.setMessageListener((from, text) -> inboxB.add(new ReceivedMsg(from, text)));

            clientA.connect("127.0.0.1", port);
            clientA.awaitInitialSync(5000);
            clientB.connect("127.0.0.1", port);
            clientB.awaitInitialSync(5000);
            joinedOnA.poll(5, TimeUnit.SECONDS);

            // 4097 bytes (1 byte acima do máximo) -> deve falhar no cliente
            String tooLong = "A".repeat(Constants.MAX_PLAINTEXT + 1);
            Assert.assertThrows(ProtocolException.class,
                    () -> clientA.sendMessage(clientB.selfId(), tooLong));

            PeerState stateBOnA = clientA.peerTable().get(clientB.selfId());
            Assert.assertEquals(0L, stateBOnA.seqSend(),
                    "seqSend não pode incrementar quando a mensagem é recusada");

            // Exatamente 4096 bytes -> deve ser enviada e decifrada com sucesso
            String exactMax = "B".repeat(Constants.MAX_PLAINTEXT);
            clientA.sendMessage(clientB.selfId(), exactMax);
            ReceivedMsg msg = inboxB.poll(5, TimeUnit.SECONDS);
            Assert.assertEquals(exactMax, msg.text());
        }
    }

    /**
     * Critério 3 da T08: Quando um cliente envia um frame E2E para um {@code recipient_id}
     * que não está conectado no servidor, o servidor responde com {@code CONTROL(ERROR)}
     * ({@link Constants#ERR_UNKNOWN_RECIPIENT}) e o remetente recebe e exibe o erro.
     */
    public static void testUnknownRecipientReturnsControlErrorToSender() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        BlockingQueue<Messages.ErrorMsg> errorQueue = new LinkedBlockingQueue<>();

        try (Server server = new Server(0, serverId);
             Client clientA = new Client(pinnedCert)) {

            server.start();
            int port = server.getPort();

            clientA.setErrorListener(errorQueue::add);
            clientA.connect("127.0.0.1", port);
            Assert.assertTrue(clientA.awaitInitialSync(5000));

            // Monta um frame E2E endereçado a um ClientId inexistente no servidor
            ClientId ghostRecipient = ClientId.random();
            byte[] dummyKey = Bytes.randomBytes(Constants.AES_KEY_BYTES);
            byte[] ivBase = Bytes.randomBytes(Constants.IV_BASE_BYTES);
            long seqNo = 0L;
            byte[] nonce = Messages.buildE2eNonce(ivBase, seqNo);
            byte[] aad = Messages.buildE2eAad(clientA.selfId(), ghostRecipient, seqNo);
            byte[] ct = AesGcm.encrypt(dummyKey, nonce, aad, "Oi fantasma".getBytes(StandardCharsets.UTF_8));

            Messages.E2eFrame frame = new Messages.E2eFrame(
                    nonce, clientA.selfId(), ghostRecipient, seqNo, ct);
            clientA.sendRawE2ePayload(Messages.packE2eFrame(frame));

            Messages.ErrorMsg err = errorQueue.poll(5, TimeUnit.SECONDS);
            Assert.assertTrue(err != null, "Remetente deve receber CONTROL(ERROR) do servidor");
            Assert.assertEquals(Constants.ERR_UNKNOWN_RECIPIENT, err.errorCode(),
                    "Código de erro deve ser ERR_UNKNOWN_RECIPIENT");
        }
    }

    /**
     * Valida a Decisão D3: se um segundo frame E2E chegar de um peer trazendo um
     * {@code IV_base} diferente daquele aprendido no 1º frame válido, o destinatário
     * rejeita o frame e não avança {@code seqRecv}.
     */
    public static void testIvBaseRecvChangedMidSessionRejected() throws Exception {
        ClientId idA = ClientId.random();
        ClientId idB = ClientId.random();
        var kpA = securechat.common.X25519Util.generateKeyPair();
        var kpB = securechat.common.X25519Util.generateKeyPair();
        byte[] saltA = Bytes.randomBytes(Constants.SALT_BYTES);
        byte[] saltB = Bytes.randomBytes(Constants.SALT_BYTES);

        PeerState stateBOnA = PeerState.derive(
                idA, kpA.getPrivate(), saltA,
                new Messages.PeerInfo(idB, securechat.common.X25519Util.toRawPublicKey(kpB.getPublic()), saltB));
        PeerState stateAOnB = PeerState.derive(
                idB, kpB.getPrivate(), saltB,
                new Messages.PeerInfo(idA, securechat.common.X25519Util.toRawPublicKey(kpA.getPublic()), saltA));

        // 1º frame válido (seq 0): B aprende ivBaseRecv
        Messages.E2eFrame f0 = stateBOnA.sealMessage(idA, "msg0".getBytes(StandardCharsets.UTF_8));
        Assert.assertArrayEquals("msg0".getBytes(StandardCharsets.UTF_8), stateAOnB.openMessage(idB, f0));
        Assert.assertEquals(0L, stateAOnB.seqRecv());

        // Forja um 2º frame (seq 1) cifrado com a chave correta, mas com outro IV_base != ivBaseSend de A
        byte[] wrongIvBase = stateBOnA.ivBaseSend();
        wrongIvBase[0] ^= (byte) 0xFF;
        byte[] nonceWrongIv = Messages.buildE2eNonce(wrongIvBase, 1L);
        byte[] aad1 = Messages.buildE2eAad(idA, idB, 1L);
        byte[] ct1 = AesGcm.encrypt(stateBOnA.keySend(), nonceWrongIv, aad1, "msg1".getBytes(StandardCharsets.UTF_8));
        Messages.E2eFrame f1WrongIv = new Messages.E2eFrame(nonceWrongIv, idA, idB, 1L, ct1);

        Assert.assertThrows(ProtocolException.class, () -> stateAOnB.openMessage(idB, f1WrongIv));
        Assert.assertEquals(0L, stateAOnB.seqRecv(), "seqRecv não pode avançar quando IV_base diverge");
    }
}
