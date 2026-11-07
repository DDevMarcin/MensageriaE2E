package securechat;

import securechat.client.ClientHandshake;
import securechat.common.AesGcm;
import securechat.common.CertUtil;
import securechat.common.ClientId;
import securechat.common.Constants;
import securechat.common.Framing;
import securechat.common.Messages;
import securechat.common.X25519Util;
import securechat.server.Server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Testes automatizados da T06: registro de sessões no {@link Server}, envio cifrado de
 * {@code REGISTER_OK}, {@code PEER_LIST}, {@code PEER_JOINED}, {@code PEER_LEFT} e
 * rejeição de {@code client_id} duplicado ativo (Decisão D4) e de {@code MAX_CLIENTS}.
 */
public final class ServerSessionControlTest {

    private ServerSessionControlTest() {
        // Classe de testes não instanciável.
    }

    /**
     * Auxiliar de cliente de teste para ler e decifrar o próximo frame {@code 0x03 CONTROL}.
     */
    private record TestConn(
            Socket socket,
            DataInputStream in,
            DataOutputStream out,
            ClientHandshake.Result hs) implements AutoCloseable {

        static TestConn connect(int port, ClientId id, X509Certificate pinnedCert) throws Exception {
            Socket s = new Socket("127.0.0.1", port);
            s.setSoTimeout(5000);
            DataInputStream in = new DataInputStream(s.getInputStream());
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            ClientHandshake.Result hs = ClientHandshake.perform(
                    s, in, out, id, X25519Util.generateKeyPair(), pinnedCert, 5000);
            s.setSoTimeout(5000);
            return new TestConn(s, in, out, hs);
        }

        Messages.ControlPayload readNextControl(long expectedSeqNo) throws Exception {
            Framing.Frame frame = Framing.readFrame(in);
            Assert.assertEquals(Constants.TYPE_CONTROL, frame.type(), "Esperado frame CONTROL (0x03)");
            Messages.ControlFrame cf = Messages.unpackControlFrame(frame.payload());
            Assert.assertEquals(expectedSeqNo, cf.seqNo(), "seq_no de controle fora de ordem");
            byte[] plain = AesGcm.decrypt(
                    hs.keyS2C(),
                    Messages.buildControlNonce(cf.seqNo()),
                    Messages.buildControlAad(hs.clientId(), cf.seqNo()),
                    cf.ciphertextWithTag());
            return Messages.unpackControlPlaintext(plain);
        }

        void disconnectNow() throws IOException {
            socket.close();
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    /**
     * Conecta 3 clientes sequencialmente (C1, C2, C3), verifica que todos recebem
     * {@code REGISTER_OK}, {@code PEER_LIST} (sem si mesmos) e {@code PEER_JOINED} na
     * ordem correta de {@code seq_no}, e ao desconectar C2 verifica que C1 e C3 recebem
     * {@code PEER_LEFT(C2)}.
     */
    public static void testThreeClientsJoinAndLeaveNotifications() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        ClientId id1 = ClientId.random();
        ClientId id2 = ClientId.random();
        ClientId id3 = ClientId.random();

        try (Server server = new Server(0, serverId)) {
            server.start();
            int port = server.getPort();

            try (TestConn c1 = TestConn.connect(port, id1, pinnedCert)) {
                // C1 recebe seq 0 = REGISTER_OK, seq 1 = PEER_LIST (vazia)
                Assert.assertTrue(c1.readNextControl(0L) instanceof Messages.RegisterOk);
                Messages.PeerList list1 = (Messages.PeerList) c1.readNextControl(1L);
                Assert.assertEquals(0, list1.peers().size(), "C1 deve receber PEER_LIST vazia");

                try (TestConn c2 = TestConn.connect(port, id2, pinnedCert)) {
                    // C2 recebe seq 0 = REGISTER_OK, seq 1 = PEER_LIST ([C1])
                    Assert.assertTrue(c2.readNextControl(0L) instanceof Messages.RegisterOk);
                    Messages.PeerList list2 = (Messages.PeerList) c2.readNextControl(1L);
                    Assert.assertEquals(1, list2.peers().size(), "C2 deve ver apenas C1 em PEER_LIST");
                    Assert.assertEquals(id1, list2.peers().get(0).clientId());

                    // C1 recebe seq 2 = PEER_JOINED(C2)
                    Messages.PeerJoined joinedOnC1 = (Messages.PeerJoined) c1.readNextControl(2L);
                    Assert.assertEquals(id2, joinedOnC1.peer().clientId());

                    try (TestConn c3 = TestConn.connect(port, id3, pinnedCert)) {
                        // C3 recebe seq 0 = REGISTER_OK, seq 1 = PEER_LIST ([C1, C2])
                        Assert.assertTrue(c3.readNextControl(0L) instanceof Messages.RegisterOk);
                        Messages.PeerList list3 = (Messages.PeerList) c3.readNextControl(1L);
                        Assert.assertEquals(2, list3.peers().size(), "C3 deve ver C1 e C2 em PEER_LIST");
                        List<ClientId> idsInList3 = list3.peers().stream()
                                .map(Messages.PeerInfo::clientId)
                                .toList();
                        Assert.assertTrue(idsInList3.contains(id1) && idsInList3.contains(id2));
                        Assert.assertFalse(idsInList3.contains(id3),
                                "PEER_LIST nunca deve incluir o próprio cliente recém-conectado");

                        // C1 e C2 recebem PEER_JOINED(C3)
                        Messages.PeerJoined joined3OnC1 = (Messages.PeerJoined) c1.readNextControl(3L);
                        Messages.PeerJoined joined3OnC2 = (Messages.PeerJoined) c2.readNextControl(2L);
                        Assert.assertEquals(id3, joined3OnC1.peer().clientId());
                        Assert.assertEquals(id3, joined3OnC2.peer().clientId());

                        // Agora desconectamos C2 e verificamos que C1 e C3 recebem PEER_LEFT(C2)
                        c2.disconnectNow();

                        Messages.PeerLeft leftOnC1 = (Messages.PeerLeft) c1.readNextControl(4L);
                        Messages.PeerLeft leftOnC3 = (Messages.PeerLeft) c3.readNextControl(2L);
                        Assert.assertEquals(id2, leftOnC1.clientId());
                        Assert.assertEquals(id2, leftOnC3.clientId());
                    }
                }
            }
        }
    }

    /**
     * Verifica a Decisão D4: tentar conectar um segundo cliente com o mesmo {@code client_id}
     * de uma sessão ativa faz o servidor enviar {@code CONTROL(ERROR)} para a nova conexão
     * e fechá-la, mantendo a sessão original intacta e sem enviar {@code PEER_LEFT}.
     */
    public static void testDuplicateActiveClientIdRejected() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        ClientId sameId = ClientId.random();

        try (Server server = new Server(0, serverId)) {
            server.start();
            int port = server.getPort();

            try (TestConn original = TestConn.connect(port, sameId, pinnedCert)) {
                Assert.assertTrue(original.readNextControl(0L) instanceof Messages.RegisterOk);
                Assert.assertTrue(original.readNextControl(1L) instanceof Messages.PeerList);

                // Segunda conexão com o mesmo client_id deve receber ERROR(ERR_DUPLICATE_CLIENT_ID)
                try (TestConn duplicate = TestConn.connect(port, sameId, pinnedCert)) {
                    Messages.ControlPayload payload = duplicate.readNextControl(0L);
                    Assert.assertTrue(payload instanceof Messages.ErrorMsg,
                            "Conexão duplicada deve receber CONTROL(ERROR)");
                    Messages.ErrorMsg err = (Messages.ErrorMsg) payload;
                    Assert.assertEquals(Constants.ERR_DUPLICATE_CLIENT_ID, err.errorCode());
                }

                // A sessão original continua registrada no servidor
                Assert.assertEquals(1, server.registry().size(),
                        "Sessão original deve permanecer ativa após rejeição da duplicata");
            }
        }
    }
}
