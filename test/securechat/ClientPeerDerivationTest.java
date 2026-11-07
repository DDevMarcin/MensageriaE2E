package securechat;

import securechat.client.Client;
import securechat.client.PeerState;
import securechat.common.Bytes;
import securechat.common.CertUtil;
import securechat.common.ClientId;
import securechat.common.Constants;
import securechat.common.Messages;
import securechat.common.ProtocolException;
import securechat.common.X25519Util;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Testes automatizados da T07: {@link PeerState}, {@link securechat.client.PeerTable} e
 * {@link Client} (derivação cruzada A↔B, substituição de chaves em reconexão e anti-replay
 * no canal de controle).
 */
public final class ClientPeerDerivationTest {

    private ClientPeerDerivationTest() {
        // Classe de testes não instanciável.
    }

    /**
     * Critério 1 da T07: Dois clientes A e B (independentemente da ordem de seus IDs)
     * derivam exatamente as mesmas chaves simétricas cruzadas:
     * {@code A.keySend == B.keyRecv}, {@code A.keyRecv == B.keySend} e {@code A.salt == B.salt},
     * sendo {@code keySend != keyRecv}.
     */
    public static void testCrossKeyDerivationSymmetry() throws Exception {
        ClientId id1 = ClientId.random();
        ClientId id2 = ClientId.random();

        KeyPair kp1 = X25519Util.generateKeyPair();
        KeyPair kp2 = X25519Util.generateKeyPair();
        byte[] pk1 = X25519Util.toRawPublicKey(kp1.getPublic());
        byte[] pk2 = X25519Util.toRawPublicKey(kp2.getPublic());

        byte[] salt1 = Bytes.randomBytes(Constants.SALT_BYTES);
        byte[] salt2 = Bytes.randomBytes(Constants.SALT_BYTES);

        Messages.PeerInfo info1 = new Messages.PeerInfo(id1, pk1, salt1);
        Messages.PeerInfo info2 = new Messages.PeerInfo(id2, pk2, salt2);

        PeerState stateOn1For2 = PeerState.derive(id1, kp1.getPrivate(), salt1, info2);
        PeerState stateOn2For1 = PeerState.derive(id2, kp2.getPrivate(), salt2, info1);

        // Chaves cruzadas devem bater byte a byte
        Assert.assertArrayEquals(stateOn1For2.keySend(), stateOn2For1.keyRecv(),
                "1.keySend deve ser idêntica a 2.keyRecv");
        Assert.assertArrayEquals(stateOn1For2.keyRecv(), stateOn2For1.keySend(),
                "1.keyRecv deve ser idêntica a 2.keySend");
        Assert.assertArrayEquals(stateOn1For2.salt(), stateOn2For1.salt(),
                "Ambos devem escolher o salt_srv do cliente de menor client_id (D2)");

        // O salt escolhido deve ser o do menor ClientId na comparação unsigned
        byte[] expectedSalt = id1.compareTo(id2) < 0 ? salt1 : salt2;
        Assert.assertArrayEquals(expectedSalt, stateOn1For2.salt());

        // Chaves por direção devem ser distintas
        Assert.assertFalse(Bytes.constantTimeEquals(stateOn1For2.keySend(), stateOn1For2.keyRecv()),
                "keySend e keyRecv nunca devem ser iguais");
    }

    /**
     * Critério 2 da T07: Quando um peer reconecta com o mesmo {@code client_id} (novo
     * {@code PEER_JOINED} com novo par X25519 e novo {@code salt_srv}), a {@code PeerTable}
     * substitui o {@link PeerState}, gerando chaves completamente diferentes e zerando
     * os contadores {@code seqSend = 0} e {@code seqRecv = -1}.
     */
    public static void testReconnectionGeneratesNewKeysAndResetsCounters() throws Exception {
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));
        ClientId selfId = ClientId.random();
        KeyPair selfKp = X25519Util.generateKeyPair();
        byte[] selfSalt = Bytes.randomBytes(Constants.SALT_BYTES);
        byte[] keyCtrl = Bytes.randomBytes(Constants.AES_KEY_BYTES);

        try (Client client = Client.createForUnitTest(selfId, selfKp, pinnedCert, selfSalt, keyCtrl)) {
            ClientId peerId = ClientId.random();

            // 1ª sessão do peer
            KeyPair peerKp1 = X25519Util.generateKeyPair();
            byte[] peerSalt1 = Bytes.randomBytes(Constants.SALT_BYTES);
            Messages.PeerInfo peerInfo1 = new Messages.PeerInfo(
                    peerId, X25519Util.toRawPublicKey(peerKp1.getPublic()), peerSalt1);

            byte[] ctrl0 = Messages.sealControl(
                    keyCtrl, selfId, 0L, new Messages.PeerList(List.of(peerInfo1)));
            client.processControlFrame(ctrl0);

            PeerState state1 = client.peerTable().get(peerId);
            byte[] firstKeySend = state1.keySend();
            byte[] firstKeyRecv = state1.keyRecv();

            // Simula envio de 1 mensagem na 1ª sessão (seqSend avança para 1)
            state1.sealMessage(selfId, new byte[] {1, 2, 3});
            Assert.assertEquals(1L, state1.seqSend());

            // Reconexão do mesmo peerId com novo par X25519 e novo salt_srv
            KeyPair peerKp2 = X25519Util.generateKeyPair();
            byte[] peerSalt2 = Bytes.randomBytes(Constants.SALT_BYTES);
            Messages.PeerInfo peerInfo2 = new Messages.PeerInfo(
                    peerId, X25519Util.toRawPublicKey(peerKp2.getPublic()), peerSalt2);

            byte[] ctrl1 = Messages.sealControl(
                    keyCtrl, selfId, 1L, new Messages.PeerJoined(peerInfo2));
            client.processControlFrame(ctrl1);

            PeerState state2 = client.peerTable().get(peerId);
            Assert.assertEquals(0L, state2.seqSend(), "seqSend deve ser zerado na reconexão");
            Assert.assertEquals(-1L, state2.seqRecv(), "seqRecv deve voltar a -1 na reconexão");
            Assert.assertFalse(Bytes.constantTimeEquals(firstKeySend, state2.keySend()),
                    "Nova sessão do mesmo client_id deve derivar keySend diferente");
            Assert.assertFalse(Bytes.constantTimeEquals(firstKeyRecv, state2.keyRecv()),
                    "Nova sessão do mesmo client_id deve derivar keyRecv diferente");
        }
    }

    /**
     * Critério 3 da T07: Mensagens repetidas ou com {@code seq_no <= ctrlSeqRecv} no canal
     * de controle são rejeitadas com {@link ProtocolException}, e um frame de controle com
     * tag GCM inválida não avança {@code ctrlSeqRecv}.
     */
    public static void testControlChannelReplayAndTamperRejected() throws Exception {
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));
        ClientId selfId = ClientId.random();
        KeyPair selfKp = X25519Util.generateKeyPair();
        byte[] selfSalt = Bytes.randomBytes(Constants.SALT_BYTES);
        byte[] keyCtrl = Bytes.randomBytes(Constants.AES_KEY_BYTES);

        try (Client client = Client.createForUnitTest(selfId, selfKp, pinnedCert, selfSalt, keyCtrl)) {
            byte[] ctrlSeq0 = Messages.sealControl(
                    keyCtrl, selfId, 0L, new Messages.RegisterOk());
            byte[] ctrlSeq1 = Messages.sealControl(
                    keyCtrl, selfId, 1L, new Messages.PeerList(List.of()));

            // seq 0 e seq 1 válidos são aceitos
            client.processControlFrame(ctrlSeq0);
            client.processControlFrame(ctrlSeq1);

            // Reenviar seq 1 (replay exato) -> rejeitado
            Assert.assertThrows(ProtocolException.class,
                    () -> client.processControlFrame(ctrlSeq1));

            // Reenviar seq 0 (seq_no antigo) -> rejeitado
            Assert.assertThrows(ProtocolException.class,
                    () -> client.processControlFrame(ctrlSeq0));

            // Enviar seq 2 com 1 bit adulterado -> falha na tag GCM e NÃO atualiza ctrlSeqRecv
            byte[] ctrlSeq2Valid = Messages.sealControl(
                    keyCtrl, selfId, 2L, new Messages.RegisterOk());
            byte[] ctrlSeq2Tampered = ctrlSeq2Valid.clone();
            ctrlSeq2Tampered[ctrlSeq2Tampered.length - 1] ^= 0x01;
            Assert.assertThrows(ProtocolException.class,
                    () -> client.processControlFrame(ctrlSeq2Tampered));

            // Como o seq 2 adulterado não atualizou ctrlSeqRecv, o seq 2 legítimo ainda é aceito!
            client.processControlFrame(ctrlSeq2Valid);
        }
    }
}

