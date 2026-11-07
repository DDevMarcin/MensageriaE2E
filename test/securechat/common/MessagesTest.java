package securechat.common;

import securechat.Assert;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Testes automatizados da T04: empacotamento e desempacotamento binário em {@link Messages}
 * ({@code HELLO}, {@code HELLO_REPLY}, {@code CONTROL} com todos os 5 opcodes e {@code E2E}),
 * incluindo rejeição segura de entradas truncadas, malformadas ou com campos inconsistentes.
 */
public final class MessagesTest {

    private MessagesTest() {
        // Classe de testes não instanciável.
    }

    /**
     * Testa round-trip e validação de tamanhos para {@code 0x01 HELLO}.
     */
    public static void testHelloRoundTripAndMalformed() throws Exception {
        ClientId id = ClientId.random();
        byte[] pkC = Bytes.randomBytes(Constants.X25519_KEY_BYTES);

        Messages.HelloMsg original = new Messages.HelloMsg(id, pkC);
        byte[] packed = Messages.packHello(original);
        Assert.assertEquals(48, packed.length, "HELLO deve ter exatamente 48 bytes");

        Messages.HelloMsg unpacked = Messages.unpackHello(packed);
        Assert.assertEquals(id, unpacked.clientId());
        Assert.assertArrayEquals(pkC, unpacked.pkC());

        // Truncado (47 B) e longo demais (49 B) devem lançar ProtocolException
        Assert.assertThrows(ProtocolException.class, () -> Messages.unpackHello(new byte[47]));
        Assert.assertThrows(ProtocolException.class, () -> Messages.unpackHello(new byte[49]));
    }

    /**
     * Testa round-trip e rejeição de comprimentos inconsistentes em {@code 0x02 HELLO_REPLY}.
     */
    public static void testHelloReplyRoundTripAndMalformed() throws Exception {
        byte[] pkS = Bytes.randomBytes(Constants.X25519_KEY_BYTES);
        byte[] salt = Bytes.randomBytes(Constants.SALT_BYTES);
        byte[] sig = Bytes.randomBytes(256);
        byte[] cert = Bytes.randomBytes(780);

        Messages.HelloReplyMsg original = new Messages.HelloReplyMsg(pkS, salt, sig, cert);
        byte[] packed = Messages.packHelloReply(original);

        Messages.HelloReplyMsg unpacked = Messages.unpackHelloReply(packed);
        Assert.assertArrayEquals(pkS, unpacked.pkS());
        Assert.assertArrayEquals(salt, unpacked.saltSrv());
        Assert.assertArrayEquals(sig, unpacked.signature());
        Assert.assertArrayEquals(cert, unpacked.certDer());

        // Adulterar sig_len para apontar além do buffer restante -> ProtocolException
        byte[] badSigLen = packed.clone();
        ByteBuffer.wrap(badSigLen, 48, 2).putShort((short) 5000);
        Assert.assertThrows(ProtocolException.class, () -> Messages.unpackHelloReply(badSigLen));

        // Adulterar cert_len para divergir dos bytes restantes -> ProtocolException
        byte[] badCertLen = packed.clone();
        ByteBuffer.wrap(badCertLen, 48 + 2 + sig.length, 2).putShort((short) (cert.length - 5));
        Assert.assertThrows(ProtocolException.class, () -> Messages.unpackHelloReply(badCertLen));
    }

    /**
     * Testa round-trip de todos os 5 opcodes de {@code 0x03 CONTROL} (incluindo cifragem
     * e decifragem com {@code Key_S2C}) e rejeição de entradas malformadas.
     */
    public static void testControlMessagesRoundTripAndMalformed() throws Exception {
        byte[] keyS2C = Bytes.randomBytes(Constants.AES_KEY_BYTES);
        ClientId client = ClientId.random();

        // 1) REGISTER_OK
        byte[] sealedOk = Messages.sealControl(keyS2C, client, 0L, new Messages.RegisterOk());
        Messages.ControlFrame frameOk = Messages.unpackControlFrame(sealedOk);
        Assert.assertEquals(0L, frameOk.seqNo());
        byte[] plainOk = AesGcm.decrypt(
                keyS2C,
                Messages.buildControlNonce(frameOk.seqNo()),
                Messages.buildControlAad(client, frameOk.seqNo()),
                frameOk.ciphertextWithTag());
        Assert.assertTrue(Messages.unpackControlPlaintext(plainOk) instanceof Messages.RegisterOk);

        // 2) PEER_LIST com 2 peers
        Messages.PeerInfo p1 = new Messages.PeerInfo(
                ClientId.random(), Bytes.randomBytes(32), Bytes.randomBytes(16));
        Messages.PeerInfo p2 = new Messages.PeerInfo(
                ClientId.random(), Bytes.randomBytes(32), Bytes.randomBytes(16));
        byte[] rawList = Messages.packControlPlaintext(new Messages.PeerList(List.of(p1, p2)));
        Messages.ControlPayload parsedList = Messages.unpackControlPlaintext(rawList);
        Assert.assertTrue(parsedList instanceof Messages.PeerList);
        List<Messages.PeerInfo> decodedPeers = ((Messages.PeerList) parsedList).peers();
        Assert.assertEquals(2, decodedPeers.size());
        Assert.assertEquals(p1.clientId(), decodedPeers.get(0).clientId());
        Assert.assertArrayEquals(p2.pkC(), decodedPeers.get(1).pkC());

        // 3) PEER_JOINED
        byte[] rawJoined = Messages.packControlPlaintext(new Messages.PeerJoined(p1));
        Messages.ControlPayload parsedJoined = Messages.unpackControlPlaintext(rawJoined);
        Assert.assertTrue(parsedJoined instanceof Messages.PeerJoined);
        Assert.assertEquals(p1.clientId(), ((Messages.PeerJoined) parsedJoined).peer().clientId());

        // 4) PEER_LEFT
        byte[] rawLeft = Messages.packControlPlaintext(new Messages.PeerLeft(p2.clientId()));
        Messages.ControlPayload parsedLeft = Messages.unpackControlPlaintext(rawLeft);
        Assert.assertTrue(parsedLeft instanceof Messages.PeerLeft);
        Assert.assertEquals(p2.clientId(), ((Messages.PeerLeft) parsedLeft).clientId());

        // 5) ERROR
        byte[] rawErr = Messages.packControlPlaintext(
                new Messages.ErrorMsg(Constants.ERR_DUPLICATE_CLIENT_ID, "client_id duplicado"));
        Messages.ControlPayload parsedErr = Messages.unpackControlPlaintext(rawErr);
        Assert.assertTrue(parsedErr instanceof Messages.ErrorMsg);
        Messages.ErrorMsg errMsg = (Messages.ErrorMsg) parsedErr;
        Assert.assertEquals(Constants.ERR_DUPLICATE_CLIENT_ID, errMsg.errorCode());
        Assert.assertEquals("client_id duplicado", errMsg.message());

        // Entradas malformadas em CONTROL
        // - PEER_LIST declarando n=10 mas sem bytes suficientes
        byte[] badPeerList = ByteBuffer.allocate(3)
                .put(Constants.CTRL_PEER_LIST)
                .putShort((short) 10)
                .array();
        Assert.assertThrows(ProtocolException.class, () -> Messages.unpackControlPlaintext(badPeerList));

        // - Opcode desconhecido (0x7F)
        Assert.assertThrows(ProtocolException.class,
                () -> Messages.unpackControlPlaintext(new byte[] {0x7F}));

        // - seq_no negativo no envelope CONTROL
        byte[] negSeqCtrl = ByteBuffer.allocate(8 + 20).putLong(-1L).array();
        Assert.assertThrows(ProtocolException.class, () -> Messages.unpackControlFrame(negSeqCtrl));
    }

    /**
     * Testa round-trip do frame {@code 0x04 E2E} e rejeição de frames truncados,
     * com {@code seq_no} negativo ou com {@code seq_no} do nonce divergente do cabeçalho.
     */
    public static void testE2eFrameRoundTripAndMalformed() throws Exception {
        ClientId sender = ClientId.random();
        ClientId recipient = ClientId.random();
        byte[] key = Bytes.randomBytes(Constants.AES_KEY_BYTES);
        byte[] ivBase = Bytes.randomBytes(Constants.IV_BASE_BYTES);
        long seqNo = 7L;

        byte[] nonce = Messages.buildE2eNonce(ivBase, seqNo);
        byte[] aad = Messages.buildE2eAad(sender, recipient, seqNo);
        byte[] plaintext = "Olá Bob, aqui é Alice!".getBytes(StandardCharsets.UTF_8);
        byte[] ct = AesGcm.encrypt(key, nonce, aad, plaintext);

        Messages.E2eFrame frame = new Messages.E2eFrame(nonce, sender, recipient, seqNo, ct);
        byte[] packed = Messages.packE2eFrame(frame);

        Messages.E2eFrame unpacked = Messages.unpackE2eFrame(packed);
        Assert.assertArrayEquals(ivBase, unpacked.ivBase());
        Assert.assertEquals(seqNo, unpacked.seqNo());
        Assert.assertEquals(seqNo, unpacked.nonceSeqNo());
        Assert.assertEquals(sender, unpacked.senderId());
        Assert.assertEquals(recipient, unpacked.recipientId());

        byte[] decrypted = AesGcm.decrypt(
                key,
                unpacked.nonce(),
                Messages.buildE2eAad(unpacked.senderId(), unpacked.recipientId(), unpacked.seqNo()),
                unpacked.ciphertextWithTag());
        Assert.assertArrayEquals(plaintext, decrypted);

        // 1) Inconsistência entre seq_no do nonce (7) e seq_no do cabeçalho (8) -> ProtocolException
        byte[] mismatchedSeq = packed.clone();
        ByteBuffer.wrap(mismatchedSeq, 12 + 16 + 16, 8).putLong(8L);
        Assert.assertThrows(ProtocolException.class, () -> Messages.unpackE2eFrame(mismatchedSeq));

        // 2) Frame E2E truncado (menor que 52 + 16 = 68 bytes) -> ProtocolException
        Assert.assertThrows(ProtocolException.class, () -> Messages.unpackE2eFrame(new byte[67]));
    }
}

