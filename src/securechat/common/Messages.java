package securechat.common;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Empacotamento e desempacotamento binário manual (byte a byte via {@link ByteBuffer}) de
 * todas as mensagens do protocolo: {@code HELLO}, {@code HELLO_REPLY}, {@code CONTROL}
 * (e seus 5 opcodes internos) e {@code E2E}.
 *
 * <p><b>Segurança de parsing implementada aqui:</b></p>
 * <ul>
 *   <li>Nenhuma serialização nativa do Java ({@code ObjectInputStream}) ou reflexão é usada.</li>
 *   <li>Todo campo de comprimento variável ({@code sig_len}, {@code cert_len}, {@code n} em
 *       {@code PEER_LIST}) é validado contra {@code bb.remaining()} <b>antes</b> de alocar
 *       qualquer {@code new byte[...]}, garantindo que entradas truncadas ou adulteradas
 *       lancem exclusivamente {@link ProtocolException} (nunca {@code BufferUnderflowException},
 *       {@code IndexOutOfBoundsException} ou {@code OutOfMemoryError}).</li>
 *   <li>Bytes excedentes ao final de mensagens de tamanho fixo também são rejeitados.</li>
 * </ul>
 */
public final class Messages {

    /** Tamanho exato do payload de {@code 0x01 HELLO}: 16B (client_id) + 32B (pk_C) = 48 bytes. */
    public static final int HELLO_PAYLOAD_BYTES =
            Constants.CLIENT_ID_BYTES + Constants.X25519_KEY_BYTES;

    /** Tamanho de cada entrada de peer em {@code PEER_LIST} / {@code PEER_JOINED}: 16 + 32 + 16 = 64 bytes. */
    public static final int PEER_ENTRY_BYTES =
            Constants.CLIENT_ID_BYTES + Constants.X25519_KEY_BYTES + Constants.SALT_BYTES;

    /** Tamanho do AAD do canal de controle: 16B (client_id) + 8B (seq_no) = 24 bytes. */
    public static final int CTRL_AAD_BYTES =
            Constants.CLIENT_ID_BYTES + Constants.SEQ_NO_BYTES;

    /** Tamanho do AAD do frame E2E: 16B (sender_id) + 16B (recipient_id) + 8B (seq_no) = 40 bytes. */
    public static final int E2E_AAD_BYTES =
            Constants.CLIENT_ID_BYTES + Constants.CLIENT_ID_BYTES + Constants.SEQ_NO_BYTES;

    /** Limite máximo de bytes para texto de erro UTF-8 em {@code CTRL_ERROR}. */
    private static final int MAX_ERROR_TEXT_BYTES = 512;

    private Messages() {
        // Classe utilitária não instanciável.
    }

    // =========================================================================
    // Records de representação imutável das mensagens
    // =========================================================================

    /**
     * Mensagem {@code 0x01 HELLO} (Cliente -> Servidor): {@code client_id (16B) || pk_C (32B)}.
     */
    public record HelloMsg(ClientId clientId, byte[] pkC) {
        public HelloMsg {
            Objects.requireNonNull(clientId, "clientId não pode ser nulo");
            Objects.requireNonNull(pkC, "pkC não pode ser nulo");
            pkC = pkC.clone();
        }

        @Override
        public byte[] pkC() {
            return pkC.clone();
        }
    }

    /**
     * Mensagem {@code 0x02 HELLO_REPLY} (Servidor -> Cliente):
     * {@code pk_S (32B) || salt_srv (16B) || sig_len (2B) || sig || cert_len (2B) || cert (DER)}.
     */
    public record HelloReplyMsg(byte[] pkS, byte[] saltSrv, byte[] signature, byte[] certDer) {
        public HelloReplyMsg {
            Objects.requireNonNull(pkS, "pkS não pode ser nulo");
            Objects.requireNonNull(saltSrv, "saltSrv não pode ser nulo");
            Objects.requireNonNull(signature, "signature não pode ser nula");
            Objects.requireNonNull(certDer, "certDer não pode ser nulo");
            pkS = pkS.clone();
            saltSrv = saltSrv.clone();
            signature = signature.clone();
            certDer = certDer.clone();
        }

        @Override
        public byte[] pkS() {
            return pkS.clone();
        }

        @Override
        public byte[] saltSrv() {
            return saltSrv.clone();
        }

        @Override
        public byte[] signature() {
            return signature.clone();
        }

        @Override
        public byte[] certDer() {
            return certDer.clone();
        }
    }

    /**
     * Dados públicos de um peer distribuídos pelo servidor no canal de controle:
     * {@code client_id (16B) || pk_C (32B) || salt_srv (16B)}.
     */
    public record PeerInfo(ClientId clientId, byte[] pkC, byte[] saltSrv) {
        public PeerInfo {
            Objects.requireNonNull(clientId, "clientId não pode ser nulo");
            Objects.requireNonNull(pkC, "pkC não pode ser nulo");
            Objects.requireNonNull(saltSrv, "saltSrv não pode ser nulo");
            pkC = pkC.clone();
            saltSrv = saltSrv.clone();
        }

        @Override
        public byte[] pkC() {
            return pkC.clone();
        }

        @Override
        public byte[] saltSrv() {
            return saltSrv.clone();
        }
    }

    /**
     * Hierarquia selada (Java 21 {@code sealed interface}) para os 5 tipos de mensagens
     * internas do canal de controle ({@code 0x03 CONTROL}) após decifragem com {@code Key_S2C}.
     */
    public sealed interface ControlPayload
            permits RegisterOk, PeerList, PeerJoined, PeerLeft, ErrorMsg {
        byte opcode();
    }

    /** Opcode {@code 0x01 REGISTER_OK}: confirma que o handshake e o registro sucederam. */
    public record RegisterOk() implements ControlPayload {
        @Override
        public byte opcode() {
            return Constants.CTRL_REGISTER_OK;
        }
    }

    /** Opcode {@code 0x02 PEER_LIST}: lista de todos os demais peers conectados. */
    public record PeerList(List<PeerInfo> peers) implements ControlPayload {
        public PeerList {
            Objects.requireNonNull(peers, "peers não pode ser nulo");
            peers = Collections.unmodifiableList(new ArrayList<>(peers));
        }

        @Override
        public byte opcode() {
            return Constants.CTRL_PEER_LIST;
        }
    }

    /** Opcode {@code 0x03 PEER_JOINED}: notifica entrada ou reconexão de um peer. */
    public record PeerJoined(PeerInfo peer) implements ControlPayload {
        public PeerJoined {
            Objects.requireNonNull(peer, "peer não pode ser nulo");
        }

        @Override
        public byte opcode() {
            return Constants.CTRL_PEER_JOINED;
        }
    }

    /** Opcode {@code 0x04 PEER_LEFT}: notifica desconexão de um peer. */
    public record PeerLeft(ClientId clientId) implements ControlPayload {
        public PeerLeft {
            Objects.requireNonNull(clientId, "clientId não pode ser nulo");
        }

        @Override
        public byte opcode() {
            return Constants.CTRL_PEER_LEFT;
        }
    }

    /** Opcode {@code 0x05 ERROR}: código de erro de 1 byte + descrição curta UTF-8. */
    public record ErrorMsg(byte errorCode, String message) implements ControlPayload {
        public ErrorMsg {
            Objects.requireNonNull(message, "message não pode ser nula");
        }

        @Override
        public byte opcode() {
            return Constants.CTRL_ERROR;
        }
    }

    /**
     * Envelope externo de uma mensagem {@code 0x03 CONTROL} no fio:
     * {@code seq_no (8B big-endian) || ciphertext+tag (AES-128-GCM com Key_S2C)}.
     */
    public record ControlFrame(long seqNo, byte[] ciphertextWithTag) {
        public ControlFrame {
            Objects.requireNonNull(ciphertextWithTag, "ciphertextWithTag não pode ser nulo");
            ciphertextWithTag = ciphertextWithTag.clone();
        }

        @Override
        public byte[] ciphertextWithTag() {
            return ciphertextWithTag.clone();
        }
    }

    /**
     * Frame {@code 0x04 E2E} completo (Cliente -> Servidor -> Cliente):
     * {@code [nonce 12B][sender_id 16B][recipient_id 16B][seq_no 8B][ciphertext + tag 16B]}.
     */
    public record E2eFrame(
            byte[] nonce,
            ClientId senderId,
            ClientId recipientId,
            long seqNo,
            byte[] ciphertextWithTag) {

        public E2eFrame {
            Objects.requireNonNull(nonce, "nonce não pode ser nulo");
            Objects.requireNonNull(senderId, "senderId não pode ser nulo");
            Objects.requireNonNull(recipientId, "recipientId não pode ser nulo");
            Objects.requireNonNull(ciphertextWithTag, "ciphertextWithTag não pode ser nulo");
            nonce = nonce.clone();
            ciphertextWithTag = ciphertextWithTag.clone();
        }

        @Override
        public byte[] nonce() {
            return nonce.clone();
        }

        @Override
        public byte[] ciphertextWithTag() {
            return ciphertextWithTag.clone();
        }

        /** Extrai os 4 primeiros bytes do nonce ({@code IV_base}). */
        public byte[] ivBase() {
            return Arrays.copyOfRange(nonce, 0, Constants.IV_BASE_BYTES);
        }

        /** Extrai os 8 últimos bytes do nonce interpretados como {@code seq_no} big-endian. */
        public long nonceSeqNo() {
            return ByteBuffer.wrap(nonce, Constants.IV_BASE_BYTES, Constants.SEQ_NO_BYTES).getLong();
        }
    }

    // =========================================================================
    // Cálculo de H, Nonces e AADs
    // =========================================================================

    /**
     * Calcula o resumo criptográfico do handshake:
     * {@code H = SHA256(pk_S (32B) || pk_C (32B) || client_id (16B) || salt_srv (16B))}.
     */
    public static byte[] handshakeHash(byte[] pkS, byte[] pkC, ClientId clientId, byte[] saltSrv)
            throws ProtocolException {
        if (pkS == null || pkS.length != Constants.X25519_KEY_BYTES) {
            throw new ProtocolException("pk_S deve ter 32 bytes para o cálculo de H");
        }
        if (pkC == null || pkC.length != Constants.X25519_KEY_BYTES) {
            throw new ProtocolException("pk_C deve ter 32 bytes para o cálculo de H");
        }
        if (clientId == null) {
            throw new ProtocolException("client_id não pode ser nulo para o cálculo de H");
        }
        if (saltSrv == null || saltSrv.length != Constants.SALT_BYTES) {
            throw new ProtocolException("salt_srv deve ter 16 bytes para o cálculo de H");
        }
        return Bytes.sha256(pkS, pkC, clientId.toBytes(), saltSrv);
    }

    /**
     * Constrói o nonce de 12 bytes de um frame E2E: {@code IV_base (4B) || seq_no (8B big-endian)}.
     */
    public static byte[] buildE2eNonce(byte[] ivBase, long seqNo) throws ProtocolException {
        return AesGcm.buildNonce(ivBase, seqNo);
    }

    /**
     * Constrói o nonce de 12 bytes do canal de controle: {@code 0x00000001 (4B) || seq_no (8B)}.
     */
    public static byte[] buildControlNonce(long seqNo) throws ProtocolException {
        return AesGcm.buildControlNonce(seqNo);
    }

    /**
     * Constrói o AAD de 24 bytes do canal de controle: {@code client_id (16B) || seq_no (8B)}.
     */
    public static byte[] buildControlAad(ClientId clientId, long seqNo) throws ProtocolException {
        if (clientId == null) {
            throw new ProtocolException("client_id não pode ser nulo no AAD de controle");
        }
        if (seqNo < 0) {
            throw new ProtocolException("seq_no não pode ser negativo no AAD de controle");
        }
        return ByteBuffer.allocate(CTRL_AAD_BYTES)
                .put(clientId.toBytes())
                .putLong(seqNo)
                .array();
    }

    /**
     * Constrói o AAD de 40 bytes do frame E2E:
     * {@code sender_id (16B) || recipient_id (16B) || seq_no (8B big-endian)}.
     */
    public static byte[] buildE2eAad(ClientId senderId, ClientId recipientId, long seqNo)
            throws ProtocolException {
        if (senderId == null || recipientId == null) {
            throw new ProtocolException("sender_id e recipient_id não podem ser nulos no AAD E2E");
        }
        if (seqNo < 0) {
            throw new ProtocolException("seq_no não pode ser negativo no AAD E2E");
        }
        return ByteBuffer.allocate(E2E_AAD_BYTES)
                .put(senderId.toBytes())
                .put(recipientId.toBytes())
                .putLong(seqNo)
                .array();
    }

    // =========================================================================
    // 0x01 HELLO
    // =========================================================================

    /** Empacota {@link HelloMsg} em 48 bytes ({@code client_id 16B || pk_C 32B}). */
    public static byte[] packHello(HelloMsg msg) throws ProtocolException {
        if (msg == null) {
            throw new ProtocolException("HelloMsg não pode ser nula");
        }
        byte[] pkC = msg.pkC();
        if (pkC.length != Constants.X25519_KEY_BYTES) {
            throw new ProtocolException("pk_C no HELLO deve ter 32 bytes");
        }
        return ByteBuffer.allocate(HELLO_PAYLOAD_BYTES)
                .put(msg.clientId().toBytes())
                .put(pkC)
                .array();
    }

    /** Desempacota os 48 bytes do payload de um frame {@code 0x01 HELLO}. */
    public static HelloMsg unpackHello(byte[] payload) throws ProtocolException {
        if (payload == null || payload.length != HELLO_PAYLOAD_BYTES) {
            int len = payload == null ? -1 : payload.length;
            throw new ProtocolException(
                    "Payload HELLO inválido: esperado " + HELLO_PAYLOAD_BYTES + " bytes, recebido " + len);
        }
        ByteBuffer bb = ByteBuffer.wrap(payload);
        byte[] idBytes = new byte[Constants.CLIENT_ID_BYTES];
        byte[] pkC = new byte[Constants.X25519_KEY_BYTES];
        bb.get(idBytes);
        bb.get(pkC);
        return new HelloMsg(ClientId.fromBytes(idBytes), pkC);
    }

    // =========================================================================
    // 0x02 HELLO_REPLY
    // =========================================================================

    /**
     * Empacota {@link HelloReplyMsg} no formato:
     * {@code pk_S (32B) || salt_srv (16B) || sig_len (2B) || sig || cert_len (2B) || cert}.
     */
    public static byte[] packHelloReply(HelloReplyMsg msg) throws ProtocolException {
        if (msg == null) {
            throw new ProtocolException("HelloReplyMsg não pode ser nula");
        }
        byte[] pkS = msg.pkS();
        byte[] salt = msg.saltSrv();
        byte[] sig = msg.signature();
        byte[] cert = msg.certDer();

        if (pkS.length != Constants.X25519_KEY_BYTES) {
            throw new ProtocolException("pk_S no HELLO_REPLY deve ter 32 bytes");
        }
        if (salt.length != Constants.SALT_BYTES) {
            throw new ProtocolException("salt_srv no HELLO_REPLY deve ter 16 bytes");
        }
        if (sig.length == 0 || sig.length > Constants.MAX_FRAME) {
            throw new ProtocolException("Tamanho de assinatura inválido no HELLO_REPLY: " + sig.length);
        }
        if (cert.length == 0 || cert.length > Constants.MAX_FRAME) {
            throw new ProtocolException("Tamanho de certificado inválido no HELLO_REPLY: " + cert.length);
        }

        int total = Constants.X25519_KEY_BYTES + Constants.SALT_BYTES + 2 + sig.length + 2 + cert.length;
        if (total + Constants.MSG_TYPE_BYTES > Constants.MAX_FRAME) {
            throw new ProtocolException("HELLO_REPLY excede MAX_FRAME: " + total);
        }

        return ByteBuffer.allocate(total)
                .put(pkS)
                .put(salt)
                .putShort((short) sig.length)
                .put(sig)
                .putShort((short) cert.length)
                .put(cert)
                .array();
    }

    /** Desempacota o payload de um frame {@code 0x02 HELLO_REPLY} com validação estrita de limites. */
    public static HelloReplyMsg unpackHelloReply(byte[] payload) throws ProtocolException {
        int minLen = Constants.X25519_KEY_BYTES + Constants.SALT_BYTES + 2 + 1 + 2 + 1;
        if (payload == null || payload.length < minLen) {
            int len = payload == null ? -1 : payload.length;
            throw new ProtocolException("Payload HELLO_REPLY truncado (len=" + len + ")");
        }

        ByteBuffer bb = ByteBuffer.wrap(payload);
        byte[] pkS = new byte[Constants.X25519_KEY_BYTES];
        byte[] salt = new byte[Constants.SALT_BYTES];
        bb.get(pkS);
        bb.get(salt);

        if (bb.remaining() < 2) {
            throw new ProtocolException("HELLO_REPLY truncado antes de sig_len");
        }
        int sigLen = Short.toUnsignedInt(bb.getShort());
        if (sigLen <= 0 || sigLen > bb.remaining() - 2) {
            throw new ProtocolException("sig_len inválido ou inconsistente no HELLO_REPLY: " + sigLen);
        }
        byte[] sig = new byte[sigLen];
        bb.get(sig);

        if (bb.remaining() < 2) {
            throw new ProtocolException("HELLO_REPLY truncado antes de cert_len");
        }
        int certLen = Short.toUnsignedInt(bb.getShort());
        if (certLen <= 0 || certLen != bb.remaining()) {
            throw new ProtocolException(
                    "cert_len inválido ou inconsistente no HELLO_REPLY: declarado=" + certLen
                            + ", restante=" + bb.remaining());
        }
        byte[] cert = new byte[certLen];
        bb.get(cert);

        return new HelloReplyMsg(pkS, salt, sig, cert);
    }

    // =========================================================================
    // 0x03 CONTROL (empacotamento interno do plaintext e envelope cifrado S2C)
    // =========================================================================

    /**
     * Serializa um {@link ControlPayload} em seus bytes em claro (1º byte = opcode).
     */
    public static byte[] packControlPlaintext(ControlPayload ctrl) throws ProtocolException {
        if (ctrl == null) {
            throw new ProtocolException("ControlPayload não pode ser nulo");
        }
        return switch (ctrl) {
            case RegisterOk ignored -> new byte[] {Constants.CTRL_REGISTER_OK};

            case PeerList list -> {
                List<PeerInfo> peers = list.peers();
                if (peers.size() > Constants.MAX_CLIENTS) {
                    throw new ProtocolException("PEER_LIST excede MAX_CLIENTS: " + peers.size());
                }
                int total = 1 + 2 + peers.size() * PEER_ENTRY_BYTES;
                ByteBuffer bb = ByteBuffer.allocate(total);
                bb.put(Constants.CTRL_PEER_LIST);
                bb.putShort((short) peers.size());
                for (PeerInfo p : peers) {
                    writePeerInfo(bb, p);
                }
                yield bb.array();
            }

            case PeerJoined joined -> {
                ByteBuffer bb = ByteBuffer.allocate(1 + PEER_ENTRY_BYTES);
                bb.put(Constants.CTRL_PEER_JOINED);
                writePeerInfo(bb, joined.peer());
                yield bb.array();
            }

            case PeerLeft left -> ByteBuffer.allocate(1 + Constants.CLIENT_ID_BYTES)
                    .put(Constants.CTRL_PEER_LEFT)
                    .put(left.clientId().toBytes())
                    .array();

            case ErrorMsg err -> {
                byte[] textBytes = err.message().getBytes(StandardCharsets.UTF_8);
                if (textBytes.length > MAX_ERROR_TEXT_BYTES) {
                    textBytes = Arrays.copyOf(textBytes, MAX_ERROR_TEXT_BYTES);
                }
                yield ByteBuffer.allocate(1 + 1 + textBytes.length)
                        .put(Constants.CTRL_ERROR)
                        .put(err.errorCode())
                        .put(textBytes)
                        .array();
            }
        };
    }

    /**
     * Desempacota o plaintext decifrado de uma mensagem {@code 0x03 CONTROL}.
     */
    public static ControlPayload unpackControlPlaintext(byte[] plaintext) throws ProtocolException {
        if (plaintext == null || plaintext.length < 1) {
            throw new ProtocolException("Plaintext de CONTROL vazio");
        }
        ByteBuffer bb = ByteBuffer.wrap(plaintext);
        byte opcode = bb.get();

        return switch (opcode) {
            case Constants.CTRL_REGISTER_OK -> {
                if (bb.hasRemaining()) {
                    throw new ProtocolException("Bytes extras após REGISTER_OK");
                }
                yield new RegisterOk();
            }

            case Constants.CTRL_PEER_LIST -> {
                if (bb.remaining() < 2) {
                    throw new ProtocolException("PEER_LIST truncado antes da contagem n");
                }
                int count = Short.toUnsignedInt(bb.getShort());
                if (count > Constants.MAX_CLIENTS || bb.remaining() != count * PEER_ENTRY_BYTES) {
                    throw new ProtocolException(
                            "Tamanho inconsistente em PEER_LIST: n=" + count + ", restante=" + bb.remaining());
                }
                List<PeerInfo> peers = new ArrayList<>(count);
                for (int i = 0; i < count; i++) {
                    peers.add(readPeerInfo(bb));
                }
                yield new PeerList(peers);
            }

            case Constants.CTRL_PEER_JOINED -> {
                if (bb.remaining() != PEER_ENTRY_BYTES) {
                    throw new ProtocolException("Tamanho inválido em PEER_JOINED: " + bb.remaining());
                }
                yield new PeerJoined(readPeerInfo(bb));
            }

            case Constants.CTRL_PEER_LEFT -> {
                if (bb.remaining() != Constants.CLIENT_ID_BYTES) {
                    throw new ProtocolException("Tamanho inválido em PEER_LEFT: " + bb.remaining());
                }
                byte[] idBytes = new byte[Constants.CLIENT_ID_BYTES];
                bb.get(idBytes);
                yield new PeerLeft(ClientId.fromBytes(idBytes));
            }

            case Constants.CTRL_ERROR -> {
                if (bb.remaining() < 1 || bb.remaining() > 1 + MAX_ERROR_TEXT_BYTES) {
                    throw new ProtocolException("Tamanho inválido em CTRL_ERROR: " + bb.remaining());
                }
                byte code = bb.get();
                byte[] textBytes = new byte[bb.remaining()];
                bb.get(textBytes);
                yield new ErrorMsg(code, new String(textBytes, StandardCharsets.UTF_8));
            }

            default -> throw new ProtocolException("Opcode de CONTROL desconhecido: 0x"
                    + Integer.toHexString(opcode & 0xFF));
        };
    }

    /**
     * Empacota o envelope externo de um frame {@code 0x03 CONTROL}:
     * {@code seq_no (8B big-endian) || ciphertextWithTag}.
     */
    public static byte[] packControlFrame(ControlFrame frame) throws ProtocolException {
        if (frame == null) {
            throw new ProtocolException("ControlFrame não pode ser nulo");
        }
        if (frame.seqNo() < 0) {
            throw new ProtocolException("seq_no de CONTROL não pode ser negativo: " + frame.seqNo());
        }
        byte[] ct = frame.ciphertextWithTag();
        if (ct.length < Constants.GCM_TAG_BYTES) {
            throw new ProtocolException("Ciphertext de CONTROL menor que a tag GCM");
        }
        return ByteBuffer.allocate(Constants.SEQ_NO_BYTES + ct.length)
                .putLong(frame.seqNo())
                .put(ct)
                .array();
    }

    /**
     * Desempacota o envelope externo de um frame {@code 0x03 CONTROL}, validando que
     * {@code seq_no >= 0} e que há bytes suficientes para a tag GCM.
     */
    public static ControlFrame unpackControlFrame(byte[] payload) throws ProtocolException {
        int minLen = Constants.SEQ_NO_BYTES + 1 + Constants.GCM_TAG_BYTES;
        if (payload == null || payload.length < minLen) {
            int len = payload == null ? -1 : payload.length;
            throw new ProtocolException("Frame CONTROL truncado (len=" + len + ")");
        }
        ByteBuffer bb = ByteBuffer.wrap(payload);
        long seqNo = bb.getLong();
        if (seqNo < 0) {
            throw new ProtocolException("seq_no negativo em frame CONTROL: " + seqNo);
        }
        byte[] ct = new byte[bb.remaining()];
        bb.get(ct);
        return new ControlFrame(seqNo, ct);
    }

    /**
     * Cifra e empacota uma mensagem de controle Servidor -> Cliente com {@code Key_S2C},
     * {@code nonce = 0x00000001 || seq_no} e {@code AAD = client_id || seq_no}.
     */
    public static byte[] sealControl(
            byte[] keyS2C, ClientId clientId, long seqNo, ControlPayload controlPayload)
            throws ProtocolException {
        byte[] plaintext = packControlPlaintext(controlPayload);
        byte[] nonce = buildControlNonce(seqNo);
        byte[] aad = buildControlAad(clientId, seqNo);
        byte[] ct = AesGcm.encrypt(keyS2C, nonce, aad, plaintext);
        return packControlFrame(new ControlFrame(seqNo, ct));
    }

    // =========================================================================
    // 0x04 E2E
    // =========================================================================

    /**
     * Empacota um {@link E2eFrame} no formato de 52 bytes de cabeçalho + ciphertext+tag:
     * {@code [nonce 12B][sender_id 16B][recipient_id 16B][seq_no 8B][ciphertext + tag 16B]}.
     */
    public static byte[] packE2eFrame(E2eFrame frame) throws ProtocolException {
        if (frame == null) {
            throw new ProtocolException("E2eFrame não pode ser nulo");
        }
        byte[] nonce = frame.nonce();
        byte[] ct = frame.ciphertextWithTag();
        if (nonce.length != Constants.NONCE_BYTES) {
            throw new ProtocolException("Nonce do E2eFrame deve ter 12 bytes");
        }
        if (frame.seqNo() < 0) {
            throw new ProtocolException("seq_no do E2eFrame não pode ser negativo: " + frame.seqNo());
        }
        if (frame.nonceSeqNo() != frame.seqNo()) {
            throw new ProtocolException("seq_no embutido no nonce diverge do campo seq_no do cabeçalho E2E");
        }
        int minCt = Constants.GCM_TAG_BYTES;
        int maxCt = Constants.MAX_PLAINTEXT + Constants.GCM_TAG_BYTES;
        if (ct.length < minCt || ct.length > maxCt) {
            throw new ProtocolException("Tamanho de ciphertext+tag E2E fora do limite: " + ct.length);
        }

        return ByteBuffer.allocate(Constants.E2E_HEADER_BYTES + ct.length)
                .put(nonce)
                .put(frame.senderId().toBytes())
                .put(frame.recipientId().toBytes())
                .putLong(frame.seqNo())
                .put(ct)
                .array();
    }

    /**
     * Desempacota o payload de um frame {@code 0x04 E2E}, validando tamanhos, não-negatividade
     * de {@code seq_no} e consistência entre o {@code seq_no} do cabeçalho e os 8 bytes finais
     * do {@code nonce}.
     */
    public static E2eFrame unpackE2eFrame(byte[] payload) throws ProtocolException {
        int minLen = Constants.E2E_HEADER_BYTES + Constants.GCM_TAG_BYTES;
        int maxLen = Constants.E2E_HEADER_BYTES + Constants.MAX_PLAINTEXT + Constants.GCM_TAG_BYTES;
        if (payload == null || payload.length < minLen || payload.length > maxLen) {
            int len = payload == null ? -1 : payload.length;
            throw new ProtocolException("Payload E2E com tamanho inválido: " + len);
        }

        ByteBuffer bb = ByteBuffer.wrap(payload);
        byte[] nonce = new byte[Constants.NONCE_BYTES];
        byte[] senderBytes = new byte[Constants.CLIENT_ID_BYTES];
        byte[] recipientBytes = new byte[Constants.CLIENT_ID_BYTES];
        bb.get(nonce);
        bb.get(senderBytes);
        bb.get(recipientBytes);
        long seqNo = bb.getLong();

        if (seqNo < 0) {
            throw new ProtocolException("seq_no negativo em frame E2E: " + seqNo);
        }
        long nonceSeq = ByteBuffer.wrap(nonce, Constants.IV_BASE_BYTES, Constants.SEQ_NO_BYTES).getLong();
        if (nonceSeq != seqNo) {
            throw new ProtocolException(
                    "Inconsistência no frame E2E: seq_no do nonce (" + nonceSeq
                            + ") != seq_no do cabeçalho (" + seqNo + ")");
        }

        byte[] ct = new byte[bb.remaining()];
        bb.get(ct);

        return new E2eFrame(
                nonce,
                ClientId.fromBytes(senderBytes),
                ClientId.fromBytes(recipientBytes),
                seqNo,
                ct);
    }

    private static void writePeerInfo(ByteBuffer bb, PeerInfo peer) throws ProtocolException {
        if (peer == null) {
            throw new ProtocolException("PeerInfo não pode ser nulo");
        }
        byte[] pkC = peer.pkC();
        byte[] salt = peer.saltSrv();
        if (pkC.length != Constants.X25519_KEY_BYTES || salt.length != Constants.SALT_BYTES) {
            throw new ProtocolException("PeerInfo com tamanho inválido de pk_C ou salt_srv");
        }
        bb.put(peer.clientId().toBytes());
        bb.put(pkC);
        bb.put(salt);
    }

    private static PeerInfo readPeerInfo(ByteBuffer bb) throws ProtocolException {
        byte[] idBytes = new byte[Constants.CLIENT_ID_BYTES];
        byte[] pkC = new byte[Constants.X25519_KEY_BYTES];
        byte[] salt = new byte[Constants.SALT_BYTES];
        bb.get(idBytes);
        bb.get(pkC);
        bb.get(salt);
        return new PeerInfo(ClientId.fromBytes(idBytes), pkC, salt);
    }
}
