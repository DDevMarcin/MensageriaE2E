package securechat.client;

import securechat.common.AesGcm;
import securechat.common.Bytes;
import securechat.common.ClientId;
import securechat.common.Constants;
import securechat.common.Hkdf;
import securechat.common.Messages;
import securechat.common.ProtocolException;
import securechat.common.X25519Util;

import java.security.PrivateKey;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Estado criptográfico E2E mantido pelo cliente para cada peer ativo ({@code docs/02}).
 *
 * <p><b>Derivação determinística de chaves por direção (seção 7 de {@code docs/01}):</b></p>
 * <ul>
 *   <li>Ordem canônica: {@code A = min(selfId, peerId)} e {@code B = max(selfId, peerId)}
 *       usando comparação sem sinal ({@link ClientId#compareTo}).</li>
 *   <li>Salt do par (Decisão D2): {@code salt_par = salt_srv} do cliente {@code A}.</li>
 *   <li>{@code Z_AB = ECDH(sk_self, pk_peer)} (zerado com {@link Bytes#wipe} logo após o HKDF).</li>
 *   <li>{@code PRK = HKDF-Extract(salt_par, Z_AB)}.</li>
 *   <li>{@code Key_A2B = HKDF-Expand(PRK, "A2B", 16)} e {@code Key_B2A = HKDF-Expand(PRK, "B2A", 16)}.</li>
 *   <li>Se {@code self == A}: {@code keySend = Key_A2B}, {@code keyRecv = Key_B2A}.
 *       Se {@code self == B}: {@code keySend = Key_B2A}, {@code keyRecv = Key_A2B}.</li>
 * </ul>
 */
public final class PeerState {

    final ClientId peerId;
    final byte[] publicKey;
    final byte[] salt;
    final byte[] keySend;
    final byte[] keyRecv;
    final byte[] ivBaseSend;
    byte[] ivBaseRecv = null;
    long seqSend = 0;
    long seqRecv = -1;

    private final ReentrantLock lock = new ReentrantLock();

    private PeerState(
            ClientId peerId,
            byte[] publicKey,
            byte[] salt,
            byte[] keySend,
            byte[] keyRecv,
            byte[] ivBaseSend) {
        this.peerId = Objects.requireNonNull(peerId, "peerId não pode ser nulo");
        this.publicKey = publicKey.clone();
        this.salt = salt.clone();
        this.keySend = keySend.clone();
        this.keyRecv = keyRecv.clone();
        this.ivBaseSend = ivBaseSend.clone();
    }

    /**
     * Deriva um novo {@link PeerState} completo a partir das credenciais locais e do
     * {@link Messages.PeerInfo} recebido do servidor, descartando {@code Z_AB} e {@code PRK}
     * da memória ao final.
     */
    public static PeerState derive(
            ClientId selfId,
            PrivateKey skSelf,
            byte[] selfSalt,
            Messages.PeerInfo peerInfo) throws ProtocolException {

        Objects.requireNonNull(selfId, "selfId não pode ser nulo");
        Objects.requireNonNull(skSelf, "skSelf não pode ser nula");
        Objects.requireNonNull(selfSalt, "selfSalt não pode ser nulo");
        Objects.requireNonNull(peerInfo, "peerInfo não pode ser nulo");

        ClientId peerId = peerInfo.clientId();
        int cmp = selfId.compareTo(peerId);
        if (cmp == 0) {
            throw new ProtocolException("Não é permitido derivar PeerState consigo mesmo: " + selfId);
        }

        // A é o cliente com o menor client_id na comparação unsigned; B é o outro
        boolean selfIsA = cmp < 0;
        // Decisão D2: ambos usam o salt_srv pertencente ao cliente A
        byte[] saltPar = selfIsA ? selfSalt.clone() : peerInfo.saltSrv();

        byte[] zAB = null;
        byte[] prk = null;
        byte[] keyA2B = null;
        byte[] keyB2A = null;
        try {
            zAB = X25519Util.sharedSecret(skSelf, peerInfo.pkC());
            prk = Hkdf.extract(saltPar, zAB);

            keyA2B = Hkdf.expand(prk, Constants.HKDF_INFO_A2B, Constants.AES_KEY_BYTES);
            keyB2A = Hkdf.expand(prk, Constants.HKDF_INFO_B2A, Constants.AES_KEY_BYTES);

            byte[] keySend = selfIsA ? keyA2B : keyB2A;
            byte[] keyRecv = selfIsA ? keyB2A : keyA2B;
            byte[] ivBaseSend = Bytes.randomBytes(Constants.IV_BASE_BYTES);

            return new PeerState(peerId, peerInfo.pkC(), saltPar, keySend, keyRecv, ivBaseSend);
        } finally {
            // Regra de ouro: nunca manter Z_AB, PRK nem cópias temporárias de chaves na RAM
            Bytes.wipe(zAB, prk, keyA2B, keyB2A);
        }
    }

    public ClientId peerId() {
        return peerId;
    }

    public byte[] publicKey() {
        return publicKey.clone();
    }

    public byte[] salt() {
        return salt.clone();
    }

    public byte[] keySend() {
        return keySend.clone();
    }

    public byte[] keyRecv() {
        return keyRecv.clone();
    }

    public byte[] ivBaseSend() {
        return ivBaseSend.clone();
    }

    public byte[] ivBaseRecv() {
        lock.lock();
        try {
            return ivBaseRecv == null ? null : ivBaseRecv.clone();
        } finally {
            lock.unlock();
        }
    }

    public long seqSend() {
        lock.lock();
        try {
            return seqSend;
        } finally {
            lock.unlock();
        }
    }

    public long seqRecv() {
        lock.lock();
        try {
            return seqRecv;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Cifra uma mensagem em claro para este peer usando {@code keySend}, montando
     * {@code nonce = ivBaseSend || seqSend} e {@code AAD = selfId || peerId || seqSend}.
     *
     * <p>Regra de consistência ({@code docs/02}): {@code seqSend} só incrementa <b>depois</b>
     * que o frame é cifrado e construído com sucesso.</p>
     */
    public Messages.E2eFrame sealMessage(ClientId selfId, byte[] plaintext) throws ProtocolException {
        if (plaintext == null) {
            throw new ProtocolException("Plaintext não pode ser nulo");
        }
        if (plaintext.length > Constants.MAX_PLAINTEXT) {
            throw new ProtocolException(
                    "Mensagem excede o tamanho máximo de " + Constants.MAX_PLAINTEXT
                            + " bytes (tamanho: " + plaintext.length + ")");
        }

        lock.lock();
        try {
            if (seqSend == Long.MAX_VALUE) {
                throw new ProtocolException("Limite de seq_send atingido para o peer " + peerId);
            }
            long currentSeq = seqSend;
            byte[] nonce = Messages.buildE2eNonce(ivBaseSend, currentSeq);
            byte[] aad = Messages.buildE2eAad(selfId, peerId, currentSeq);
            byte[] ct = AesGcm.encrypt(keySend, nonce, aad, plaintext);

            Messages.E2eFrame frame = new Messages.E2eFrame(nonce, selfId, peerId, currentSeq, ct);
            seqSend = currentSeq + 1;
            return frame;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Valida e decifra um {@link Messages.E2eFrame} recebido deste peer (seção 8 de {@code docs/01}):
     * <ol>
     *   <li>Confere {@code sender_id == peerId} e {@code recipient_id == selfId}.</li>
     *   <li>Confere que o {@code seq_no} do nonce é igual ao campo {@code seq_no}.</li>
     *   <li>Confere anti-replay: {@code seq_no > seqRecv}.</li>
     *   <li>Confere {@code IV_base} do nonce contra {@code ivBaseRecv} (se já aprendido no 1º frame, D3).</li>
     *   <li>Decifra com {@code keyRecv} e {@code AAD = sender_id || recipient_id || seq_no}.</li>
     *   <li><b>Somente se a tag GCM validar</b>, fixa {@code ivBaseRecv} (no 1º frame) e
     *       atualiza {@code seqRecv = seq_no}.</li>
     * </ol>
     */
    public byte[] openMessage(ClientId selfId, Messages.E2eFrame frame) throws ProtocolException {
        Objects.requireNonNull(selfId, "selfId não pode ser nulo");
        Objects.requireNonNull(frame, "frame não pode ser nulo");

        lock.lock();
        try {
            if (!frame.senderId().equals(peerId)) {
                throw new ProtocolException("sender_id do frame E2E diverge do peerId esperado");
            }
            if (!frame.recipientId().equals(selfId)) {
                throw new ProtocolException("recipient_id do frame E2E não corresponde a este cliente");
            }
            if (frame.nonceSeqNo() != frame.seqNo()) {
                throw new ProtocolException("seq_no do nonce diverge do campo seq_no do frame E2E");
            }
            if (frame.seqNo() <= seqRecv) {
                throw new ProtocolException(
                        "replay detectado: seq_no recebido (" + frame.seqNo()
                                + ") <= último seq_no aceito (" + seqRecv + ")");
            }

            byte[] frameIvBase = frame.ivBase();
            if (ivBaseRecv != null && !Bytes.constantTimeEquals(ivBaseRecv, frameIvBase)) {
                throw new ProtocolException(
                        "IV_base do frame E2E diverge do IV_base_recv aprendido na sessão (D3)");
            }

            byte[] aad = Messages.buildE2eAad(peerId, selfId, frame.seqNo());
            byte[] plaintext = AesGcm.decrypt(keyRecv, frame.nonce(), aad, frame.ciphertextWithTag());

            // Regra de ouro 5: atualizar seqRecv e ivBaseRecv SOMENTE após a tag GCM validar
            if (ivBaseRecv == null) {
                ivBaseRecv = frameIvBase;
            }
            seqRecv = frame.seqNo();
            return plaintext;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Limpa as chaves simétricas E2E da memória quando o peer desconecta ou reconecta.
     */
    public void wipe() {
        lock.lock();
        try {
            Bytes.wipe(keySend, keyRecv);
        } finally {
            lock.unlock();
        }
    }
}

