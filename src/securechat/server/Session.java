package securechat.server;

import securechat.common.Bytes;
import securechat.common.ClientId;
import securechat.common.Constants;
import securechat.common.Framing;
import securechat.common.Messages;
import securechat.common.ProtocolException;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Representa a sessão ativa de um cliente registrado no servidor (conforme {@code docs/02}).
 *
 * <p><b>Isolamento E2E (Regra de Ouro 1):</b> Esta classe armazena apenas a chave pública
 * X25519 do cliente ({@code publicKey}), o {@code salt} do seu handshake e a chave de
 * controle administrativo Servidor -> Cliente ({@code keyCtrl = Key_S2C}). Ela <b>não</b>
 * possui e jamais calcula nenhuma chave E2E ({@code Z_AB}, {@code Key_A2B}, {@code Key_B2A}).</p>
 *
 * <p><b>Concorrência em Virtual Threads (Java 21):</b> Todas as escritas no {@link DataOutputStream}
 * do socket são protegidas por um {@link ReentrantLock} ({@code writeLock}) em vez de
 * {@code synchronized}, evitando o <i>pinning</i> da virtual thread na carrier thread do SO
 * durante bloqueios de I/O de rede.</p>
 */
public final class Session {

    final ClientId clientId;
    final Socket socket;
    final DataOutputStream out;
    final ReentrantLock writeLock = new ReentrantLock();
    final byte[] publicKey;
    final byte[] salt;
    final byte[] keyCtrl;
    long seqRecv = -1;
    long seqSend = 0;

    public Session(
            ClientId clientId,
            Socket socket,
            DataOutputStream out,
            byte[] publicKey,
            byte[] salt,
            byte[] keyCtrl) {
        this.clientId = Objects.requireNonNull(clientId, "clientId não pode ser nulo");
        this.socket = Objects.requireNonNull(socket, "socket não pode ser nulo");
        this.out = Objects.requireNonNull(out, "out não pode ser nulo");
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey não pode ser nula").clone();
        this.salt = Objects.requireNonNull(salt, "salt não pode ser nulo").clone();
        this.keyCtrl = Objects.requireNonNull(keyCtrl, "keyCtrl não pode ser nula").clone();
    }

    public ClientId clientId() {
        return clientId;
    }

    public byte[] publicKey() {
        return publicKey.clone();
    }

    public byte[] salt() {
        return salt.clone();
    }

    /**
     * Constrói um {@link Messages.PeerInfo} com os dados públicos desta sessão para envio
     * em {@code PEER_LIST} e {@code PEER_JOINED}.
     */
    public Messages.PeerInfo toPeerInfo() {
        return new Messages.PeerInfo(clientId, publicKey, salt);
    }

    /**
     * Cifra e envia uma mensagem administrativa {@code 0x03 CONTROL} ao cliente.
     *
     * <p>O incremento de {@code seqSend}, a cifragem AES-GCM com {@code keyCtrl} e a escrita
     * no socket ocorrem dentro do mesmo {@link #writeLock}, garantindo que a ordem de
     * {@code seq_no} no fio coincida estritamente com a ordem de transmissão.</p>
     */
    public void sendControl(Messages.ControlPayload payload) throws ProtocolException, IOException {
        writeLock.lock();
        try {
            if (seqSend == Long.MAX_VALUE) {
                throw new ProtocolException("Limite de seqSend atingido no canal de controle");
            }
            long currentSeq = seqSend;
            byte[] packedControl = Messages.sealControl(keyCtrl, clientId, currentSeq, payload);
            Framing.writeFrame(out, Constants.TYPE_CONTROL, packedControl);
            seqSend = currentSeq + 1;
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Encaminha (relay cego) o payload bruto de um frame {@code 0x04 E2E} para este cliente
     * sob {@link #writeLock}, sem alterar nem decifrar nenhum byte.
     */
    public void forwardE2ePayload(byte[] rawE2ePayload) throws ProtocolException, IOException {
        writeLock.lock();
        try {
            Framing.writeFrame(out, Constants.TYPE_E2E, rawE2ePayload);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Zera a chave de controle {@code keyCtrl} da memória e fecha o socket da sessão.
     */
    public void closeAndWipe() {
        writeLock.lock();
        try {
            Bytes.wipe(keyCtrl);
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        } finally {
            writeLock.unlock();
        }
    }
}

