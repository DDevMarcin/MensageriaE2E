package securechat.server;

import securechat.common.Bytes;
import securechat.common.CertUtil;
import securechat.common.ClientId;
import securechat.common.Constants;
import securechat.common.Framing;
import securechat.common.FramingException;
import securechat.common.Messages;
import securechat.common.ProtocolException;
import securechat.common.SecureLog;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Semaphore;

/**
 * Tarefa executada em uma virtual thread dedicada por cliente conectado ao servidor.
 *
 * <p>Responsabilidades:</p>
 * <ol>
 *   <li>Conduzir o {@link ServerHandshake} e estabelecer {@code Key_S2C}.</li>
 *   <li>Verificar o limite {@code MAX_CLIENTS} e a unicidade do {@code client_id} (D4),
 *       enviando {@code CONTROL(ERROR)} cifrado com {@code Key_S2C} caso recusado.</li>
 *   <li>Registrar a {@link Session}, enviar {@code REGISTER_OK} e {@code PEER_LIST} (apenas
 *       com os demais peers) ao novo cliente e notificar {@code PEER_JOINED} aos outros.</li>
 *   <li>No loop de leitura, validar {@code sender_id == session.clientId} (anti-spoof) e
 *       encaminhar frames {@code 0x04 E2E} ao destinatário sem decifrar.</li>
 *   <li>No bloco {@code finally}, remover a sessão, limpar {@code Key_S2C} e notificar
 *       {@code PEER_LEFT} aos demais clientes conectados.</li>
 * </ol>
 */
public final class ClientConnection implements Runnable {

    private final Socket socket;
    private final CertUtil.ServerIdentity serverIdentity;
    private final SessionRegistry registry;
    private final Semaphore clientSlots;
    private final int handshakeTimeoutMs;

    public ClientConnection(
            Socket socket,
            CertUtil.ServerIdentity serverIdentity,
            SessionRegistry registry,
            Semaphore clientSlots,
            int handshakeTimeoutMs) {
        this.socket = Objects.requireNonNull(socket, "socket não pode ser nulo");
        this.serverIdentity = Objects.requireNonNull(serverIdentity, "serverIdentity não pode ser nula");
        this.registry = Objects.requireNonNull(registry, "registry não pode ser nulo");
        this.clientSlots = Objects.requireNonNull(clientSlots, "clientSlots não pode ser nulo");
        this.handshakeTimeoutMs = handshakeTimeoutMs;
    }

    @Override
    public void run() {
        Session session = null;
        boolean slotAcquired = false;
        boolean registered = false;

        try (DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

            // 1. Executa handshake (HELLO -> HELLO_REPLY) e deriva Key_S2C
            ServerHandshake.Result hs = ServerHandshake.perform(
                    socket, in, out, serverIdentity, handshakeTimeoutMs);

            session = new Session(
                    hs.clientId(), socket, out, hs.pkC(), hs.saltSrv(), hs.keyS2C());

            // 2. Verifica limite de conexões simultâneas (MAX_CLIENTS)
            if (!clientSlots.tryAcquire()) {
                SecureLog.rejected(session.clientId(), "servidor lotado (MAX_CLIENTS atingido)");
                sendErrorQuietly(session, Constants.ERR_SERVER_FULL, "Servidor lotado");
                return;
            }
            slotAcquired = true;

            // 3. Segura o writeLock da nova sessão durante o registro + envio de REGISTER_OK e PEER_LIST.
            // Como ReentrantLock é reentrante, isso impede que outra virtual thread (em broadcast de
            // PEER_JOINED/PEER_LEFT) envie controles antes de REGISTER_OK (seq 0) e PEER_LIST (seq 1).
            session.writeLock.lock();
            try {
                if (!registry.register(session)) {
                    SecureLog.rejected(session.clientId(), "client_id duplicado ativo");
                    sendErrorQuietly(session, Constants.ERR_DUPLICATE_CLIENT_ID,
                            "client_id ja possui sessao ativa");
                    return;
                }
                registered = true;

                SecureLog.connected(session.clientId(), Bytes.fingerprint(session.publicKey()));

                // 4. Envia confirmação REGISTER_OK (seq 0) e PEER_LIST (seq 1, excluindo o próprio cliente)
                List<Messages.PeerInfo> otherPeers = registry.snapshotOtherPeerInfos(session.clientId());
                session.sendControl(new Messages.RegisterOk());
                session.sendControl(new Messages.PeerList(otherPeers));
            } finally {
                session.writeLock.unlock();
            }

            // 5. Notifica PEER_JOINED a todos os demais clientes já conectados
            Messages.PeerJoined joinedMsg = new Messages.PeerJoined(session.toPeerInfo());
            for (Session other : registry.snapshotOtherSessions(session.clientId())) {
                try {
                    other.sendControl(joinedMsg);
                } catch (ProtocolException | IOException e) {
                    SecureLog.warn("Falha ao enviar PEER_JOINED para " + other.clientId());
                }
            }

            // 6. Loop principal de leitura e roteamento cego de frames E2E
            readLoop(session, in);

        } catch (FramingException e) {
            if (!e.isCleanEof()) {
                ClientId id = session == null ? null : session.clientId();
                SecureLog.rejected(id, "framing invalido: " + e.getMessage());
            }
        } catch (ProtocolException e) {
            ClientId id = session == null ? null : session.clientId();
            SecureLog.rejected(id, "erro de protocolo: " + e.getMessage());
        } catch (IOException e) {
            // Queda abrupta de socket tratada silenciosamente com desconexão limpa no finally
        } catch (RuntimeException e) {
            ClientId id = session == null ? null : session.clientId();
            SecureLog.error("Erro inesperado na sessao " + (id == null ? "desconhecida" : id),
                    e.getClass().getSimpleName());
        } finally {
            if (registered && session != null && registry.removeIfSame(session.clientId(), session)) {
                SecureLog.disconnected(session.clientId());
                Messages.PeerLeft leftMsg = new Messages.PeerLeft(session.clientId());
                for (Session other : registry.snapshotOtherSessions(session.clientId())) {
                    try {
                        other.sendControl(leftMsg);
                    } catch (ProtocolException | IOException ignored) {
                    }
                }
            }
            if (slotAcquired) {
                clientSlots.release();
            }
            if (session != null) {
                session.closeAndWipe();
            } else {
                try {
                    socket.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    private void readLoop(Session session, DataInputStream in) throws ProtocolException, IOException {
        while (!socket.isClosed()) {
            Framing.Frame frame = Framing.readFrame(in);
            if (frame.type() != Constants.TYPE_E2E) {
                SecureLog.rejected(session.clientId(),
                        "tipo de frame invalido apos handshake: " + frame.type(),
                        frame.payload().length);
                throw new ProtocolException("Cliente só pode enviar frames E2E (0x04) após handshake");
            }

            Messages.E2eFrame e2e = Messages.unpackE2eFrame(frame.payload());

            // Anti-spoof: garante que o sender_id declarado no cabeçalho E2E é o dono deste socket
            if (!e2e.senderId().equals(session.clientId())) {
                SecureLog.rejected(session.clientId(),
                        "sender_id forjado no frame E2E (declarado=" + e2e.senderId() + ")",
                        frame.payload().length);
                continue;
            }

            Session target = registry.get(e2e.recipientId());
            if (target == null) {
                SecureLog.rejected(session.clientId(),
                        "destinatario inexistente: " + e2e.recipientId(),
                        frame.payload().length);
                session.sendControl(new Messages.ErrorMsg(
                        Constants.ERR_UNKNOWN_RECIPIENT,
                        "Destinatario nao encontrado: " + e2e.recipientId()));
                continue;
            }

            // Repassa os bytes do frame E2E sem alterar nenhum bit e sem decifrar
            target.forwardE2ePayload(frame.payload());
            SecureLog.routed(session.clientId(), target.clientId(), frame.payload().length);
        }
    }

    private static void sendErrorQuietly(Session session, byte code, String text) {
        try {
            session.sendControl(new Messages.ErrorMsg(code, text));
        } catch (ProtocolException | IOException ignored) {
        }
    }
}

