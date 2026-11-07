package securechat.client;

import securechat.common.AesGcm;
import securechat.common.Bytes;
import securechat.common.CertUtil;
import securechat.common.ClientId;
import securechat.common.Constants;
import securechat.common.Framing;
import securechat.common.FramingException;
import securechat.common.Messages;
import securechat.common.ProtocolException;
import securechat.common.SecureLog;
import securechat.common.X25519Util;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * Cliente do sistema de mensageria segura E2E.
 *
 * <p>Mantém a identidade efêmera da sessão ({@code selfId}, {@code skClient}, {@code pkClient}),
 * o certificado pinado do servidor ({@code certPinado}), a chave de controle ({@code keyCtrl = Key_S2C})
 * com seu contador anti-replay ({@code ctrlSeqRecv = -1}) e a {@link PeerTable} com as chaves
 * E2E de cada par.</p>
 */
public final class Client implements AutoCloseable {

    private final ClientId selfId;
    private final KeyPair keyPair;
    private final byte[] pkClient;
    private final X509Certificate certPinado;
    private final PeerTable peerTable = new PeerTable();
    private final ReentrantLock writeLock = new ReentrantLock();
    private final ReentrantLock ctrlLock = new ReentrantLock();
    private final CountDownLatch initialSyncLatch = new CountDownLatch(1);
    private final AtomicBoolean running = new AtomicBoolean(false);

    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private byte[] saltSrv;
    private byte[] keyCtrl;
    private long ctrlSeqRecv = -1;
    private Thread readerThread;

    private volatile BiConsumer<ClientId, String> messageListener = (from, text) -> {};
    private volatile Consumer<Messages.ErrorMsg> errorListener = err -> {};
    private volatile Consumer<ClientId> peerJoinedListener = id -> {};
    private volatile Consumer<ClientId> peerLeftListener = id -> {};
    private volatile Consumer<String> rejectionListener = reason -> {};

    /**
     * Cria uma instância de cliente com {@link ClientId} e par X25519 efêmero fornecidos.
     */
    public Client(ClientId selfId, KeyPair keyPair, X509Certificate certPinado)
            throws ProtocolException {
        this.selfId = Objects.requireNonNull(selfId, "selfId não pode ser nulo");
        this.keyPair = Objects.requireNonNull(keyPair, "keyPair não pode ser nulo");
        this.pkClient = X25519Util.toRawPublicKey(keyPair.getPublic());
        this.certPinado = Objects.requireNonNull(certPinado, "certPinado não pode ser nulo");
    }

    /**
     * Cria uma instância de cliente gerando automaticamente um novo {@link ClientId} (UUID v4)
     * e um novo par de chaves X25519 efêmero.
     */
    public Client(X509Certificate certPinado) throws ProtocolException {
        this(ClientId.random(), X25519Util.generateKeyPair(), certPinado);
    }

    /**
     * Configura um cliente pronto para uso no estado pós-handshake (útil para testes unitários
     * de controle e derivação sem abrir socket).
     */
    public static Client createForUnitTest(
            ClientId selfId,
            KeyPair keyPair,
            X509Certificate certPinado,
            byte[] saltSrv,
            byte[] keyCtrl) throws ProtocolException {
        Client c = new Client(selfId, keyPair, certPinado);
        c.saltSrv = saltSrv.clone();
        c.keyCtrl = keyCtrl.clone();
        return c;
    }

    public ClientId selfId() {
        return selfId;
    }

    public byte[] pkClient() {
        return pkClient.clone();
    }

    public byte[] saltSrv() {
        return saltSrv == null ? null : saltSrv.clone();
    }

    public PeerTable peerTable() {
        return peerTable;
    }

    public PrivateKey privateKey() {
        return keyPair.getPrivate();
    }

    public void setMessageListener(BiConsumer<ClientId, String> listener) {
        this.messageListener = Objects.requireNonNull(listener);
    }

    public void setErrorListener(Consumer<Messages.ErrorMsg> listener) {
        this.errorListener = Objects.requireNonNull(listener);
    }

    public void setPeerJoinedListener(Consumer<ClientId> listener) {
        this.peerJoinedListener = Objects.requireNonNull(listener);
    }

    public void setPeerLeftListener(Consumer<ClientId> listener) {
        this.peerLeftListener = Objects.requireNonNull(listener);
    }

    public void setRejectionListener(Consumer<String> listener) {
        this.rejectionListener = Objects.requireNonNull(listener);
    }

    /**
     * Conecta ao servidor TCP, executa o {@link ClientHandshake} e inicia a virtual thread
     * leitora para processar mensagens {@code CONTROL} e {@code E2E}.
     */
    public void connect(String host, int port, int handshakeTimeoutMs)
            throws ProtocolException, IOException {
        socket = new Socket(host, port);
        in = new DataInputStream(socket.getInputStream());
        out = new DataOutputStream(socket.getOutputStream());

        ClientHandshake.Result hs = ClientHandshake.perform(
                socket, in, out, selfId, keyPair, certPinado, handshakeTimeoutMs);
        this.saltSrv = hs.saltSrv();
        this.keyCtrl = hs.keyS2C();
        this.ctrlSeqRecv = -1;

        running.set(true);
        readerThread = Thread.ofVirtual()
                .name("client-reader-" + selfId.shortHex())
                .start(this::readLoop);
    }

    public void connect(String host, int port) throws ProtocolException, IOException {
        connect(host, port, Constants.HANDSHAKE_TIMEOUT_MS);
    }

    /**
     * Aguarda até que o cliente receba {@code REGISTER_OK} e a {@code PEER_LIST} inicial do servidor.
     */
    public boolean awaitInitialSync(long timeoutMs) throws InterruptedException {
        return initialSyncLatch.await(timeoutMs, TimeUnit.MILLISECONDS);
    }

    /**
     * Processa o payload bruto de um frame {@code 0x03 CONTROL} recebido do servidor:
     * valida anti-replay ({@code seq_no > ctrlSeqRecv}), decifra com {@code keyCtrl} e
     * {@code AAD = selfId || seq_no}, atualiza {@code ctrlSeqRecv} somente se a tag GCM
     * validar e aplica a operação na {@link PeerTable}.
     */
    public Messages.ControlPayload processControlFrame(byte[] rawControlPayload)
            throws ProtocolException {
        ctrlLock.lock();
        try {
            Messages.ControlFrame cf = Messages.unpackControlFrame(rawControlPayload);
            if (cf.seqNo() <= ctrlSeqRecv) {
                String reason = "replay no canal de controle: seq=" + cf.seqNo() + " <= " + ctrlSeqRecv;
                SecureLog.rejected(selfId, reason, rawControlPayload.length);
                rejectionListener.accept(reason);
                throw new ProtocolException(
                        "Replay detectado no canal de controle: seq_no=" + cf.seqNo());
            }

            byte[] nonce = Messages.buildControlNonce(cf.seqNo());
            byte[] aad = Messages.buildControlAad(selfId, cf.seqNo());
            byte[] plaintext = null;
            try {
                try {
                    plaintext = AesGcm.decrypt(keyCtrl, nonce, aad, cf.ciphertextWithTag());
                } catch (ProtocolException e) {
                    SecureLog.rejected(selfId, "tag mismatch no canal de controle", rawControlPayload.length);
                    rejectionListener.accept("tag mismatch no canal de controle");
                    throw e;
                }

                // Só atualiza ctrlSeqRecv após a tag GCM validar (Regra de Ouro 5)
                ctrlSeqRecv = cf.seqNo();

                Messages.ControlPayload payload = Messages.unpackControlPlaintext(plaintext);
                applyControlPayload(payload);
                return payload;
            } finally {
                Bytes.wipe(plaintext);
            }
        } finally {
            ctrlLock.unlock();
        }
    }

    private void applyControlPayload(Messages.ControlPayload payload) throws ProtocolException {
        switch (payload) {
            case Messages.RegisterOk ignored -> {
                // Confirmação recebida; PEER_LIST vem logo em seguida
            }
            case Messages.PeerList list -> {
                for (Messages.PeerInfo info : list.peers()) {
                    peerTable.upsertPeer(selfId, keyPair.getPrivate(), saltSrv, info);
                }
                initialSyncLatch.countDown();
            }
            case Messages.PeerJoined joined -> {
                PeerState ps = peerTable.upsertPeer(
                        selfId, keyPair.getPrivate(), saltSrv, joined.peer());
                if (ps != null) {
                    peerJoinedListener.accept(ps.peerId());
                }
            }
            case Messages.PeerLeft left -> {
                PeerState removed = peerTable.removePeer(left.clientId());
                if (removed != null) {
                    peerLeftListener.accept(left.clientId());
                }
            }
            case Messages.ErrorMsg err -> {
                errorListener.accept(err);
                initialSyncLatch.countDown();
            }
        }
    }

    /**
     * Processa o payload bruto de um frame {@code 0x04 E2E} recebido do servidor:
     * desempacota o cabeçalho, busca o remetente na {@link PeerTable}, valida anti-replay,
     * {@code IV_base_recv} e tag GCM via {@link PeerState#openMessage} e entrega o texto
     * claro ao listener.
     */
    public String processE2eFrame(byte[] rawE2ePayload) throws ProtocolException {
        Messages.E2eFrame frame;
        try {
            frame = Messages.unpackE2eFrame(rawE2ePayload);
        } catch (ProtocolException e) {
            String reason = "frame E2E malformado: " + e.getMessage();
            SecureLog.rejected(selfId, reason,
                    rawE2ePayload == null ? 0 : rawE2ePayload.length);
            rejectionListener.accept(reason);
            throw e;
        }

        if (!frame.recipientId().equals(selfId)) {
            String reason = "recipient_id incorreto no frame E2E";
            SecureLog.rejected(selfId, reason, rawE2ePayload.length);
            rejectionListener.accept(reason);
            throw new ProtocolException("Frame E2E endereçado a outro destinatário");
        }

        PeerState peer = peerTable.get(frame.senderId());
        if (peer == null) {
            String reason = "remetente E2E desconhecido: " + frame.senderId();
            SecureLog.rejected(selfId, reason, rawE2ePayload.length);
            rejectionListener.accept(reason);
            throw new ProtocolException("Remetente E2E não consta na PeerTable: " + frame.senderId());
        }

        byte[] plaintext = null;
        try {
            plaintext = peer.openMessage(selfId, frame);
            String text = new String(plaintext, StandardCharsets.UTF_8);
            messageListener.accept(frame.senderId(), text);
            return text;
        } catch (ProtocolException e) {
            SecureLog.rejected(selfId, e.getMessage(), rawE2ePayload.length);
            rejectionListener.accept(e.getMessage());
            throw e;
        } finally {
            Bytes.wipe(plaintext);
        }
    }

    /**
     * Cifra e envia uma mensagem de texto UTF-8 (máx. 4096 bytes) para {@code recipientId}.
     */
    public void sendMessage(ClientId recipientId, String text) throws ProtocolException, IOException {
        Objects.requireNonNull(recipientId, "recipientId não pode ser nulo");
        Objects.requireNonNull(text, "text não pode ser nulo");

        byte[] plaintext = text.getBytes(StandardCharsets.UTF_8);
        try {
            if (plaintext.length > Constants.MAX_PLAINTEXT) {
                throw new ProtocolException(
                        "Mensagem excede o limite máximo de " + Constants.MAX_PLAINTEXT
                                + " bytes (tamanho: " + plaintext.length + ")");
            }

            PeerState peer = peerTable.get(recipientId);
            if (peer == null) {
                throw new ProtocolException("Peer não encontrado na PeerTable: " + recipientId);
            }

            Messages.E2eFrame frame = peer.sealMessage(selfId, plaintext);
            byte[] packed = Messages.packE2eFrame(frame);
            sendRawE2ePayload(packed);
        } finally {
            Bytes.wipe(plaintext);
        }
    }

    /**
     * Envia os bytes já empachecados de um payload {@code 0x04 E2E} sob {@link #writeLock}.
     */
    public void sendRawE2ePayload(byte[] packedE2ePayload) throws ProtocolException, IOException {
        writeLock.lock();
        try {
            if (out == null || socket == null || socket.isClosed()) {
                throw new IOException("Cliente não está conectado ao servidor");
            }
            Framing.writeFrame(out, Constants.TYPE_E2E, packedE2ePayload);
        } finally {
            writeLock.unlock();
        }
    }

    private void readLoop() {
        try {
            while (running.get() && !socket.isClosed()) {
                Framing.Frame frame = Framing.readFrame(in);
                switch (frame.type()) {
                    case Constants.TYPE_CONTROL -> {
                        try {
                            processControlFrame(frame.payload());
                        } catch (ProtocolException ignored) {
                            // Já registrado via SecureLog.rejected em processControlFrame
                        }
                    }
                    case Constants.TYPE_E2E -> {
                        try {
                            processE2eFrame(frame.payload());
                        } catch (ProtocolException ignored) {
                            // Já registrado via SecureLog.rejected em processE2eFrame
                        }
                    }
                    default -> SecureLog.rejected(
                            selfId,
                            "tipo de frame desconhecido recebido pelo cliente: " + frame.type(),
                            frame.payload().length);
                }
            }
        } catch (FramingException e) {
            if (running.get() && !e.isCleanEof()) {
                SecureLog.rejected(selfId, "framing invalido recebido pelo cliente: " + e.getMessage());
            }
        } catch (IOException ignored) {
        } catch (RuntimeException e) {
            SecureLog.error("Erro inesperado no leitor do cliente " + selfId, e.getClass().getSimpleName());
        } finally {
            running.set(false);
            initialSyncLatch.countDown();
        }
    }

    @Override
    public void close() {
        running.set(false);
        initialSyncLatch.countDown();
        peerTable.clearAndWipeAll();
        Bytes.wipe(keyCtrl, saltSrv);
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
        if (readerThread != null && readerThread != Thread.currentThread()) {
            try {
                readerThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Ponto de entrada de linha de comando (`scripts/run-client`).
     * Uso: {@code java securechat.client.Client [host] [porta] [caminho_server_crt]}
     */
    public static void main(String[] args) {
        try {
            String host = args.length >= 1 ? args[0] : "127.0.0.1";
            int port = args.length >= 2 ? Integer.parseInt(args[1]) : Constants.DEFAULT_PORT;
            Path certPath = args.length >= 3 ? Path.of(args[2]) : Path.of(Constants.DEFAULT_CERT_PATH);

            X509Certificate pinned = CertUtil.loadPinnedCertificate(certPath);
            try (Client client = new Client(pinned)) {
                Cli cli = new Cli(client);
                cli.startInteractive(host, port);
            }
        } catch (ProtocolException | IOException | IllegalArgumentException e) {
            SecureLog.error("Falha ao iniciar cliente", e.getMessage());
            System.exit(1);
        }
    }
}

