package securechat.tools;

import securechat.common.Bytes;
import securechat.common.Constants;
import securechat.common.Framing;
import securechat.common.FramingException;
import securechat.common.Messages;
import securechat.common.ProtocolException;
import securechat.common.SecureLog;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Proxy TCP intermediário (Man-in-the-Middle de rede) entre um Cliente e o Servidor
 * para demonstração prática e testes automatizados das garantias de segurança (T09).
 *
 * <p>Modos suportados ({@link Mode}):</p>
 * <ul>
 *   <li>{@link Mode#SNIFF}: encaminha todos os frames intactos e registra o tamanho e uma
 *       amostra hexadecimal do ciphertext E2E capturado na rede, comprovando que um
 *       observador na rede vê apenas bytes indecifráveis (Confidencialidade).</li>
 *   <li>{@link Mode#BITFLIP}: no primeiro (ou em todo) frame {@code 0x04 E2E} enviado pelo
 *       cliente, inverte 1 bit ({@code ^= 0x01}) no primeiro byte do ciphertext (após os
 *       52 bytes do cabeçalho E2E), comprovando que o destinatário rejeita a mensagem por
 *       falha na tag GCM de 16 bytes (Integridade).</li>
 *   <li>{@link Mode#REPLAY}: encaminha o frame {@code 0x04 E2E} normalmente e, em seguida,
 *       reenvia uma cópia idêntica do mesmo frame E2E para o servidor, comprovando que o
 *       destinatário descarta a segunda cópia porque {@code seq_no <= seqRecv} (Anti-replay).</li>
 *   <li>{@link Mode#BADFRAME}: ao interceptar um frame {@code 0x04 E2E}, substitui o envio
 *       por um prefixo de frame TCP inválido ({@code len = -1} ou {@code len > MAX_FRAME}),
 *       comprovando que o servidor detecta o erro de framing, fecha apenas a conexão infratora
 *       e continua operando normalmente para os demais clientes.</li>
 * </ul>
 */
public final class TamperProxy implements AutoCloseable {

    /** Modos de operação do proxy de inspeção/adulteração. */
    public enum Mode {
        SNIFF,
        BITFLIP,
        REPLAY,
        BADFRAME;

        public static Mode fromString(String s) {
            return Mode.valueOf(s.trim().toUpperCase(Locale.ROOT));
        }
    }

    private final Mode mode;
    private final String serverHost;
    private final int serverPort;
    private final ServerSocket listenSocket;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final List<byte[]> capturedE2ePayloads = new CopyOnWriteArrayList<>();
    private volatile boolean tamperNextE2eOnly = false;
    private final AtomicBoolean tamperedOnce = new AtomicBoolean(false);
    private Thread acceptThread;

    public TamperProxy(Mode mode, int listenPort, String serverHost, int serverPort)
            throws IOException {
        this.mode = Objects.requireNonNull(mode, "mode não pode ser nulo");
        this.serverHost = Objects.requireNonNull(serverHost, "serverHost não pode ser nulo");
        this.serverPort = serverPort;
        this.listenSocket = new ServerSocket(listenPort);
    }

    /**
     * Se configurado como {@code true}, aplica a adulteração ({@code BITFLIP}, {@code REPLAY}
     * ou {@code BADFRAME}) apenas no primeiro frame E2E e encaminha os seguintes normalmente.
     */
    public void setTamperFirstE2eOnly(boolean onlyFirst) {
        this.tamperNextE2eOnly = onlyFirst;
    }

    /** Inicia o loop de aceitação do proxy em uma virtual thread. */
    public void start() {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        acceptThread = Thread.ofVirtual()
                .name("tamper-proxy-accept")
                .start(this::acceptLoop);
        SecureLog.info("TamperProxy iniciado em modo " + mode
                + " na porta " + getListenPort() + " -> " + serverHost + ":" + serverPort);
    }

    /** Porta local onde o cliente deve se conectar ao proxy. */
    public int getListenPort() {
        return listenSocket.getLocalPort();
    }

    /** Lista de payloads brutos de frames E2E capturados pelo proxy (para inspeção em testes). */
    public List<byte[]> capturedE2ePayloads() {
        return capturedE2ePayloads;
    }

    private void acceptLoop() {
        while (running.get() && !listenSocket.isClosed()) {
            try {
                Socket clientSide = listenSocket.accept();
                executor.submit(() -> handleConnection(clientSide));
            } catch (SocketException e) {
                break;
            } catch (IOException e) {
                if (running.get()) {
                    SecureLog.warn("TamperProxy falha no accept: " + e.getMessage());
                }
            }
        }
    }

    private void handleConnection(Socket clientSide) {
        try (clientSide;
             Socket serverSide = new Socket(serverHost, serverPort);
             DataInputStream cIn = new DataInputStream(clientSide.getInputStream());
             DataOutputStream cOut = new DataOutputStream(clientSide.getOutputStream());
             DataInputStream sIn = new DataInputStream(serverSide.getInputStream());
             DataOutputStream sOut = new DataOutputStream(serverSide.getOutputStream())) {

            // Virtual thread para o sentido Servidor -> Cliente (sempre repassa intacto)
            Thread s2c = Thread.ofVirtual().start(() -> pipeServerToClient(sIn, cOut, clientSide));

            // Sentido Cliente -> Servidor (aplica o modo configurado sobre frames E2E)
            pipeClientToServer(cIn, sOut, serverSide);

            s2c.join(2000);
        } catch (IOException | InterruptedException ignored) {
        } catch (RuntimeException e) {
            SecureLog.error("Erro inesperado no TamperProxy", e.getClass().getSimpleName());
        }
    }

    private void pipeServerToClient(
            DataInputStream sIn, DataOutputStream cOut, Socket clientSide) {
        try {
            while (running.get() && !clientSide.isClosed()) {
                Framing.Frame frame = Framing.readFrame(sIn);
                Framing.writeFrame(cOut, frame.type(), frame.payload());
            }
        } catch (FramingException | IOException ignored) {
            try {
                clientSide.close();
            } catch (IOException ignoredClose) {
            }
        }
    }

    private void pipeClientToServer(
            DataInputStream cIn, DataOutputStream sOut, Socket serverSide) throws IOException {
        try {
            while (running.get() && !serverSide.isClosed()) {
                Framing.Frame frame = Framing.readFrame(cIn);
                if (frame.type() != Constants.TYPE_E2E) {
                    Framing.writeFrame(sOut, frame.type(), frame.payload());
                    continue;
                }

                byte[] payload = frame.payload();
                capturedE2ePayloads.add(payload.clone());
                logSniffedE2e(payload);

                boolean shouldTamper = !tamperNextE2eOnly || tamperedOnce.compareAndSet(false, true);
                if (!shouldTamper) {
                    Framing.writeFrame(sOut, Constants.TYPE_E2E, payload);
                    continue;
                }

                switch (mode) {
                    case SNIFF -> Framing.writeFrame(sOut, Constants.TYPE_E2E, payload);

                    case BITFLIP -> {
                        byte[] corrupted = payload.clone();
                        // Inverte 1 bit no primeiro byte do ciphertext (logo após os 52B do cabeçalho E2E)
                        int targetIdx = Constants.E2E_HEADER_BYTES;
                        if (corrupted.length > targetIdx) {
                            corrupted[targetIdx] ^= 0x01;
                        }
                        SecureLog.info("[TamperProxy BITFLIP] 1 bit invertido no byte "
                                + targetIdx + " do payload E2E");
                        Framing.writeFrame(sOut, Constants.TYPE_E2E, corrupted);
                    }

                    case REPLAY -> {
                        Framing.writeFrame(sOut, Constants.TYPE_E2E, payload);
                        SecureLog.info("[TamperProxy REPLAY] Reenviando cópia idêntica do frame E2E ("
                                + payload.length + "B)");
                        Framing.writeFrame(sOut, Constants.TYPE_E2E, payload.clone());
                    }

                    case BADFRAME -> {
                        SecureLog.info("[TamperProxy BADFRAME] Injetando prefixo de tamanho inválido (-42) no servidor");
                        sOut.writeInt(-42);
                        sOut.flush();
                        return;
                    }
                }
            }
        } catch (FramingException ignored) {
        } finally {
            try {
                serverSide.close();
            } catch (IOException ignored) {
            }
        }
    }

    private void logSniffedE2e(byte[] payload) {
        try {
            Messages.E2eFrame parsed = Messages.unpackE2eFrame(payload);
            String ctFp = Bytes.fingerprint(parsed.ciphertextWithTag());
            SecureLog.info("[TamperProxy SNIFF] Frame E2E de=" + parsed.senderId()
                    + " para=" + parsed.recipientId()
                    + " seq=" + parsed.seqNo()
                    + " ct_len=" + parsed.ciphertextWithTag().length + "B"
                    + " ct_sha256_fp=" + ctFp);
        } catch (ProtocolException e) {
            SecureLog.info("[TamperProxy SNIFF] Frame E2E bruto tam=" + payload.length + "B");
        }
    }

    @Override
    public void close() {
        running.set(false);
        try {
            listenSocket.close();
        } catch (IOException ignored) {
        }
        executor.close();
        if (acceptThread != null) {
            try {
                acceptThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Uso em linha de comando para demonstração ao vivo:
     * {@code java -cp out securechat.tools.TamperProxy <sniff|bitflip|replay|badframe> [listenPort] [serverHost] [serverPort]}
     * ou com flags {@code --mode <m> --listen <p> --target <host:port>}.
     */
    public static void main(String[] args) {
        if (args.length < 1) {
            SecureLog.info("Uso: TamperProxy <sniff|bitflip|replay|badframe> [listenPort=8444] [serverHost=127.0.0.1] [serverPort=8443]");
            System.exit(1);
        }
        try {
            Mode mode = Mode.SNIFF;
            int listenPort = 8444;
            String serverHost = "127.0.0.1";
            int serverPort = Constants.DEFAULT_PORT;
            boolean once = false;

            if (args[0].startsWith("--")) {
                for (int i = 0; i < args.length; i++) {
                    switch (args[i]) {
                        case "--mode" -> mode = Mode.fromString(args[++i]);
                        case "--listen" -> listenPort = Integer.parseInt(args[++i]);
                        case "--target" -> {
                            String[] parts = args[++i].split(":");
                            serverHost = parts[0];
                            if (parts.length > 1) {
                                serverPort = Integer.parseInt(parts[1]);
                            }
                        }
                        case "--once" -> once = true;
                        default -> throw new IllegalArgumentException("Flag desconhecida: " + args[i]);
                    }
                }
            } else {
                mode = Mode.fromString(args[0]);
                if (args.length >= 2) {
                    listenPort = Integer.parseInt(args[1]);
                }
                if (args.length >= 3) {
                    serverHost = args[2];
                }
                if (args.length >= 4) {
                    serverPort = Integer.parseInt(args[3]);
                }
                if (args.length >= 5 && "--once".equalsIgnoreCase(args[4])) {
                    once = true;
                }
            }

            try (TamperProxy proxy = new TamperProxy(mode, listenPort, serverHost, serverPort)) {
                proxy.setTamperFirstE2eOnly(once);
                proxy.start();
                Runtime.getRuntime().addShutdownHook(new Thread(proxy::close));
                if (proxy.acceptThread != null) {
                    proxy.acceptThread.join();
                }
            }
        } catch (IOException | InterruptedException | IllegalArgumentException e) {
            SecureLog.error("TamperProxy encerrado com erro", e.getMessage());
            System.exit(1);
        }
    }
}

