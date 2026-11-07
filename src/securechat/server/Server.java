package securechat.server;

import securechat.common.CertUtil;
import securechat.common.Constants;
import securechat.common.ProtocolException;
import securechat.common.SecureLog;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Servidor relay/rendezvous multi-cliente do SecureChat.
 *
 * <p>Utiliza um {@link ServerSocket} bloqueante combinado com virtual threads do Java 21
 * ({@link Executors#newVirtualThreadPerTaskExecutor()}), criando uma virtual thread leve
 * para cada conexão aceita ({@link ClientConnection}).</p>
 */
public final class Server implements AutoCloseable {

    private final CertUtil.ServerIdentity serverIdentity;
    private final SessionRegistry registry = new SessionRegistry();
    private final Semaphore clientSlots;
    private final int handshakeTimeoutMs;
    private final ServerSocket serverSocket;
    private final ExecutorService virtualExecutor = Executors.newVirtualThreadPerTaskExecutor();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread acceptThread;

    public Server(
            int port,
            CertUtil.ServerIdentity serverIdentity,
            int maxClients,
            int handshakeTimeoutMs) throws IOException {
        this.serverIdentity = Objects.requireNonNull(serverIdentity, "serverIdentity não pode ser nula");
        if (maxClients <= 0) {
            throw new IllegalArgumentException("maxClients deve ser > 0");
        }
        this.clientSlots = new Semaphore(maxClients);
        this.handshakeTimeoutMs = handshakeTimeoutMs;
        this.serverSocket = new ServerSocket(port);
    }

    public Server(int port, CertUtil.ServerIdentity serverIdentity) throws IOException {
        this(port, serverIdentity, Constants.MAX_CLIENTS, Constants.HANDSHAKE_TIMEOUT_MS);
    }

    /**
     * Inicia a virtual thread de aceitação de conexões em background.
     */
    public void start() {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        acceptThread = Thread.ofVirtual().name("server-accept").start(this::acceptLoop);
        SecureLog.info("Servidor iniciado na porta " + getPort());
    }

    /**
     * Retorna a porta TCP em que o servidor está escutando (útil quando iniciado com porta 0).
     */
    public int getPort() {
        return serverSocket.getLocalPort();
    }

    /**
     * Retorna a tabela de sessões ativas (para inspeção em testes automatizados).
     */
    public SessionRegistry registry() {
        return registry;
    }

    private void acceptLoop() {
        while (running.get() && !serverSocket.isClosed()) {
            try {
                Socket clientSocket = serverSocket.accept();
                virtualExecutor.submit(new ClientConnection(
                        clientSocket,
                        serverIdentity,
                        registry,
                        clientSlots,
                        handshakeTimeoutMs));
            } catch (SocketException e) {
                if (running.get()) {
                    SecureLog.warn("Erro de socket no accept: " + e.getMessage());
                }
                break;
            } catch (IOException e) {
                if (running.get()) {
                    SecureLog.warn("Falha ao aceitar conexão: " + e.getMessage());
                }
            } catch (RuntimeException e) {
                if (running.get()) {
                    SecureLog.error("Erro inesperado no loop de accept", e.getClass().getSimpleName());
                }
            }
        }
    }

    /**
     * Encerra o {@link ServerSocket}, fecha todas as sessões ativas e aguarda o executor
     * de virtual threads finalizar.
     */
    @Override
    public void close() {
        if (!running.compareAndSet(true, false)) {
            try {
                serverSocket.close();
            } catch (IOException ignored) {
            }
            return;
        }
        try {
            serverSocket.close();
        } catch (IOException ignored) {
        }
        registry.closeAll();
        virtualExecutor.close();
        if (acceptThread != null) {
            try {
                acceptThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        SecureLog.info("Servidor encerrado");
    }

    /**
     * Ponto de entrada de linha de comando (`scripts/run-server`).
     * Uso: {@code java securechat.server.Server [porta] [caminho_p12]}
     */
    public static void main(String[] args) {
        try {
            int port = Constants.DEFAULT_PORT;
            if (args.length >= 1) {
                port = Integer.parseInt(args[0]);
            }
            Path keystorePath = args.length >= 2
                    ? Path.of(args[1])
                    : Path.of(Constants.DEFAULT_KEYSTORE_PATH);

            CertUtil.ServerIdentity identity = CertUtil.loadServerIdentity(
                    keystorePath, CertUtil.resolveKeystorePassword());
            try (Server server = new Server(port, identity)) {
                server.start();
                Runtime.getRuntime().addShutdownHook(new Thread(server::close));
                // Mantém a thread principal viva enquanto o servidor estiver rodando
                if (server.acceptThread != null) {
                    server.acceptThread.join();
                }
            }
        } catch (ProtocolException | IOException | InterruptedException | IllegalArgumentException e) {
            SecureLog.error("Falha fatal no servidor", e.getMessage());
            System.exit(1);
        }
    }
}

