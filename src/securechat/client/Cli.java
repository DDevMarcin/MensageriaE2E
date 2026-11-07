package securechat.client;

import securechat.common.Bytes;
import securechat.common.ProtocolException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;

/**
 * Interface de linha de comando (CLI) do cliente para interação humana no terminal.
 *
 * <p>Comandos suportados (T08):</p>
 * <ul>
 *   <li>{@code /peers} — lista todos os peers conectados com seu ID curto, ID completo e
 *       fingerprint SHA-256 da chave pública X25519 (para verificação fora de banda).</li>
 *   <li>{@code /msg <id|prefixo> <texto>} — cifra e envia uma mensagem E2E (até 4096 bytes)
 *       para o peer indicado.</li>
 *   <li>{@code /quit} — fecha a sessão e encerra o cliente com limpeza das chaves em memória.</li>
 * </ul>
 */
public final class Cli {

    private final Client client;
    private final InputStream inStream;
    private final PrintStream outStream;

    public Cli(Client client, InputStream inStream, PrintStream outStream) {
        this.client = Objects.requireNonNull(client, "client não pode ser nulo");
        this.inStream = Objects.requireNonNull(inStream, "inStream não pode ser nulo");
        this.outStream = Objects.requireNonNull(outStream, "outStream não pode ser nulo");
    }

    /**
     * Cria um CLI conectado à entrada e saída padrão do terminal ({@code System.in} e {@code System.out}).
     */
    public Cli(Client client) {
        this(client, System.in, System.out);
    }

    /**
     * Registra os listeners de exibição para mensagens E2E, erros de controle e entrada/saída
     * de peers no stream de saída do CLI.
     */
    public void attachListeners() {
        client.setMessageListener((senderId, text) ->
                outStream.println("[MSG de " + senderId.shortHex() + "]: " + text));
        client.setErrorListener(err ->
                outStream.println("[ERRO DO SERVIDOR (cod=" + err.errorCode() + ")]: " + err.message()));
        client.setPeerJoinedListener(peerId ->
                outStream.println("[EVENTO] Peer entrou: " + peerId.shortHex() + " (" + peerId.fullHex() + ")"));
        client.setPeerLeftListener(peerId ->
                outStream.println("[EVENTO] Peer saiu: " + peerId.shortHex()));
    }

    /**
     * Conecta o cliente ao servidor, registra os callbacks de exibição e inicia o loop de
     * leitura de comandos do terminal.
     */
    public void startInteractive(String host, int port) throws ProtocolException, IOException {
        attachListeners();

        client.connect(host, port);
        try {
            client.awaitInitialSync(5000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        outStream.println("=== SecureChat E2E conectado ===");
        outStream.println("Meu client_id : " + client.selfId().shortHex()
                + " (completo: " + client.selfId().fullHex() + ")");
        outStream.println("Meu pk_fp     : " + Bytes.fingerprint(client.pkClient()));
        outStream.println("Comandos      : /peers | /msg <id|prefixo> <texto> | /quit");

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(inStream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!handleCommandLine(line)) {
                    break;
                }
            }
        }
    }

    /**
     * Processa uma linha digitada pelo usuário no CLI.
     *
     * @return {@code true} para continuar lendo comandos; {@code false} se o usuário digitou {@code /quit}.
     */
    public boolean handleCommandLine(String rawLine) {
        if (rawLine == null) {
            return false;
        }
        String line = rawLine.trim();
        if (line.isEmpty()) {
            return true;
        }

        if (line.equals("/quit") || line.equals("/exit")) {
            outStream.println("Encerrando conexão...");
            return false;
        }

        if (line.equals("/peers")) {
            printPeers();
            return true;
        }

        if (line.startsWith("/msg ")) {
            String rest = line.substring(5).trim();
            int spaceIdx = rest.indexOf(' ');
            if (spaceIdx <= 0 || spaceIdx == rest.length() - 1) {
                outStream.println("Uso: /msg <id|prefixo> <texto>");
                return true;
            }
            String targetToken = rest.substring(0, spaceIdx).trim();
            String messageText = rest.substring(spaceIdx + 1);
            try {
                PeerState target = client.peerTable().resolveByPrefix(targetToken);
                client.sendMessage(target.peerId(), messageText);
                outStream.println("[Enviado para " + target.peerId().shortHex() + "]");
            } catch (ProtocolException | IOException e) {
                outStream.println("[Falha ao enviar]: " + e.getMessage());
            }
            return true;
        }

        outStream.println("Comando desconhecido. Use: /peers | /msg <id|prefixo> <texto> | /quit");
        return true;
    }

    private void printPeers() {
        List<PeerState> peers = client.peerTable().snapshotAll();
        if (peers.isEmpty()) {
            outStream.println("Nenhum outro peer conectado no momento.");
            return;
        }
        outStream.println("Peers conectados (" + peers.size() + "):");
        for (PeerState p : peers) {
            outStream.println("  - " + p.peerId().shortHex()
                    + " | full=" + p.peerId().fullHex()
                    + " | pk_fp=" + Bytes.fingerprint(p.publicKey())
                    + " | seqSend=" + p.seqSend()
                    + " | seqRecv=" + p.seqRecv());
        }
    }
}

