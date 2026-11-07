package securechat.common;

import java.io.PrintStream;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/**
 * Logger seguro centralizado do sistema ({@code SecureLog}).
 *
 * <p>Política de segurança implementada por construção (em tempo de compilação):
 * esta classe expõe <b>apenas métodos fortemente tipados</b> que aceitam identificadores
 * públicos ({@link ClientId}), contagens de bytes ({@code int}), números de sequência
 * ({@code long}), fingerprints SHA-256 truncados e descrições textuais de eventos.
 * Não existe nenhum método que receba {@code byte[]} ou chaves criptográficas, tornando
 * acidentalmente impossível logar chaves privadas, {@code Z_AB}, {@code salt}, nonces ou
 * conteúdo de mensagens.</p>
 */
public final class SecureLog {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    private static final PrintStream OUT = System.out;
    private static volatile boolean silent = false;

    private SecureLog() {
        // Classe utilitária não instanciável.
    }

    /**
     * Permite silenciar a saída de log durante testes automatizados de erro para manter
     * o console do {@code TestRunner} limpo.
     */
    public static void setSilent(boolean silentMode) {
        silent = silentMode;
    }

    /** Registra que um cliente concluiu o handshake e foi conectado. */
    public static void connected(ClientId clientId) {
        log("INFO", "Cliente conectado: id=" + safeId(clientId));
    }

    /** Registra que um cliente concluiu o handshake, incluindo o fingerprint da sua chave pública. */
    public static void connected(ClientId clientId, String pkFingerprint) {
        log("INFO", "Cliente conectado: id=" + safeId(clientId) + " pk_fp=" + safeText(pkFingerprint));
    }

    /** Registra a desconexão de um cliente. */
    public static void disconnected(ClientId clientId) {
        log("INFO", "Cliente desconectado: id=" + safeId(clientId));
    }

    /** Registra a desconexão de um cliente com o motivo associado. */
    public static void disconnected(ClientId clientId, String reason) {
        log("INFO", "Cliente desconectado: id=" + safeId(clientId) + " motivo=\"" + safeText(reason) + "\"");
    }

    /**
     * Registra a rejeição de um frame ou tentativa de handshake (ex.: tag mismatch, replay,
     * framing inválido, assinatura inválida), informando o tamanho em bytes envolvido.
     */
    public static void rejected(ClientId clientId, String reason, int byteLength) {
        log("WARN", "Rejeitado: id=" + safeId(clientId)
                + " motivo=\"" + safeText(reason) + "\" tam=" + byteLength + "B");
    }

    /** Registra a rejeição de uma operação quando o tamanho de frame não se aplica. */
    public static void rejected(ClientId clientId, String reason) {
        log("WARN", "Rejeitado: id=" + safeId(clientId) + " motivo=\"" + safeText(reason) + "\"");
    }

    /** Registra o encaminhamento cego (relay) de um frame E2E pelo servidor. */
    public static void routed(ClientId senderId, ClientId recipientId, int frameBytes) {
        log("INFO", "Relay E2E: de=" + safeId(senderId)
                + " para=" + safeId(recipientId) + " tam=" + frameBytes + "B");
    }

    /** Registra uma mensagem informativa de ciclo de vida do sistema. */
    public static void info(String message) {
        log("INFO", safeText(message));
    }

    /** Registra um alerta operacional sem expor dados sensíveis. */
    public static void warn(String message) {
        log("WARN", safeText(message));
    }

    /** Registra um erro de operação ou de protocolo com contexto e razão. */
    public static void error(String context, String reason) {
        log("ERROR", safeText(context) + ": " + safeText(reason));
    }

    private static String safeId(ClientId id) {
        return id == null ? "desconhecido" : id.shortHex();
    }

    private static String safeText(String s) {
        return s == null ? "" : s;
    }

    private static synchronized void log(String level, String body) {
        if (silent) {
            return;
        }
        String ts = LocalTime.now().format(TIME_FMT);
        OUT.println("[" + ts + "] [" + level + "] " + body);
    }
}

