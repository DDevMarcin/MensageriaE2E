package securechat.common;

/**
 * Exceção verificada (checked) que representa qualquer violação das regras do protocolo
 * criptográfico ou de formato de mensagens (handshake inválido, assinatura incorreta,
 * tag GCM inválida, replay detectado, campos inconsistentes).
 *
 * <p>Escolhida como exceção verificada para obrigar que todas as camadas de rede e
 * criptografia tratem explicitamente falhas de segurança, registrando o motivo via
 * {@link SecureLog} e descartando o frame ou encerrando a conexão.</p>
 */
public class ProtocolException extends Exception {

    private static final long serialVersionUID = 1L;

    public ProtocolException(String message) {
        super(message);
    }

    public ProtocolException(String message, Throwable cause) {
        super(message, cause);
    }
}

