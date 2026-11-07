package securechat.common;

/**
 * Exceção lançada quando a camada de framing TCP detecta um tamanho de frame inválido
 * (menor ou igual a zero, ou acima de {@link Constants#MAX_FRAME}), truncamento de bytes
 * (EOF inesperado no meio do frame) ou encerramento do fluxo.
 *
 * <p>Ao capturar {@code FramingException}, o receptor deve encerrar o socket de forma
 * segura, pois o fluxo TCP perdeu o sincronismo de fronteira de frames.</p>
 */
public final class FramingException extends ProtocolException {

    private static final long serialVersionUID = 1L;

    private final boolean cleanEof;

    public FramingException(String message) {
        super(message);
        this.cleanEof = false;
    }

    public FramingException(String message, Throwable cause) {
        this(message, cause, false);
    }

    public FramingException(String message, Throwable cause, boolean cleanEof) {
        super(message, cause);
        this.cleanEof = cleanEof;
    }

    /**
     * Indica se o EOF ocorreu exatamente antes do primeiro byte de um novo frame
     * (fechamento normal do socket pelo par remoto) ou se houve truncamento no meio de um frame.
     */
    public boolean isCleanEof() {
        return cleanEof;
    }
}

