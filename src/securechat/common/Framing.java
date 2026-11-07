package securechat.common;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.Objects;

/**
 * Leitura e escrita de frames TCP com prefixo de tamanho de 4 bytes big-endian e
 * byte de tipo (Decisão D5).
 *
 * <pre>
 * Formato no fio:
 *   [len : 4 bytes big-endian] [type : 1 byte] [payload : (len - 1) bytes]
 * </pre>
 *
 * <p>Regra de ouro de segurança implementada aqui: o comprimento {@code len} lido da rede
 * é rigorosamente validado ({@code 1 <= len <= Constants.MAX_FRAME}) <b>antes</b> de
 * executar {@code new byte[len - 1]}, impedindo ataques de negação de serviço por
 * exaustão de memória ({@code OutOfMemoryError}) ou tamanho negativo ({@code NegativeArraySizeException}).</p>
 */
public final class Framing {

    /**
     * Representa um frame TCP desempacotado em seu byte de tipo e payload bruto.
     */
    public record Frame(byte type, byte[] payload) {
        public Frame {
            Objects.requireNonNull(payload, "payload não pode ser nulo");
        }
    }

    private Framing() {
        // Classe utilitária não instanciável.
    }

    /**
     * Envia um frame completo pelo stream de saída: escreve {@code len = 1 + payload.length}
     * em 4 bytes big-endian, seguido de {@code type} (1 B) e {@code payload}, e faz flush.
     *
     * @throws FramingException se o tamanho exceder {@link Constants#MAX_FRAME}.
     * @throws IOException se ocorrer erro de escrita no socket.
     */
    public static void writeFrame(DataOutputStream out, byte type, byte[] payload)
            throws FramingException, IOException {
        Objects.requireNonNull(out, "out não pode ser nulo");
        Objects.requireNonNull(payload, "payload não pode ser nulo");

        long totalLen = (long) Constants.MSG_TYPE_BYTES + payload.length;
        if (totalLen <= 0 || totalLen > Constants.MAX_FRAME) {
            throw new FramingException(
                    "Tentativa de enviar frame com tamanho fora do limite permitido: " + totalLen);
        }

        out.writeInt((int) totalLen);
        out.writeByte(type);
        if (payload.length > 0) {
            out.write(payload);
        }
        out.flush();
    }

    /**
     * Lê um frame completo do stream de entrada, validando os limites antes de alocar memória
     * e garantindo a leitura integral de todos os bytes declarados ({@code readFully}).
     *
     * @throws FramingException se a conexão fechar (EOF), o frame estiver truncado ou
     *         o tamanho declarado for inválido ({@code <= 0} ou {@code > MAX_FRAME}).
     * @throws IOException se ocorrer falha de I/O subjacente no socket.
     */
    public static Frame readFrame(DataInputStream in) throws FramingException, IOException {
        Objects.requireNonNull(in, "in não pode ser nulo");

        // Lê o 1º byte do tamanho separadamente para distinguir EOF limpo entre frames
        // de um truncamento no meio do cabeçalho de 4 bytes.
        int b0 = in.read();
        if (b0 < 0) {
            throw new FramingException(
                    "Fluxo encerrado pelo par remoto (EOF antes de novo frame)",
                    new EOFException(),
                    true);
        }

        byte[] restLen = new byte[3];
        try {
            in.readFully(restLen);
        } catch (EOFException e) {
            throw new FramingException("Frame truncado durante leitura do prefixo de 4 bytes", e, false);
        }

        int len = ((b0 & 0xFF) << 24)
                | ((restLen[0] & 0xFF) << 16)
                | ((restLen[1] & 0xFF) << 8)
                | (restLen[2] & 0xFF);

        if (len < Constants.MSG_TYPE_BYTES) {
            throw new FramingException("Tamanho de frame inválido (<= 0): " + len);
        }
        if (len > Constants.MAX_FRAME) {
            throw new FramingException(
                    "Tamanho de frame excede MAX_FRAME (" + Constants.MAX_FRAME + "): " + len);
        }

        byte type;
        byte[] payload;
        try {
            type = in.readByte();
            payload = new byte[len - Constants.MSG_TYPE_BYTES];
            if (payload.length > 0) {
                in.readFully(payload);
            }
        } catch (EOFException e) {
            throw new FramingException(
                    "Frame truncado: declarados " + len + " bytes, mas o stream terminou antes",
                    e,
                    false);
        }

        return new Frame(type, payload);
    }
}

