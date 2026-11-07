package securechat.common;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Utilitários de manipulação de arrays de bytes, codificação big-endian, comparação em
 * tempo constante, limpeza de segredos em memória e cálculo de fingerprint SHA-256.
 */
public final class Bytes {

    private static final HexFormat HEX = HexFormat.of();
    private static final HexFormat HEX_COLON = HexFormat.ofDelimiter(":");
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private Bytes() {
        // Classe utilitária não instanciável.
    }

    /**
     * Gera um array de {@code length} bytes criptograficamente aleatórios usando uma instância
     * compartilhada e thread-safe de {@link SecureRandom}.
     */
    public static byte[] randomBytes(int length) {
        if (length < 0) {
            throw new IllegalArgumentException("Tamanho não pode ser negativo: " + length);
        }
        byte[] out = new byte[length];
        SECURE_RANDOM.nextBytes(out);
        return out;
    }

    /**
     * Concatena múltiplos arrays de bytes na ordem fornecida.
     */
    public static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) {
            if (p != null) {
                total = Math.addExact(total, p.length);
            }
        }
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] p : parts) {
            if (p != null && p.length > 0) {
                System.arraycopy(p, 0, result, pos, p.length);
                pos += p.length;
            }
        }
        return result;
    }

    /**
     * Codifica um inteiro de 32 bits em 4 bytes big-endian.
     */
    public static byte[] intToBytes(int value) {
        return ByteBuffer.allocate(Integer.BYTES).putInt(value).array();
    }

    /**
     * Codifica um inteiro longo de 64 bits em 8 bytes big-endian.
     */
    public static byte[] longToBytes(long value) {
        return ByteBuffer.allocate(Long.BYTES).putLong(value).array();
    }

    /**
     * Lê um inteiro longo de 64 bits big-endian a partir de {@code offset}.
     *
     * @throws ProtocolException se não houver 8 bytes disponíveis a partir de {@code offset}.
     */
    public static long bytesToLong(byte[] data, int offset) throws ProtocolException {
        if (data == null || offset < 0 || data.length - offset < Long.BYTES) {
            throw new ProtocolException("Bytes insuficientes para ler long (64 bits)");
        }
        return ByteBuffer.wrap(data, offset, Long.BYTES).getLong();
    }

    /**
     * Compara dois arrays de bytes em tempo constante via {@link MessageDigest#isEqual(byte[], byte[])},
     * prevenindo ataques de temporização (timing attacks) ao verificar certificados ou tags.
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return a == b;
        }
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Sobrescreve com zeros todos os arrays fornecidos para remover material sensível
     * (como segredos compartilhados {@code Z_AB} e chaves de sessão encerradas) da RAM.
     */
    public static void wipe(byte[]... secrets) {
        if (secrets == null) {
            return;
        }
        for (byte[] s : secrets) {
            if (s != null) {
                Arrays.fill(s, (byte) 0);
            }
        }
    }

    /**
     * Calcula o resumo criptográfico SHA-256 (32 bytes) sobre a concatenação das partes.
     */
    public static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) {
                if (p != null) {
                    md.update(p);
                }
            }
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponível no JDK", e);
        }
    }

    /**
     * Calcula o fingerprint visual de uma chave pública: primeiros 8 bytes do SHA-256
     * formatados em hexadecimal separado por dois-pontos (ex.: {@code "1a:2b:3c:4d:5e:6f:70:81"}).
     *
     * <p>Como o SHA-256 é unidirecional, o fingerprint pode ser exibido no CLI e em logs
     * para conferência fora de banda sem expor segredos.</p>
     */
    public static String fingerprint(byte[] publicKeyBytes) {
        if (publicKeyBytes == null || publicKeyBytes.length == 0) {
            return "invalid";
        }
        byte[] digest = sha256(publicKeyBytes);
        return HEX_COLON.formatHex(digest, 0, Constants.FINGERPRINT_BYTES);
    }

    /**
     * Formata até {@code maxBytes} iniciais de um array em hexadecimal minúsculo curto.
     */
    public static String shortHex(byte[] data, int maxBytes) {
        if (data == null) {
            return "null";
        }
        int len = Math.min(data.length, Math.max(0, maxBytes));
        return HEX.formatHex(data, 0, len);
    }
}

