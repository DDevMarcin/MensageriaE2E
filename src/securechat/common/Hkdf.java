package securechat.common;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * Implementação manual do HKDF (HMAC-based Key Derivation Function) com HMAC-SHA256,
 * seguindo estritamente o RFC 5869.
 *
 * <p><b>Por que implementar manualmente?</b> O JDK 21 não possui API pública de HKDF
 * (introduzida apenas no JDK 25 via JEP 478), mas fornece {@code Mac.getInstance("HmacSHA256")}.</p>
 *
 * <p><b>Por que usar HKDF em vez de usar {@code Z_AB} direto como chave AES?</b>
 * O segredo bruto {@code Z_AB} produzido pelo X25519 não tem distribuição perfeitamente
 * uniforme em todos os bits e é o mesmo para os dois lados. O {@code HKDF-Extract}
 * concentra a entropia de {@code Z_AB} com um {@code salt} aleatório gerando a chave
 * pseudoaleatória {@code PRK}, e o {@code HKDF-Expand} deriva chaves independentes por
 * direção ({@code info="A2B"}, {@code info="B2A"}, {@code info="S2C"}).</p>
 */
public final class Hkdf {

    private static final String HMAC_ALG = "HmacSHA256";
    private static final int HASH_LEN = Constants.SHA256_BYTES; // 32 bytes
    private static final int MAX_OKM_LEN = 255 * HASH_LEN;

    private Hkdf() {
        // Classe utilitária não instanciável.
    }

    /**
     * Etapa 1 do RFC 5869: {@code HKDF-Extract(salt, IKM) -> PRK} (32 bytes).
     * Calcula {@code HMAC-SHA256(key = salt, data = ikm)}.
     *
     * @param salt bytes de salt (se nulo ou vazio, usa 32 bytes zero conforme RFC 5869 §2.2).
     * @param ikm  Input Keying Material (ex.: segredo compartilhado {@code Z} de 32 bytes).
     * @return {@code PRK} de 32 bytes.
     * @throws ProtocolException se {@code ikm} for nulo ou vazio.
     */
    public static byte[] extract(byte[] salt, byte[] ikm) throws ProtocolException {
        if (ikm == null || ikm.length == 0) {
            throw new ProtocolException("IKM do HKDF-Extract não pode ser nulo ou vazio");
        }
        byte[] effectiveSalt = (salt == null || salt.length == 0)
                ? new byte[HASH_LEN]
                : salt;
        return hmacSha256(effectiveSalt, ikm);
    }

    /**
     * Etapa 2 do RFC 5869: {@code HKDF-Expand(PRK, info, L) -> OKM} ({@code length} bytes).
     *
     * <pre>
     * N = ceil(L / HashLen)
     * T(0) = vazio
     * T(i) = HMAC-SHA256(PRK, T(i-1) || info || byte(i))   para i = 1..N
     * OKM  = primeiros L bytes de T(1) || T(2) || ... || T(N)
     * </pre>
     *
     * @param prk    Pseudorandom Key de pelo menos 32 bytes gerada por {@link #extract}.
     * @param info   bytes de contexto de aplicação (pode ser vazio, não nulo).
     * @param length tamanho desejado em bytes para o material de chave de saída ({@code 1 <= L <= 255*32}).
     * @return chave derivada com exatamente {@code length} bytes.
     * @throws ProtocolException se os parâmetros violarem os limites do RFC 5869.
     */
    public static byte[] expand(byte[] prk, byte[] info, int length) throws ProtocolException {
        if (prk == null || prk.length < HASH_LEN) {
            throw new ProtocolException("PRK do HKDF-Expand inválido (mínimo " + HASH_LEN + " bytes)");
        }
        if (length <= 0 || length > MAX_OKM_LEN) {
            throw new ProtocolException("Tamanho L do HKDF-Expand fora da faixa permitida: " + length);
        }
        byte[] context = (info == null) ? new byte[0] : info;

        int n = (length + HASH_LEN - 1) / HASH_LEN;
        byte[] okm = new byte[length];
        byte[] tPrev = new byte[0];
        int offset = 0;

        try {
            Mac mac = Mac.getInstance(HMAC_ALG);
            mac.init(new SecretKeySpec(prk, HMAC_ALG));

            for (int i = 1; i <= n; i++) {
                mac.reset();
                mac.update(tPrev);
                mac.update(context);
                mac.update((byte) i);
                byte[] tCurr = mac.doFinal();

                int toCopy = Math.min(HASH_LEN, length - offset);
                System.arraycopy(tCurr, 0, okm, offset, toCopy);
                offset += toCopy;

                Bytes.wipe(tPrev);
                tPrev = tCurr;
            }
            return okm;
        } catch (GeneralSecurityException e) {
            throw new ProtocolException("Falha ao executar HKDF-Expand com HmacSHA256", e);
        } finally {
            Bytes.wipe(tPrev);
        }
    }

    /**
     * Sobrecarga conveniente de {@link #expand(byte[], byte[], int)} que converte a string
     * {@code infoAscii} (ex.: {@code "A2B"}, {@code "B2A"}, {@code "S2C"}) usando US-ASCII.
     */
    public static byte[] expand(byte[] prk, String infoAscii, int length) throws ProtocolException {
        if (infoAscii == null) {
            throw new ProtocolException("infoAscii do HKDF-Expand não pode ser nulo");
        }
        return expand(prk, infoAscii.getBytes(StandardCharsets.US_ASCII), length);
    }

    /**
     * Executa Extract + Expand em uma única chamada e limpa o {@code PRK} intermediário da RAM.
     */
    public static byte[] deriveKey(byte[] salt, byte[] ikm, String infoAscii, int length)
            throws ProtocolException {
        byte[] prk = extract(salt, ikm);
        try {
            return expand(prk, infoAscii, length);
        } finally {
            Bytes.wipe(prk);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) throws ProtocolException {
        try {
            Mac mac = Mac.getInstance(HMAC_ALG);
            mac.init(new SecretKeySpec(key, HMAC_ALG));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new ProtocolException("Falha ao calcular HMAC-SHA256 no HKDF", e);
        }
    }
}

