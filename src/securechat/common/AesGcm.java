package securechat.common;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * Cifra autenticada com dados associados (AEAD) usando {@code AES-128-GCM}
 * ({@code AES/GCM/NoPadding}, chave de 16 bytes, nonce de 12 bytes e tag de 128 bits).
 *
 * <p><b>Regras críticas implementadas nesta classe:</b></p>
 * <ul>
 *   <li>Uma instância <b>nova</b> de {@link Cipher} é criada a cada operação de cifragem
 *       ou decifragem (o provider JCA proíbe reutilizar a mesma instância com mesmo par
 *       chave/IV e {@code Cipher} não é thread-safe).</li>
 *   <li>Os dados autenticados adicionais ({@code AAD}) são injetados via
 *       {@link Cipher#updateAAD(byte[])} antes de {@link Cipher#doFinal(byte[])}.</li>
 *   <li>Se qualquer bit do ciphertext, do AAD, do nonce ou da tag de 16 bytes for alterado,
 *       o JCA lança {@link AEADBadTagException} sem devolver texto parcial; esta classe
 *       converte a falha em {@link ProtocolException}.</li>
 * </ul>
 */
public final class AesGcm {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String KEY_ALG = "AES";

    private AesGcm() {
        // Classe utilitária não instanciável.
    }

    /**
     * Constrói o nonce de 12 bytes para frames E2E: {@code IV_base (4B) || seq_no (8B big-endian)}.
     *
     * @throws ProtocolException se {@code ivBase} não tiver 4 bytes ou {@code seqNo < 0}.
     */
    public static byte[] buildNonce(byte[] ivBase, long seqNo) throws ProtocolException {
        if (ivBase == null || ivBase.length != Constants.IV_BASE_BYTES) {
            throw new ProtocolException("IV_base deve ter exatamente 4 bytes");
        }
        if (seqNo < 0) {
            throw new ProtocolException("seq_no não pode ser negativo: " + seqNo);
        }
        return ByteBuffer.allocate(Constants.NONCE_BYTES)
                .put(ivBase)
                .putLong(seqNo)
                .array();
    }

    /**
     * Constrói o nonce de 12 bytes para o canal de controle Servidor -> Cliente:
     * {@code direction (0x00000001, 4B big-endian) || seq_no (8B big-endian)}.
     *
     * @throws ProtocolException se {@code seqNo < 0}.
     */
    public static byte[] buildControlNonce(long seqNo) throws ProtocolException {
        if (seqNo < 0) {
            throw new ProtocolException("seq_no de controle não pode ser negativo: " + seqNo);
        }
        return ByteBuffer.allocate(Constants.NONCE_BYTES)
                .putInt(Constants.CTRL_DIRECTION_S2C)
                .putLong(seqNo)
                .array();
    }

    /**
     * Cifra {@code plaintext} com AES-128-GCM autenticado por {@code aad}, retornando
     * {@code ciphertext || tag (16 bytes)}.
     */
    public static byte[] encrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
            throws ProtocolException {
        validateKeyAndNonce(key, nonce);
        if (plaintext == null) {
            throw new ProtocolException("Plaintext não pode ser nulo");
        }

        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec keySpec = new SecretKeySpec(key, KEY_ALG);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(Constants.GCM_TAG_BITS, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new ProtocolException("Erro ao cifrar com AES-128-GCM", e);
        }
    }

    /**
     * Verifica a tag de autenticação de 16 bytes e decifra {@code ciphertextWithTag} com
     * AES-128-GCM e {@code aad}.
     *
     * @throws ProtocolException se a tag GCM falhar ({@link AEADBadTagException}) ou se
     *         o tamanho do bloco cifrado for menor que os 16 bytes da tag.
     */
    public static byte[] decrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertextWithTag)
            throws ProtocolException {
        validateKeyAndNonce(key, nonce);
        if (ciphertextWithTag == null || ciphertextWithTag.length < Constants.GCM_TAG_BYTES) {
            throw new ProtocolException("Ciphertext curto demais para conter a tag GCM de 16 bytes");
        }

        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec keySpec = new SecretKeySpec(key, KEY_ALG);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(Constants.GCM_TAG_BITS, nonce);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertextWithTag);
        } catch (AEADBadTagException e) {
            throw new ProtocolException("tag mismatch: falha de integridade/autenticidade no AES-GCM", e);
        } catch (GeneralSecurityException e) {
            throw new ProtocolException("Erro ao decifrar com AES-128-GCM", e);
        }
    }

    private static void validateKeyAndNonce(byte[] key, byte[] nonce) throws ProtocolException {
        if (key == null || key.length != Constants.AES_KEY_BYTES) {
            int len = key == null ? -1 : key.length;
            throw new ProtocolException("Chave AES-128 deve ter 16 bytes (recebido: " + len + ")");
        }
        if (nonce == null || nonce.length != Constants.NONCE_BYTES) {
            int len = nonce == null ? -1 : nonce.length;
            throw new ProtocolException("Nonce AES-GCM deve ter 12 bytes (recebido: " + len + ")");
        }
    }
}

