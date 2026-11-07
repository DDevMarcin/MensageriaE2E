package securechat.common;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

/**
 * Utilitário para geração de pares de chaves efêmeras X25519 (Curve25519, RFC 7748),
 * conversão entre o formato interno do JCA ({@link XECPublicKey}) e os 32 bytes raw
 * little-endian exigidos pelo protocolo, e cálculo do acordo de chaves ECDH.
 *
 * <p><b>Por que a conversão manual little-endian é necessária?</b> O JDK representa a
 * coordenada {@code u} da chave pública X25519 como um {@link BigInteger} (cujo método
 * {@code toByteArray()} usa big-endian em complemento de dois, podendo ter 33 bytes por
 * causa do byte de sinal ou menos de 32 bytes se houver zeros à esquerda). Já o RFC 7748
 * e o nosso protocolo exigem exatamente 32 bytes em ordem little-endian.</p>
 */
public final class X25519Util {

    private static final String ALGORITHM = "X25519";
    private static final byte[] ALL_ZERO_SECRET = new byte[Constants.X25519_SECRET_BYTES];

    private X25519Util() {
        // Classe utilitária não instanciável.
    }

    /**
     * Gera um novo par de chaves efêmero X25519 ({@code sk}, {@code pk}).
     */
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
            return kpg.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Falha ao gerar par de chaves X25519 no JDK 21", e);
        }
    }

    /**
     * Exporta uma chave pública X25519 do JCA para exatamente 32 bytes raw little-endian (RFC 7748).
     *
     * @throws ProtocolException se a chave não for uma {@link XECPublicKey} válida.
     */
    public static byte[] toRawPublicKey(PublicKey publicKey) throws ProtocolException {
        if (!(publicKey instanceof XECPublicKey xecPub)) {
            throw new ProtocolException("Chave pública não é uma instância de XECPublicKey");
        }
        BigInteger u = xecPub.getU();
        if (u == null || u.signum() < 0) {
            throw new ProtocolException("Coordenada u da chave pública X25519 inválida");
        }

        // toByteArray() retorna representação big-endian em complemento de dois.
        // Copiamos os bytes menos significativos invertendo a ordem para little-endian.
        byte[] be = u.toByteArray();
        byte[] rawLe = new byte[Constants.X25519_KEY_BYTES];
        for (int i = 0; i < Constants.X25519_KEY_BYTES; i++) {
            int beIndex = be.length - 1 - i;
            if (beIndex >= 0) {
                rawLe[i] = be[beIndex];
            }
        }
        // Garante que o bit 255 (MSB do último byte little-endian) esteja zerado conforme RFC 7748 §5
        rawLe[Constants.X25519_KEY_BYTES - 1] &= 0x7F;
        return rawLe;
    }

    /**
     * Importa 32 bytes raw little-endian (RFC 7748) para um objeto {@link PublicKey} X25519 do JCA.
     *
     * <p>Conforme o RFC 7748 §5, o bit mais significativo do último byte (bit 255) é mascarado
     * ({@code raw[31] &= 0x7F}) antes de converter para o inteiro big-endian {@code u}.</p>
     *
     * @throws ProtocolException se o array for nulo, não tiver 32 bytes ou a chave for inválida.
     */
    public static PublicKey fromRawPublicKey(byte[] rawLe) throws ProtocolException {
        if (rawLe == null || rawLe.length != Constants.X25519_KEY_BYTES) {
            int len = rawLe == null ? -1 : rawLe.length;
            throw new ProtocolException("Chave pública X25519 raw deve ter 32 bytes (recebido: " + len + ")");
        }

        byte[] copy = rawLe.clone();
        // Regra obrigatória do RFC 7748 §5: zerar o bit mais significativo do último byte little-endian
        copy[Constants.X25519_KEY_BYTES - 1] &= 0x7F;

        // Inverte de little-endian para big-endian para construir BigInteger positivo
        byte[] be = new byte[Constants.X25519_KEY_BYTES];
        for (int i = 0; i < Constants.X25519_KEY_BYTES; i++) {
            be[i] = copy[Constants.X25519_KEY_BYTES - 1 - i];
        }

        BigInteger u = new BigInteger(1, be);
        try {
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
            return kf.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, u));
        } catch (GeneralSecurityException e) {
            throw new ProtocolException("Falha ao reconstruir PublicKey X25519 a partir de bytes raw", e);
        }
    }

    /**
     * Importa um escalar privado de 32 bytes raw (RFC 7748) para {@link PrivateKey} X25519.
     * Útil para validação com os vetores oficiais de teste do RFC 7748 §6.1.
     */
    public static PrivateKey fromRawPrivateKey(byte[] rawScalar32) throws ProtocolException {
        if (rawScalar32 == null || rawScalar32.length != Constants.X25519_KEY_BYTES) {
            int len = rawScalar32 == null ? -1 : rawScalar32.length;
            throw new ProtocolException("Chave privada X25519 raw deve ter 32 bytes (recebido: " + len + ")");
        }
        try {
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
            return kf.generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, rawScalar32.clone()));
        } catch (GeneralSecurityException e) {
            throw new ProtocolException("Falha ao importar PrivateKey X25519", e);
        }
    }

    /**
     * Calcula o segredo compartilhado {@code Z = ECDH(skSelf, pkPeer)} (32 bytes) a partir
     * da chave privada local e dos 32 bytes raw da chave pública do par.
     *
     * <p>Rejeita chaves públicas que produzam segredo compartilhado todo zero (ponto de
     * ordem baixa na curva), lançando {@link ProtocolException} em tempo constante.</p>
     */
    public static byte[] sharedSecret(PrivateKey skSelf, byte[] rawPkPeer) throws ProtocolException {
        PublicKey pkPeer = fromRawPublicKey(rawPkPeer);
        return sharedSecret(skSelf, pkPeer);
    }

    /**
     * Calcula o segredo compartilhado {@code Z = ECDH(skSelf, pkPeer)} (32 bytes).
     *
     * @throws ProtocolException se a chave for inválida ou se {@code Z} resultar em 32 bytes zero.
     */
    public static byte[] sharedSecret(PrivateKey skSelf, PublicKey pkPeer) throws ProtocolException {
        if (skSelf == null || pkPeer == null) {
            throw new ProtocolException("Chaves para ECDH X25519 não podem ser nulas");
        }
        try {
            KeyAgreement ka = KeyAgreement.getInstance(ALGORITHM);
            ka.init(skSelf);
            ka.doPhase(pkPeer, true);
            byte[] z = ka.generateSecret();
            if (z.length != Constants.X25519_SECRET_BYTES || Bytes.constantTimeEquals(z, ALL_ZERO_SECRET)) {
                Bytes.wipe(z);
                throw new ProtocolException("Segredo compartilhado X25519 inválido (ponto de ordem baixa / tudo zero)");
            }
            return z;
        } catch (InvalidKeyException e) {
            throw new ProtocolException("Chave X25519 rejeitada no ECDH (possível ponto de ordem baixa)", e);
        } catch (GeneralSecurityException e) {
            throw new ProtocolException("Erro criptográfico ao calcular ECDH X25519", e);
        }
    }
}

