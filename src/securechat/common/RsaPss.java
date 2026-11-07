package securechat.common;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Assinatura digital e verificação com {@code RSASSA-PSS} e parâmetros explícitos fixos
 * (Decisão de Projeto D6).
 *
 * <p><b>Por que fixar explicitamente o {@link PSSParameterSpec}?</b>
 * No JCA do Java, uma instância de {@code Signature.getInstance("RSASSA-PSS")} exige que
 * o algoritmo de hash, a função de geração de máscara (MGF1), o tamanho do salt e o byte
 * de trailer sejam configurados de forma idêntica no assinante (servidor) e no verificador
 * (cliente) antes de {@code initSign}/{@code initVerify}.</p>
 *
 * <p>Parâmetros fixados (D6): Hash {@code SHA-256}, MGF {@code MGF1-SHA-256}, salt de
 * {@code 32 bytes} e trailer {@code 0xBC} ({@link PSSParameterSpec#TRAILER_FIELD_BC}),
 * exigindo chave RSA de no mínimo {@code 2048 bits}.</p>
 */
public final class RsaPss {

    private static final String SIGNATURE_ALG = "RSASSA-PSS";

    /** Especificação imutável de parâmetros RSA-PSS compartilhada entre servidor e cliente (D6). */
    public static final PSSParameterSpec PSS_PARAMS = new PSSParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            Constants.PSS_SALT_BYTES,
            PSSParameterSpec.TRAILER_FIELD_BC);

    private RsaPss() {
        // Classe utilitária não instanciável.
    }

    /**
     * Assina os bytes fornecidos (tipicamente o resumo {@code H} de 32 bytes do handshake)
     * usando a chave privada RSA do servidor e os parâmetros fixos D6.
     *
     * @throws ProtocolException se a chave não for RSA >= 2048 bits ou ocorrer falha na assinatura.
     */
    public static byte[] sign(PrivateKey privateKey, byte[] data) throws ProtocolException {
        validateRsaKey(privateKey);
        if (data == null || data.length == 0) {
            throw new ProtocolException("Dados para assinatura RSA-PSS não podem ser nulos ou vazios");
        }
        try {
            Signature sig = Signature.getInstance(SIGNATURE_ALG);
            sig.setParameter(PSS_PARAMS);
            sig.initSign(privateKey);
            sig.update(data);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new ProtocolException("Falha ao assinar com RSASSA-PSS", e);
        }
    }

    /**
     * Verifica uma assinatura RSA-PSS sobre {@code data} usando a chave pública do certificado
     * do servidor e os parâmetros fixos D6.
     *
     * @throws ProtocolException se a assinatura for inválida, adulterada ou a chave for fraca.
     */
    public static void verify(PublicKey publicKey, byte[] data, byte[] signatureBytes)
            throws ProtocolException {
        validateRsaKey(publicKey);
        if (data == null || data.length == 0) {
            throw new ProtocolException("Dados para verificação RSA-PSS não podem ser nulos ou vazios");
        }
        if (signatureBytes == null || signatureBytes.length == 0) {
            throw new ProtocolException("Assinatura RSA-PSS ausente ou vazia");
        }

        try {
            Signature sig = Signature.getInstance(SIGNATURE_ALG);
            sig.setParameter(PSS_PARAMS);
            sig.initVerify(publicKey);
            sig.update(data);
            boolean ok = sig.verify(signatureBytes);
            if (!ok) {
                throw new ProtocolException("Assinatura RSA-PSS inválida para o hash H do handshake");
            }
        } catch (ProtocolException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new ProtocolException("Falha na verificação da assinatura RSASSA-PSS", e);
        }
    }

    private static void validateRsaKey(Object key) throws ProtocolException {
        if (!(key instanceof RSAKey rsaKey)) {
            throw new ProtocolException("Chave fornecida para RSA-PSS não é uma chave RSA");
        }
        int bits = rsaKey.getModulus().bitLength();
        if (bits < Constants.RSA_MIN_BITS) {
            throw new ProtocolException(
                    "Chave RSA insegura: exigido >= " + Constants.RSA_MIN_BITS + " bits, obtido " + bits);
        }
    }
}

