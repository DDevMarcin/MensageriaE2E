package securechat.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;

/**
 * Carregamento da identidade RSA do servidor ({@code certs/server.p12}) e validação
 * por pinning do certificado público autoassinado ({@code certs/server.crt} em formato DER)
 * pelos clientes (Decisão de Projeto D7).
 *
 * <p><b>Por que usar Certificate Pinning byte a byte em tempo constante?</b>
 * Como o certificado do servidor é autoassinado (não há Autoridade Certificadora comercial),
 * uma simples verificação de cadeia X.509 aceitaria qualquer certificado autoassinado forjado
 * por um atacante Man-in-the-Middle. Com o pinning (D7), o cliente possui uma cópia local
 * de {@code certs/server.crt} e compara os bytes DER recebidos no {@code HELLO_REPLY} com
 * os bytes pinados via {@link Bytes#constantTimeEquals(byte[], byte[])} antes de extrair a
 * chave pública RSA para verificar a assinatura RSA-PSS.</p>
 */
public final class CertUtil {

    /**
     * Agrupa a chave privada RSA e o certificado X.509 (objeto e bytes DER) do servidor.
     */
    public record ServerIdentity(
            PrivateKey privateKey,
            X509Certificate certificate,
            byte[] certDer) {

        public ServerIdentity {
            Objects.requireNonNull(privateKey, "privateKey não pode ser nula");
            Objects.requireNonNull(certificate, "certificate não pode ser nulo");
            Objects.requireNonNull(certDer, "certDer não pode ser nulo");
            certDer = certDer.clone();
        }

        @Override
        public byte[] certDer() {
            return certDer.clone();
        }
    }

    private CertUtil() {
        // Classe utilitária não instanciável.
    }

    /**
     * Resolve a senha do keystore PKCS#12 lendo a variável de ambiente
     * {@link Constants#ENV_KEYSTORE_PASS} ou usando o padrão didático
     * {@link Constants#DEFAULT_KEYSTORE_PASS}.
     */
    public static char[] resolveKeystorePassword() {
        String env = System.getenv(Constants.ENV_KEYSTORE_PASS);
        String pass = (env != null && !env.isEmpty()) ? env : Constants.DEFAULT_KEYSTORE_PASS;
        return pass.toCharArray();
    }

    /**
     * Carrega a chave privada RSA e o certificado X.509 do keystore PKCS#12 do servidor.
     *
     * @param keystorePath caminho do arquivo {@code certs/server.p12}.
     * @param password     senha do keystore (será zerada ao final da chamada).
     * @param alias        alias da entrada RSA (ex.: {@link Constants#KEYSTORE_ALIAS}).
     * @throws ProtocolException se o arquivo não puder ser lido ou a chave/certificado forem inválidos.
     */
    public static ServerIdentity loadServerIdentity(Path keystorePath, char[] password, String alias)
            throws ProtocolException {
        Objects.requireNonNull(keystorePath, "keystorePath não pode ser nulo");
        Objects.requireNonNull(password, "password não pode ser nula");
        Objects.requireNonNull(alias, "alias não pode ser nulo");

        char[] passCopy = password.clone();
        try (InputStream in = Files.newInputStream(keystorePath)) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(in, passCopy);

            Key key = ks.getKey(alias, passCopy);
            if (!(key instanceof PrivateKey privateKey)) {
                throw new ProtocolException("Alias '" + alias + "' não contém uma PrivateKey em " + keystorePath);
            }

            Certificate cert = ks.getCertificate(alias);
            if (!(cert instanceof X509Certificate x509)) {
                throw new ProtocolException("Alias '" + alias + "' não contém um X509Certificate em " + keystorePath);
            }

            byte[] der = x509.getEncoded();
            return new ServerIdentity(privateKey, x509, der);
        } catch (ProtocolException e) {
            throw e;
        } catch (IOException | GeneralSecurityException e) {
            throw new ProtocolException("Falha ao carregar identidade do servidor de " + keystorePath, e);
        } finally {
            Arrays.fill(passCopy, '\0');
            Arrays.fill(password, '\0');
        }
    }

    /**
     * Sobrecarga conveniente que carrega o alias padrão {@link Constants#KEYSTORE_ALIAS}.
     */
    public static ServerIdentity loadServerIdentity(Path keystorePath, char[] password)
            throws ProtocolException {
        return loadServerIdentity(keystorePath, password, Constants.KEYSTORE_ALIAS);
    }

    /**
     * Carrega um certificado X.509 em formato DER (ou PEM) a partir do disco para uso como
     * certificado pinado no cliente ({@code certs/server.crt}).
     */
    public static X509Certificate loadPinnedCertificate(Path certPath) throws ProtocolException {
        Objects.requireNonNull(certPath, "certPath não pode ser nulo");
        try {
            byte[] raw = Files.readAllBytes(certPath);
            return parseCertificateDer(raw);
        } catch (IOException e) {
            throw new ProtocolException("Falha ao ler certificado pinado em " + certPath, e);
        }
    }

    /**
     * Decodifica um array de bytes DER em um objeto {@link X509Certificate}.
     */
    public static X509Certificate parseCertificateDer(byte[] certDer) throws ProtocolException {
        if (certDer == null || certDer.length == 0) {
            throw new ProtocolException("Bytes do certificado X.509 ausentes ou vazios");
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certDer));
            if (!(cert instanceof X509Certificate x509)) {
                throw new ProtocolException("Certificado decodificado não é X.509");
            }
            return x509;
        } catch (GeneralSecurityException e) {
            throw new ProtocolException("Certificado X.509 malformado ou inválido", e);
        }
    }

    /**
     * Valida que os bytes DER recebidos do servidor no {@code HELLO_REPLY} são idênticos,
     * byte a byte e em tempo constante, ao certificado pinado localmente (Decisão D7),
     * retornando a {@link PublicKey} RSA confiável para verificação da assinatura RSA-PSS.
     *
     * @throws ProtocolException se os bytes do certificado divergirem do certificado pinado.
     */
    public static PublicKey verifyPinnedCertificate(X509Certificate pinnedCert, byte[] receivedCertDer)
            throws ProtocolException {
        if (pinnedCert == null) {
            throw new ProtocolException("Certificado pinado local não configurado");
        }
        if (receivedCertDer == null || receivedCertDer.length == 0) {
            throw new ProtocolException("Certificado recebido do servidor está vazio");
        }
        try {
            byte[] pinnedDer = pinnedCert.getEncoded();
            if (!Bytes.constantTimeEquals(pinnedDer, receivedCertDer)) {
                throw new ProtocolException(
                        "Pinning falhou: o certificado enviado pelo servidor diverge do server.crt pinado");
            }
            return pinnedCert.getPublicKey();
        } catch (CertificateEncodingException e) {
            throw new ProtocolException("Erro ao obter codificação DER do certificado pinado", e);
        }
    }
}

