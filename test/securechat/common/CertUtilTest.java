package securechat.common;

import securechat.Assert;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Testes automatizados da T03: carregamento de {@code certs/server.p12}, pinning de
 * {@code certs/server.crt} e ciclo completo de assinatura/verificação RSA-PSS com as
 * credenciais reais do servidor.
 */
public final class CertUtilTest {

    private CertUtilTest() {
        // Classe de testes não instanciável.
    }

    /**
     * Carrega {@code certs/server.p12} e {@code certs/server.crt}, valida o pinning D7,
     * assina um hash {@code H} de handshake com a {@code PrivateKey} do keystore e verifica
     * com a {@code PublicKey} extraída do certificado pinado.
     */
    public static void testLoadKeystoreAndVerifyPinnedCert() throws Exception {
        Path p12Path = Path.of(Constants.DEFAULT_KEYSTORE_PATH);
        Path crtPath = Path.of(Constants.DEFAULT_CERT_PATH);

        Assert.assertTrue(Files.exists(p12Path),
                "certs/server.p12 deve existir (gerado por scripts/gen-cert)");
        Assert.assertTrue(Files.exists(crtPath),
                "certs/server.crt deve existir (gerado por scripts/gen-cert)");

        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                p12Path, CertUtil.resolveKeystorePassword());
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(crtPath);

        // Pinning com os bytes exatos do certificado do servidor deve suceder
        PublicKey verifiedPubKey = CertUtil.verifyPinnedCertificate(pinnedCert, serverId.certDer());
        Assert.assertEquals(pinnedCert.getPublicKey(), verifiedPubKey,
                "PublicKey retornada após pinning deve coincidir com o certificado pinado");

        // Assina um hash H com a chave privada do server.p12 e verifica com server.crt
        byte[] pkS = Bytes.randomBytes(Constants.X25519_KEY_BYTES);
        byte[] pkC = Bytes.randomBytes(Constants.X25519_KEY_BYTES);
        ClientId clientId = ClientId.random();
        byte[] salt = Bytes.randomBytes(Constants.SALT_BYTES);

        byte[] h = Messages.handshakeHash(pkS, pkC, clientId, salt);
        byte[] signature = RsaPss.sign(serverId.privateKey(), h);
        RsaPss.verify(verifiedPubKey, h, signature);

        // Se 1 byte do certificado DER recebido for alterado, o pinning deve rejeitar (D7)
        byte[] tamperedDer = serverId.certDer();
        tamperedDer[tamperedDer.length / 2] ^= 0x01;
        Assert.assertThrows(ProtocolException.class,
                () -> CertUtil.verifyPinnedCertificate(pinnedCert, tamperedDer));
    }

    /**
     * Verifica que {@code certs/server.p12} está listado no {@code .gitignore} para nunca
     * vazar a chave privada no controle de versão.
     */
    public static void testServerP12InGitignore() throws Exception {
        String gitignore = Files.readString(Path.of(".gitignore"));
        Assert.assertTrue(gitignore.contains("certs/server.p12"),
                ".gitignore deve conter certs/server.p12");
    }
}

