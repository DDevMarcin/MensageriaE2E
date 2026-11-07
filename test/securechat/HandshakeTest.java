package securechat;

import securechat.client.ClientHandshake;
import securechat.common.Bytes;
import securechat.common.CertUtil;
import securechat.common.ClientId;
import securechat.common.Constants;
import securechat.common.Framing;
import securechat.common.Messages;
import securechat.common.ProtocolException;
import securechat.common.RsaPss;
import securechat.common.X25519Util;
import securechat.server.ServerHandshake;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Testes automatizados de integração da T05: {@link ServerHandshake} e {@link ClientHandshake}.
 */
public final class HandshakeTest {

    private HandshakeTest() {
        // Classe de testes não instanciável.
    }

    /**
     * Cenário 1: Handshake completo válido sobre TCP local em porta efêmera; verifica que
     * cliente e servidor derivam exatamente a mesma {@code Key_S2C} e concordam em
     * {@code client_id}, {@code pk_C} e {@code salt_srv}.
     */
    public static void testHandshakeSuccess() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        AtomicReference<ServerHandshake.Result> srvRef = new AtomicReference<>();
        AtomicReference<Throwable> srvErr = new AtomicReference<>();

        try (ServerSocket ss = new ServerSocket(0)) {
            int port = ss.getLocalPort();
            Thread srvThread = Thread.ofVirtual().start(() -> {
                try (Socket s = ss.accept();
                     DataInputStream in = new DataInputStream(s.getInputStream());
                     DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
                    srvRef.set(ServerHandshake.perform(
                            s, in, out, serverId, Constants.HANDSHAKE_TIMEOUT_MS));
                } catch (Throwable t) {
                    srvErr.set(t);
                }
            });

            ClientId cid = ClientId.random();
            KeyPair clientKp = X25519Util.generateKeyPair();
            ClientHandshake.Result cliRes;
            try (Socket c = new Socket("127.0.0.1", port);
                 DataInputStream in = new DataInputStream(c.getInputStream());
                 DataOutputStream out = new DataOutputStream(c.getOutputStream())) {
                cliRes = ClientHandshake.perform(
                        c, in, out, cid, clientKp, pinnedCert, Constants.HANDSHAKE_TIMEOUT_MS);
            }

            srvThread.join(5000);
            if (srvErr.get() != null) {
                throw new AssertionError("Erro no servidor durante handshake", srvErr.get());
            }

            ServerHandshake.Result srvRes = srvRef.get();
            Assert.assertEquals(cid, srvRes.clientId());
            Assert.assertArrayEquals(cliRes.pkC(), srvRes.pkC());
            Assert.assertArrayEquals(cliRes.saltSrv(), srvRes.saltSrv());
            Assert.assertArrayEquals(cliRes.keyS2C(), srvRes.keyS2C(),
                    "Cliente e servidor devem derivar a mesma Key_S2C");
        }
    }

    /**
     * Cenário 2: Certificado enviado pelo servidor diverge do certificado pinado no cliente
     * -> {@link ClientHandshake} aborta com {@link ProtocolException}.
     */
    public static void testHandshakeWrongCertificateAborts() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate realPinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        try (ServerSocket ss = new ServerSocket(0)) {
            int port = ss.getLocalPort();
            Thread srvThread = Thread.ofVirtual().start(() -> {
                try (Socket s = ss.accept();
                     DataInputStream in = new DataInputStream(s.getInputStream());
                     DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
                    Framing.Frame helloFrame = Framing.readFrame(in);
                    Messages.HelloMsg hello = Messages.unpackHello(helloFrame.payload());

                    byte[] pkS = X25519Util.toRawPublicKey(X25519Util.generateKeyPair().getPublic());
                    byte[] salt = Bytes.randomBytes(Constants.SALT_BYTES);
                    byte[] h = Messages.handshakeHash(pkS, hello.pkC(), hello.clientId(), salt);
                    byte[] sig = RsaPss.sign(serverId.privateKey(), h);

                    // Altera 1 byte nos bytes DER do certificado enviado
                    byte[] fakeCertDer = serverId.certDer();
                    fakeCertDer[fakeCertDer.length - 10] ^= 0x01;

                    Messages.HelloReplyMsg reply = new Messages.HelloReplyMsg(pkS, salt, sig, fakeCertDer);
                    Framing.writeFrame(out, Constants.TYPE_HELLO_REPLY, Messages.packHelloReply(reply));
                } catch (Throwable ignored) {
                }
            });

            try (Socket c = new Socket("127.0.0.1", port);
                 DataInputStream in = new DataInputStream(c.getInputStream());
                 DataOutputStream out = new DataOutputStream(c.getOutputStream())) {
                Assert.assertThrows(ProtocolException.class, () -> ClientHandshake.perform(
                        c, in, out, ClientId.random(), X25519Util.generateKeyPair(),
                        realPinnedCert, Constants.HANDSHAKE_TIMEOUT_MS));
            }
            srvThread.join(5000);
        }
    }

    /**
     * Cenário 3: Assinatura RSA-PSS adulterada no {@code HELLO_REPLY}
     * -> {@link ClientHandshake} aborta com {@link ProtocolException}.
     */
    public static void testHandshakeCorruptedSignatureAborts() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        try (ServerSocket ss = new ServerSocket(0)) {
            int port = ss.getLocalPort();
            Thread srvThread = Thread.ofVirtual().start(() -> {
                try (Socket s = ss.accept();
                     DataInputStream in = new DataInputStream(s.getInputStream());
                     DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
                    Framing.Frame helloFrame = Framing.readFrame(in);
                    Messages.HelloMsg hello = Messages.unpackHello(helloFrame.payload());

                    byte[] pkS = X25519Util.toRawPublicKey(X25519Util.generateKeyPair().getPublic());
                    byte[] salt = Bytes.randomBytes(Constants.SALT_BYTES);
                    byte[] h = Messages.handshakeHash(pkS, hello.pkC(), hello.clientId(), salt);
                    byte[] sig = RsaPss.sign(serverId.privateKey(), h);
                    sig[0] ^= 0x01; // corrompe 1 bit da assinatura

                    Messages.HelloReplyMsg reply = new Messages.HelloReplyMsg(
                            pkS, salt, sig, serverId.certDer());
                    Framing.writeFrame(out, Constants.TYPE_HELLO_REPLY, Messages.packHelloReply(reply));
                } catch (Throwable ignored) {
                }
            });

            try (Socket c = new Socket("127.0.0.1", port);
                 DataInputStream in = new DataInputStream(c.getInputStream());
                 DataOutputStream out = new DataOutputStream(c.getOutputStream())) {
                Assert.assertThrows(ProtocolException.class, () -> ClientHandshake.perform(
                        c, in, out, ClientId.random(), X25519Util.generateKeyPair(),
                        pinnedCert, Constants.HANDSHAKE_TIMEOUT_MS));
            }
            srvThread.join(5000);
        }
    }

    /**
     * Cenário 4: Servidor assina {@code H} calculado com um {@code client_id} diferente
     * daquele enviado pelo cliente -> {@link ClientHandshake} detecta divergência no {@code H}
     * recalculado localmente e aborta com {@link ProtocolException}.
     */
    public static void testHandshakeSwappedClientIdInHashAborts() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());
        X509Certificate pinnedCert = CertUtil.loadPinnedCertificate(
                Path.of(Constants.DEFAULT_CERT_PATH));

        try (ServerSocket ss = new ServerSocket(0)) {
            int port = ss.getLocalPort();
            Thread srvThread = Thread.ofVirtual().start(() -> {
                try (Socket s = ss.accept();
                     DataInputStream in = new DataInputStream(s.getInputStream());
                     DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
                    Framing.Frame helloFrame = Framing.readFrame(in);
                    Messages.HelloMsg hello = Messages.unpackHello(helloFrame.payload());

                    byte[] pkS = X25519Util.toRawPublicKey(X25519Util.generateKeyPair().getPublic());
                    byte[] salt = Bytes.randomBytes(Constants.SALT_BYTES);
                    // Assina H usando outro client_id diferente do cliente real
                    byte[] wrongH = Messages.handshakeHash(pkS, hello.pkC(), ClientId.random(), salt);
                    byte[] sig = RsaPss.sign(serverId.privateKey(), wrongH);

                    Messages.HelloReplyMsg reply = new Messages.HelloReplyMsg(
                            pkS, salt, sig, serverId.certDer());
                    Framing.writeFrame(out, Constants.TYPE_HELLO_REPLY, Messages.packHelloReply(reply));
                } catch (Throwable ignored) {
                }
            });

            try (Socket c = new Socket("127.0.0.1", port);
                 DataInputStream in = new DataInputStream(c.getInputStream());
                 DataOutputStream out = new DataOutputStream(c.getOutputStream())) {
                Assert.assertThrows(ProtocolException.class, () -> ClientHandshake.perform(
                        c, in, out, ClientId.random(), X25519Util.generateKeyPair(),
                        pinnedCert, Constants.HANDSHAKE_TIMEOUT_MS));
            }
            srvThread.join(5000);
        }
    }

    /**
     * Cenário 5: Cliente conecta mas não envia {@code HELLO} dentro do timeout configurado
     * -> {@link ServerHandshake} lança {@link ProtocolException} por timeout sem travar a thread.
     */
    public static void testHandshakeTimeoutHandled() throws Exception {
        CertUtil.ServerIdentity serverId = CertUtil.loadServerIdentity(
                Path.of(Constants.DEFAULT_KEYSTORE_PATH), CertUtil.resolveKeystorePassword());

        try (ServerSocket ss = new ServerSocket(0)) {
            int port = ss.getLocalPort();
            AtomicReference<Throwable> srvCaught = new AtomicReference<>();

            Thread srvThread = Thread.ofVirtual().start(() -> {
                try (Socket s = ss.accept();
                     DataInputStream in = new DataInputStream(s.getInputStream());
                     DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
                    ServerHandshake.perform(s, in, out, serverId, 150); // timeout curto de 150 ms
                } catch (Throwable t) {
                    srvCaught.set(t);
                }
            });

            try (Socket idleClient = new Socket("127.0.0.1", port)) {
                Assert.assertTrue(idleClient.isConnected(), "Cliente de teste deve conectar");
                srvThread.join(3000);
            }

            Assert.assertTrue(srvCaught.get() instanceof ProtocolException,
                    "Servidor deve lançar ProtocolException quando o handshake estoura o timeout");
        }
    }
}
