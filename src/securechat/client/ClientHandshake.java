package securechat.client;

import securechat.common.Bytes;
import securechat.common.CertUtil;
import securechat.common.ClientId;
import securechat.common.Constants;
import securechat.common.Framing;
import securechat.common.Hkdf;
import securechat.common.Messages;
import securechat.common.ProtocolException;
import securechat.common.RsaPss;
import securechat.common.SecureLog;
import securechat.common.X25519Util;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Execução do handshake criptográfico no lado do cliente (seção 4 de {@code docs/01}).
 *
 * <pre>
 * Fluxo no cliente:
 *   1. Aplica timeout de leitura no socket (HANDSHAKE_TIMEOUT_MS).
 *   2. Envia frame 0x01 HELLO: client_id (16B) || pk_C (32B raw X25519).
 *   3. Lê frame 0x02 HELLO_REPLY: pk_S (32B) || salt_srv (16B) || sig || server.crt (DER).
 *   4. Valida Certificate Pinning (D7): compara server.crt recebido byte a byte em tempo
 *      constante com o certificado pinado local antes de confiar na PublicKey RSA.
 *   5. Recalcula localmente H = SHA256(pk_S || pk_C || client_id || salt_srv) e verifica
 *      a assinatura RSA-PSS (D6). Se falhar, aborta imediatamente.
 *   6. Calcula Z_ctrl = ECDH(sk_C, pk_S), deriva Key_S2C via HKDF(salt_srv, Z_ctrl, "S2C", 16B)
 *      e zera Z_ctrl da memória.
 *   7. Remove o timeout de handshake (setSoTimeout(0)).
 * </pre>
 */
public final class ClientHandshake {

    /**
     * Resultado produzido pelo handshake do cliente.
     */
    public record Result(
            ClientId clientId,
            KeyPair clientKeyPair,
            byte[] pkC,
            byte[] saltSrv,
            byte[] keyS2C) {

        public Result {
            Objects.requireNonNull(clientId, "clientId não pode ser nulo");
            Objects.requireNonNull(clientKeyPair, "clientKeyPair não pode ser nulo");
            Objects.requireNonNull(pkC, "pkC não pode ser nulo");
            Objects.requireNonNull(saltSrv, "saltSrv não pode ser nulo");
            Objects.requireNonNull(keyS2C, "keyS2C não pode ser nulo");
            pkC = pkC.clone();
            saltSrv = saltSrv.clone();
            keyS2C = keyS2C.clone();
        }

        @Override
        public byte[] pkC() {
            return pkC.clone();
        }

        @Override
        public byte[] saltSrv() {
            return saltSrv.clone();
        }

        @Override
        public byte[] keyS2C() {
            return keyS2C.clone();
        }
    }

    private ClientHandshake() {
        // Classe utilitária não instanciável.
    }

    /**
     * Executa o handshake do lado cliente contra o servidor conectado.
     *
     * @throws ProtocolException se o certificado divergir do pinado, a assinatura RSA-PSS
     *         for inválida, a chave X25519 do servidor for inválida ou ocorrer timeout.
     * @throws IOException se ocorrer erro de I/O no socket.
     */
    public static Result perform(
            Socket socket,
            DataInputStream in,
            DataOutputStream out,
            ClientId clientId,
            KeyPair clientKeyPair,
            X509Certificate pinnedServerCert,
            int timeoutMs) throws ProtocolException, IOException {

        Objects.requireNonNull(socket, "socket não pode ser nulo");
        Objects.requireNonNull(in, "in não pode ser nulo");
        Objects.requireNonNull(out, "out não pode ser nulo");
        Objects.requireNonNull(clientId, "clientId não pode ser nulo");
        Objects.requireNonNull(clientKeyPair, "clientKeyPair não pode ser nulo");
        Objects.requireNonNull(pinnedServerCert, "pinnedServerCert não pode ser nulo");

        byte[] zCtrl = null;
        try {
            socket.setSoTimeout(timeoutMs);

            byte[] pkC = X25519Util.toRawPublicKey(clientKeyPair.getPublic());
            Messages.HelloMsg hello = new Messages.HelloMsg(clientId, pkC);
            Framing.writeFrame(out, Constants.TYPE_HELLO, Messages.packHello(hello));

            Framing.Frame replyFrame = Framing.readFrame(in);
            if (replyFrame.type() != Constants.TYPE_HELLO_REPLY) {
                SecureLog.rejected(clientId, "esperado HELLO_REPLY (0x02), recebido " + replyFrame.type(),
                        replyFrame.payload().length);
                throw new ProtocolException("Resposta inesperada no handshake: tipo " + replyFrame.type());
            }

            Messages.HelloReplyMsg reply = Messages.unpackHelloReply(replyFrame.payload());

            // 6(a) Certificate Pinning (Decisão D7): igualdade exata DER em tempo constante
            PublicKey serverRsaPub = CertUtil.verifyPinnedCertificate(pinnedServerCert, reply.certDer());

            // 6(b) Verificação da assinatura RSA-PSS (Decisão D6) sobre o H recalculado localmente
            byte[] expectedH = Messages.handshakeHash(reply.pkS(), pkC, clientId, reply.saltSrv());
            RsaPss.verify(serverRsaPub, expectedH, reply.signature());

            // Deriva Key_S2C = HKDF(salt_srv, ECDH(sk_C, pk_S), "S2C", 16B) e zera Z_ctrl
            zCtrl = X25519Util.sharedSecret(clientKeyPair.getPrivate(), reply.pkS());
            byte[] keyS2C = Hkdf.deriveKey(
                    reply.saltSrv(), zCtrl, Constants.HKDF_INFO_S2C, Constants.AES_KEY_BYTES);

            socket.setSoTimeout(0);
            return new Result(clientId, clientKeyPair, pkC, reply.saltSrv(), keyS2C);
        } catch (SocketTimeoutException e) {
            SecureLog.rejected(clientId, "timeout aguardando HELLO_REPLY do servidor");
            throw new ProtocolException("Timeout aguardando HELLO_REPLY do servidor", e);
        } catch (ProtocolException e) {
            SecureLog.rejected(clientId, "handshake abortado pelo cliente: " + e.getMessage());
            throw e;
        } finally {
            Bytes.wipe(zCtrl);
        }
    }
}

