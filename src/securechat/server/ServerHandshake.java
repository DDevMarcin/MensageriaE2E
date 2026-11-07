package securechat.server;

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
import java.util.Objects;

/**
 * Execução do handshake criptográfico no lado do servidor (seção 4 de {@code docs/01}).
 *
 * <pre>
 * Fluxo no servidor:
 *   1. Aplica timeout de leitura no socket (HANDSHAKE_TIMEOUT_MS).
 *   2. Lê frame 0x01 HELLO: client_id (16B) || pk_C (32B raw X25519).
 *   3. Gera salt_srv (16B) e par X25519 efêmero (sk_S, pk_S) exclusivo desta conexão (D1).
 *   4. Calcula Z_ctrl = ECDH(sk_S, pk_C), deriva Key_S2C via HKDF(salt_srv, Z_ctrl, "S2C", 16B)
 *      e descarta Z_ctrl e sk_S imediatamente (Forward Secrecy).
 *   5. Calcula H = SHA256(pk_S || pk_C || client_id || salt_srv) e assina H com RSA-PSS (D6).
 *   6. Envia 0x02 HELLO_REPLY: pk_S || salt_srv || sig || server.crt (DER).
 *   7. Remove o timeout de handshake (setSoTimeout(0)) e devolve o resultado para registro.
 * </pre>
 */
public final class ServerHandshake {

    /**
     * Resultado produzido pelo handshake do servidor para inaugurar a {@code Session} do cliente.
     * Note que {@code keyS2C} protege apenas o canal administrativo Servidor -> Cliente; o
     * servidor jamais recebe ou deriva chaves E2E entre clientes.
     */
    public record Result(
            ClientId clientId,
            byte[] pkC,
            byte[] saltSrv,
            byte[] keyS2C) {

        public Result {
            Objects.requireNonNull(clientId, "clientId não pode ser nulo");
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

    private ServerHandshake() {
        // Classe utilitária não instanciável.
    }

    /**
     * Executa o handshake do lado servidor na conexão fornecida.
     *
     * @throws ProtocolException se o cliente enviar frame inválido, chave X25519 inválida
     *         ou exceder o tempo limite de handshake.
     * @throws IOException se ocorrer erro de rede no socket.
     */
    public static Result perform(
            Socket socket,
            DataInputStream in,
            DataOutputStream out,
            CertUtil.ServerIdentity serverIdentity,
            int timeoutMs) throws ProtocolException, IOException {

        Objects.requireNonNull(socket, "socket não pode ser nulo");
        Objects.requireNonNull(in, "in não pode ser nulo");
        Objects.requireNonNull(out, "out não pode ser nulo");
        Objects.requireNonNull(serverIdentity, "serverIdentity não pode ser nula");

        ClientId clientId = null;
        byte[] zCtrl = null;
        try {
            socket.setSoTimeout(timeoutMs);

            Framing.Frame frame = Framing.readFrame(in);
            if (frame.type() != Constants.TYPE_HELLO) {
                SecureLog.rejected(null, "esperado HELLO (0x01), recebido tipo " + frame.type(),
                        frame.payload().length);
                throw new ProtocolException("Primeiro frame do handshake deve ser HELLO (0x01)");
            }

            Messages.HelloMsg hello = Messages.unpackHello(frame.payload());
            clientId = hello.clientId();
            byte[] pkC = hello.pkC();

            // Importa pk_C e valida que é um ponto X25519 válido
            PublicKey clientPubKey = X25519Util.fromRawPublicKey(pkC);

            // Gera salt_srv (16B) e par X25519 efêmero (sk_S, pk_S) para esta sessão (Decisão D1)
            byte[] saltSrv = Bytes.randomBytes(Constants.SALT_BYTES);
            KeyPair serverEphemeral = X25519Util.generateKeyPair();
            byte[] pkS = X25519Util.toRawPublicKey(serverEphemeral.getPublic());

            // Calcula segredo ECDH do canal de controle e deriva Key_S2C
            zCtrl = X25519Util.sharedSecret(serverEphemeral.getPrivate(), clientPubKey);
            byte[] keyS2C = Hkdf.deriveKey(
                    saltSrv, zCtrl, Constants.HKDF_INFO_S2C, Constants.AES_KEY_BYTES);

            // Assina H = SHA256(pk_S || pk_C || client_id || salt_srv) com RSA-PSS (D6)
            byte[] h = Messages.handshakeHash(pkS, pkC, clientId, saltSrv);
            byte[] sig = RsaPss.sign(serverIdentity.privateKey(), h);

            Messages.HelloReplyMsg reply = new Messages.HelloReplyMsg(
                    pkS, saltSrv, sig, serverIdentity.certDer());
            Framing.writeFrame(out, Constants.TYPE_HELLO_REPLY, Messages.packHelloReply(reply));

            socket.setSoTimeout(0);
            return new Result(clientId, pkC, saltSrv, keyS2C);
        } catch (SocketTimeoutException e) {
            SecureLog.rejected(clientId, "timeout no handshake do servidor");
            throw new ProtocolException("Timeout aguardando HELLO do cliente", e);
        } catch (ProtocolException e) {
            SecureLog.rejected(clientId, "falha no handshake: " + e.getMessage());
            throw e;
        } finally {
            Bytes.wipe(zCtrl);
        }
    }
}

