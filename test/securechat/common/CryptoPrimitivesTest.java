package securechat.common;

import securechat.Assert;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.HexFormat;

/**
 * Testes automatizados da T02: {@link X25519Util}, {@link Hkdf}, {@link AesGcm},
 * {@link RsaPss} e {@link Messages#handshakeHash}.
 */
public final class CryptoPrimitivesTest {

    private static final HexFormat HEX = HexFormat.of();

    private CryptoPrimitivesTest() {
        // Classe de testes não instanciável.
    }

    /**
     * Valida o X25519 contra os vetores oficiais do RFC 7748 §6.1 (Alice e Bob),
     * comprovando que a conversão little-endian raw de 32 bytes está exata e que
     * {@code ECDH(sk_A, pk_B) == ECDH(sk_B, pk_A) == K}.
     */
    public static void testX25519Rfc7748Vector() throws Exception {
        byte[] alicePrivate = HEX.parseHex(
                "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] alicePublicExpected = HEX.parseHex(
                "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        byte[] bobPrivate = HEX.parseHex(
                "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        byte[] bobPublicExpected = HEX.parseHex(
                "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        byte[] expectedSharedSecret = HEX.parseHex(
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        PrivateKey skA = X25519Util.fromRawPrivateKey(alicePrivate);
        PrivateKey skB = X25519Util.fromRawPrivateKey(bobPrivate);

        PublicKey pkA = X25519Util.fromRawPublicKey(alicePublicExpected);
        PublicKey pkB = X25519Util.fromRawPublicKey(bobPublicExpected);

        // Round-trip raw -> PublicKey -> raw nos vetores do RFC
        Assert.assertArrayEquals(alicePublicExpected, X25519Util.toRawPublicKey(pkA),
                "Round-trip da chave pública de Alice deve bater byte a byte com o RFC 7748");
        Assert.assertArrayEquals(bobPublicExpected, X25519Util.toRawPublicKey(pkB),
                "Round-trip da chave pública de Bob deve bater byte a byte com o RFC 7748");

        byte[] zAB = X25519Util.sharedSecret(skA, bobPublicExpected);
        byte[] zBA = X25519Util.sharedSecret(skB, alicePublicExpected);

        Assert.assertArrayEquals(expectedSharedSecret, zAB,
                "Segredo compartilhado Z_AB deve bater com o vetor oficial do RFC 7748 §6.1");
        Assert.assertArrayEquals(zAB, zBA,
                "ECDH deve ser simétrico: ECDH(A,B) == ECDH(B,A)");
    }

    /**
     * Valida geração aleatória de pares X25519, round-trip de chave pública raw de 32 bytes,
     * simetria do ECDH e rejeição de ponto de ordem baixa (chave pública toda zero -> Z zero).
     */
    public static void testX25519RoundTripAndLowOrderRejection() throws Exception {
        KeyPair kpA = X25519Util.generateKeyPair();
        KeyPair kpB = X25519Util.generateKeyPair();

        byte[] rawPkA = X25519Util.toRawPublicKey(kpA.getPublic());
        byte[] rawPkB = X25519Util.toRawPublicKey(kpB.getPublic());

        Assert.assertEquals(32, rawPkA.length, "pk_A raw deve ter 32 bytes");
        Assert.assertEquals(32, rawPkB.length, "pk_B raw deve ter 32 bytes");

        // Round-trip: raw -> PublicKey -> raw
        PublicKey importedA = X25519Util.fromRawPublicKey(rawPkA);
        Assert.assertArrayEquals(rawPkA, X25519Util.toRawPublicKey(importedA),
                "Round-trip raw -> PublicKey -> raw deve preservar todos os 32 bytes");

        byte[] z1 = X25519Util.sharedSecret(kpA.getPrivate(), rawPkB);
        byte[] z2 = X25519Util.sharedSecret(kpB.getPrivate(), rawPkA);
        Assert.assertArrayEquals(z1, z2, "ECDH entre pares gerados deve produzir o mesmo Z");

        // Ponto de ordem baixa (32 bytes zero) produz Z todo zero e deve ser rejeitado
        byte[] allZeroPk = new byte[32];
        Assert.assertThrows(ProtocolException.class,
                () -> X25519Util.sharedSecret(kpA.getPrivate(), allZeroPk));

        // Tamanho incorreto de chave pública deve falhar
        Assert.assertThrows(ProtocolException.class,
                () -> X25519Util.fromRawPublicKey(new byte[31]));
    }

    /**
     * Valida o HKDF-SHA256 manual contra o vetor oficial do RFC 5869 Apêndice A.1 (Test Case 1).
     */
    public static void testHkdfRfc5869Vector() throws Exception {
        byte[] ikm = HEX.parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = HEX.parseHex("000102030405060708090a0b0c");
        byte[] info = HEX.parseHex("f0f1f2f3f4f5f6f7f8f9");
        int length = 42;

        byte[] expectedPrk = HEX.parseHex(
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        byte[] expectedOkm = HEX.parseHex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

        byte[] prk = Hkdf.extract(salt, ikm);
        Assert.assertArrayEquals(expectedPrk, prk,
                "PRK do HKDF-Extract deve bater com o RFC 5869 A.1");

        byte[] okm = Hkdf.expand(prk, info, length);
        Assert.assertArrayEquals(expectedOkm, okm,
                "OKM do HKDF-Expand deve bater com o RFC 5869 A.1");

        // Verifica que chaves derivadas para A2B, B2A e S2C têm 16 bytes e são distintas
        byte[] kA2B = Hkdf.expand(prk, Constants.HKDF_INFO_A2B, Constants.AES_KEY_BYTES);
        byte[] kB2A = Hkdf.expand(prk, Constants.HKDF_INFO_B2A, Constants.AES_KEY_BYTES);
        byte[] kS2C = Hkdf.expand(prk, Constants.HKDF_INFO_S2C, Constants.AES_KEY_BYTES);
        Assert.assertEquals(16, kA2B.length);
        Assert.assertFalse(Bytes.constantTimeEquals(kA2B, kB2A), "Key_A2B e Key_B2A devem ser diferentes");
        Assert.assertFalse(Bytes.constantTimeEquals(kA2B, kS2C), "Key_A2B e Key_S2C devem ser diferentes");
    }

    /**
     * Valida o AES-128-GCM: round-trip com AAD, e rejeição imediata (tag mismatch ->
     * {@link ProtocolException}) ao inverter 1 bit no ciphertext, na tag GCM ou no AAD.
     */
    public static void testAesGcmRoundTripAndTamperDetection() throws Exception {
        byte[] key = Bytes.randomBytes(Constants.AES_KEY_BYTES);
        byte[] ivBase = Bytes.randomBytes(Constants.IV_BASE_BYTES);
        byte[] nonce = AesGcm.buildNonce(ivBase, 0L);
        byte[] aad = "sender-recipient-seq0".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "Mensagem secreta ponta-a-ponta!".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertextWithTag = AesGcm.encrypt(key, nonce, aad, plaintext);
        Assert.assertEquals(plaintext.length + Constants.GCM_TAG_BYTES, ciphertextWithTag.length,
                "Saída do AES-GCM deve ser ciphertext + 16 bytes de tag");

        byte[] decrypted = AesGcm.decrypt(key, nonce, aad, ciphertextWithTag);
        Assert.assertArrayEquals(plaintext, decrypted, "Plaintext decifrado deve ser idêntico ao original");

        // 1) Adulterar 1 bit no ciphertext (primeiro byte)
        byte[] tamperedCt = ciphertextWithTag.clone();
        tamperedCt[0] ^= 0x01;
        Assert.assertThrows(ProtocolException.class,
                () -> AesGcm.decrypt(key, nonce, aad, tamperedCt));

        // 2) Adulterar 1 bit na tag de 16 bytes (último byte)
        byte[] tamperedTag = ciphertextWithTag.clone();
        tamperedTag[tamperedTag.length - 1] ^= 0x01;
        Assert.assertThrows(ProtocolException.class,
                () -> AesGcm.decrypt(key, nonce, aad, tamperedTag));

        // 3) Adulterar 1 bit no AAD
        byte[] tamperedAad = aad.clone();
        tamperedAad[0] ^= 0x01;
        Assert.assertThrows(ProtocolException.class,
                () -> AesGcm.decrypt(key, nonce, tamperedAad, ciphertextWithTag));

        // 4) Nonce com seq_no diferente na decifragem deve falhar
        byte[] wrongNonce = AesGcm.buildNonce(ivBase, 1L);
        Assert.assertThrows(ProtocolException.class,
                () -> AesGcm.decrypt(key, wrongNonce, aad, ciphertextWithTag));
    }

    /**
     * Valida assinatura RSA-PSS sobre o hash {@code H} do handshake:
     * assinatura válida passa; assinatura corrompida, {@code H} alterado ou parâmetros
     * PSS divergentes (ex.: salt de 20 B em vez de 32 B) lançam {@link ProtocolException}.
     */
    public static void testRsaPssSignVerifyAndMismatchedParams() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(Constants.RSA_MIN_BITS);
        KeyPair rsaKp = kpg.generateKeyPair();

        byte[] pkS = Bytes.randomBytes(Constants.X25519_KEY_BYTES);
        byte[] pkC = Bytes.randomBytes(Constants.X25519_KEY_BYTES);
        ClientId clientId = ClientId.random();
        byte[] saltSrv = Bytes.randomBytes(Constants.SALT_BYTES);

        byte[] h = Messages.handshakeHash(pkS, pkC, clientId, saltSrv);
        Assert.assertEquals(Constants.SHA256_BYTES, h.length, "Hash H deve ter 32 bytes");

        byte[] sig = RsaPss.sign(rsaKp.getPrivate(), h);
        // Verificação legítima deve suceder
        RsaPss.verify(rsaKp.getPublic(), h, sig);

        // 1) 1 bit corrompido na assinatura deve falhar
        byte[] badSig = sig.clone();
        badSig[badSig.length / 2] ^= 0x01;
        Assert.assertThrows(ProtocolException.class,
                () -> RsaPss.verify(rsaKp.getPublic(), h, badSig));

        // 2) Hash H calculado com outro client_id deve falhar na verificação
        byte[] hOtherClient = Messages.handshakeHash(pkS, pkC, ClientId.random(), saltSrv);
        Assert.assertThrows(ProtocolException.class,
                () -> RsaPss.verify(rsaKp.getPublic(), hOtherClient, sig));

        // 3) Assinatura gerada com parâmetro PSS diferente (salt de 20 B em vez de 32 B) deve falhar
        Signature customSig = Signature.getInstance("RSASSA-PSS");
        customSig.setParameter(new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 20, PSSParameterSpec.TRAILER_FIELD_BC));
        customSig.initSign(rsaKp.getPrivate());
        customSig.update(h);
        byte[] sigWrongSaltLen = customSig.sign();

        Assert.assertThrows(ProtocolException.class,
                () -> RsaPss.verify(rsaKp.getPublic(), h, sigWrongSaltLen));
    }
}

