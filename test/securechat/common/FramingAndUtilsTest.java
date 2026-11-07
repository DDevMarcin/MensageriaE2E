package securechat.common;

import securechat.Assert;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

/**
 * Testes automatizados da T01: {@link ClientId}, {@link Bytes}, {@link Framing} e {@link SecureLog}.
 */
public final class FramingAndUtilsTest {

    private FramingAndUtilsTest() {
        // Classe de testes não instanciável.
    }

    /**
     * Verifica que um frame válido é escrito e lido de volta com tipo e payload idênticos.
     */
    public static void testFrameOk() throws Exception {
        byte[] payload = new byte[] {10, 20, 30, 40, 50};
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Framing.writeFrame(new DataOutputStream(baos), Constants.TYPE_HELLO, payload);

        byte[] rawWire = baos.toByteArray();
        // 4 bytes de len + 1 byte de type + 5 bytes de payload = 10 bytes
        Assert.assertEquals(10, rawWire.length, "Tamanho total no fio deve ser 10 bytes");

        Framing.Frame read = Framing.readFrame(new DataInputStream(new ByteArrayInputStream(rawWire)));
        Assert.assertEquals(Constants.TYPE_HELLO, read.type(), "Tipo do frame deve ser TYPE_HELLO");
        Assert.assertArrayEquals(payload, read.payload(), "Payload lido deve ser igual ao enviado");
    }

    /**
     * Verifica que um frame truncado no meio do payload (declara 20 bytes, entrega 5)
     * lança {@link FramingException} com {@code isCleanEof() == false}.
     */
    public static void testFrameTruncated() {
        byte[] wire = ByteBuffer.allocate(4 + 1 + 4)
                .putInt(20) // declara 20 bytes após o prefixo, mas só há 5
                .put(Constants.TYPE_E2E)
                .put(new byte[] {1, 2, 3, 4})
                .array();

        FramingException ex = Assert.assertThrows(
                FramingException.class,
                () -> Framing.readFrame(new DataInputStream(new ByteArrayInputStream(wire))));
        Assert.assertFalse(ex.isCleanEof(), "Truncamento no meio do frame não deve ser EOF limpo");
    }

    /**
     * Verifica que um frame com tamanho declarado 0 lança {@link FramingException}.
     */
    public static void testFrameZeroLength() {
        byte[] wire = ByteBuffer.allocate(4).putInt(0).array();
        Assert.assertThrows(
                FramingException.class,
                () -> Framing.readFrame(new DataInputStream(new ByteArrayInputStream(wire))));
    }

    /**
     * Verifica que um frame com tamanho declarado negativo lança {@link FramingException}
     * sem tentar alocar array negativo ({@code NegativeArraySizeException}).
     */
    public static void testFrameNegativeLength() {
        byte[] wire = ByteBuffer.allocate(4).putInt(-42).array();
        Assert.assertThrows(
                FramingException.class,
                () -> Framing.readFrame(new DataInputStream(new ByteArrayInputStream(wire))));
    }

    /**
     * Verifica que um frame com tamanho declarado acima de {@link Constants#MAX_FRAME}
     * lança {@link FramingException} antes de alocar memória, tantando na leitura quanto na escrita.
     */
    public static void testFrameExceedsMaxLength() {
        byte[] wire = ByteBuffer.allocate(4).putInt(Constants.MAX_FRAME + 1).array();
        Assert.assertThrows(
                FramingException.class,
                () -> Framing.readFrame(new DataInputStream(new ByteArrayInputStream(wire))));

        byte[] hugePayload = new byte[Constants.MAX_FRAME]; // +1 byte de type = MAX_FRAME + 1
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Assert.assertThrows(
                FramingException.class,
                () -> Framing.writeFrame(new DataOutputStream(baos), Constants.TYPE_E2E, hugePayload));
    }

    /**
     * Verifica que duas instâncias distintas de {@link ClientId} com os mesmos 16 bytes
     * funcionam corretamente como chave em {@link HashMap} ({@code equals} e {@code hashCode}
     * por valor, e não por referência de {@code byte[]}).
     */
    public static void testClientIdAsMapKey() throws Exception {
        byte[] raw1 = new byte[Constants.CLIENT_ID_BYTES];
        for (int i = 0; i < raw1.length; i++) {
            raw1[i] = (byte) (i + 1);
        }
        byte[] raw2 = raw1.clone();

        ClientId id1 = ClientId.fromBytes(raw1);
        ClientId id2 = ClientId.fromBytes(raw2);

        // Mutar o array externo não pode alterar o ClientId (imutabilidade)
        raw1[0] = (byte) 0xFF;

        Assert.assertEquals(id1, id2, "ClientIds com mesmos bytes devem ser iguais");
        Assert.assertEquals(id1.hashCode(), id2.hashCode(), "hashCode deve coincidir");

        Map<ClientId, String> map = new HashMap<>();
        map.put(id1, "sessao-ativa");
        Assert.assertEquals("sessao-ativa", map.get(id2), "Busca no HashMap com outra instância deve funcionar");

        // Tamanho inválido deve lançar ProtocolException
        Assert.assertThrows(ProtocolException.class, () -> ClientId.fromBytes(new byte[15]));
    }

    /**
     * Verifica a comparação lexicográfica sem sinal ({@code Arrays.compareUnsigned}):
     * um byte {@code 0x80} (128 unsigned, -128 signed) deve ser MAIOR que {@code 0x7F} (127).
     */
    public static void testClientIdUnsignedComparison() throws Exception {
        byte[] bytesLow = new byte[Constants.CLIENT_ID_BYTES];
        byte[] bytesHigh = new byte[Constants.CLIENT_ID_BYTES];
        bytesLow[0] = (byte) 0x7F;  // 127
        bytesHigh[0] = (byte) 0x80; // 128 unsigned (-128 em byte com sinal)

        ClientId low = ClientId.fromBytes(bytesLow);
        ClientId high = ClientId.fromBytes(bytesHigh);

        Assert.assertTrue(low.compareTo(high) < 0,
                "0x7F deve ser menor que 0x80 na comparação unsigned (papel A vs B)");
        Assert.assertTrue(high.compareTo(low) > 0,
                "0x80 deve ser maior que 0x7F na comparação unsigned");
        Assert.assertEquals(0, low.compareTo(ClientId.fromBytes(bytesLow.clone())),
                "IDs idênticos devem retornar 0 no compareTo");
    }

    /**
     * Verifica os utilitários de {@link Bytes} (concatenação, big-endian, wipe, fingerprint).
     */
    public static void testBytesAndFingerprint() throws Exception {
        byte[] a = new byte[] {1, 2};
        byte[] b = new byte[] {3, 4, 5};
        Assert.assertArrayEquals(new byte[] {1, 2, 3, 4, 5}, Bytes.concat(a, b));

        long seq = 0x0102030405060708L;
        byte[] seqBytes = Bytes.longToBytes(seq);
        Assert.assertEquals(seq, Bytes.bytesToLong(seqBytes, 0));

        byte[] secret = new byte[] {9, 8, 7, 6};
        Bytes.wipe(secret);
        Assert.assertArrayEquals(new byte[] {0, 0, 0, 0}, secret, "wipe deve zerar o array");

        String fp = Bytes.fingerprint(new byte[32]);
        // 8 bytes em hex separados por ':' = 8*2 + 7 = 23 caracteres
        Assert.assertEquals(23, fp.length(), "Fingerprint de 8 bytes deve ter 23 caracteres (xx:xx:...)");
    }
}

