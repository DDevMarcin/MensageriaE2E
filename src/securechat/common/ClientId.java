package securechat.common;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

/**
 * Identificador imutável de 16 bytes de um cliente ({@code client_id}, {@code sender_id}
 * ou {@code recipient_id}), correspondente a um UUID v4 em ordem de bytes de rede (big-endian).
 *
 * <p>Importante: {@code byte[]} puro em Java não pode ser usado como chave de {@code Map}
 * porque herda {@code equals}/{@code hashCode} por referência de memória. Esta classe
 * implementa igualdade por conteúdo ({@link Arrays#equals}) e ordenação lexicográfica sem
 * sinal ({@link Arrays#compareUnsigned}), essencial para determinar de forma determinística
 * quem é o cliente A (menor {@code client_id}) e quem é o cliente B (maior {@code client_id})
 * na derivação de chaves E2E.</p>
 */
public final class ClientId implements Comparable<ClientId> {

    private static final HexFormat HEX = HexFormat.of();

    private final byte[] bytes;

    private ClientId(byte[] raw) {
        this.bytes = raw.clone();
    }

    /**
     * Cria um {@link ClientId} a partir de exatamente 16 bytes binários.
     *
     * @throws ProtocolException se o array for nulo ou não tiver 16 bytes.
     */
    public static ClientId fromBytes(byte[] raw) throws ProtocolException {
        if (raw == null || raw.length != Constants.CLIENT_ID_BYTES) {
            int len = raw == null ? -1 : raw.length;
            throw new ProtocolException("client_id inválido: esperado 16 bytes, recebido " + len);
        }
        return new ClientId(raw);
    }

    /**
     * Converte um {@link UUID} em {@link ClientId} (16 bytes big-endian: MSB 8B || LSB 8B).
     */
    public static ClientId fromUuid(UUID uuid) {
        Objects.requireNonNull(uuid, "uuid não pode ser nulo");
        byte[] buf = new byte[Constants.CLIENT_ID_BYTES];
        ByteBuffer.wrap(buf)
                .putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits());
        return new ClientId(buf);
    }

    /**
     * Gera um novo {@link ClientId} aleatório baseado em {@link UUID#randomUUID()} (UUID v4).
     */
    public static ClientId random() {
        return fromUuid(UUID.randomUUID());
    }

    /**
     * Devolve uma cópia defensiva dos 16 bytes deste identificador.
     */
    public byte[] toBytes() {
        return bytes.clone();
    }

    /**
     * Converte os 16 bytes de volta para {@link UUID}.
     */
    public UUID toUuid() {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        long msb = bb.getLong();
        long lsb = bb.getLong();
        return new UUID(msb, lsb);
    }

    /**
     * Retorna os primeiros 4 bytes (8 caracteres hexadecimais) para exibição curta em logs e CLI.
     */
    public String shortHex() {
        return HEX.formatHex(bytes, 0, 4);
    }

    /**
     * Retorna todos os 16 bytes (32 caracteres hexadecimais) sem separadores.
     */
    public String fullHex() {
        return HEX.formatHex(bytes);
    }

    /**
     * Verifica se este identificador corresponde ao texto informado no CLI (aceita prefixo
     * hexadecimal de pelo menos 2 caracteres, hex completo de 32 caracteres ou formato UUID).
     */
    public boolean matchesPrefix(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        String normalized = token.trim().toLowerCase().replace("-", "");
        if (normalized.length() < 2) {
            return false;
        }
        return fullHex().startsWith(normalized);
    }

    /**
     * Compara dois {@code ClientId} byte a byte como inteiros sem sinal (0..255).
     * Define a ordem canônica do protocolo: o menor {@code ClientId} assume o papel A
     * e o maior assume o papel B na derivação HKDF ({@code Key_A2B} e {@code Key_B2A}).
     */
    @Override
    public int compareTo(ClientId other) {
        Objects.requireNonNull(other, "other não pode ser nulo");
        return Arrays.compareUnsigned(this.bytes, other.bytes);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ClientId other)) {
            return false;
        }
        return Arrays.equals(this.bytes, other.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.bytes);
    }

    /**
     * Representação curta (primeiros 4 bytes em hexadecimal) segura para logs e interface.
     */
    @Override
    public String toString() {
        return shortHex();
    }
}

