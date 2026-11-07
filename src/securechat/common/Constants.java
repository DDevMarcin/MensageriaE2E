package securechat.common;

/**
 * Constantes globais do protocolo de mensageria segura E2E.
 *
 * <p>Reúne em um único ponto todos os tamanhos de chaves, parâmetros criptográficos,
 * bytes de tipo de frame TCP, opcodes do canal de controle e limites máximos de
 * alocação exigidos para proteger contra exaustão de memória (DoS) e erros de framing.</p>
 */
public final class Constants {

    private Constants() {
        // Classe utilitária não instanciável.
    }

    // =========================================================================
    // Tamanhos de identificadores e primitivas criptográficas (em bytes/bits)
    // =========================================================================

    /** Tamanho binário de client_id, sender_id e recipient_id (UUID v4 = 16 bytes). */
    public static final int CLIENT_ID_BYTES = 16;

    /** Tamanho da chave pública X25519 em formato raw little-endian (RFC 7748 = 32 bytes). */
    public static final int X25519_KEY_BYTES = 32;

    /** Tamanho do segredo compartilhado Z produzido pelo X25519 (32 bytes). */
    public static final int X25519_SECRET_BYTES = 32;

    /** Tamanho do salt aleatório gerado pelo servidor no handshake de cada cliente (16 bytes). */
    public static final int SALT_BYTES = 16;

    /** Tamanho do resumo SHA-256 e do PRK do HKDF-SHA256 (32 bytes). */
    public static final int SHA256_BYTES = 32;

    /** Tamanho mínimo em bits da chave RSA do servidor para assinatura RSA-PSS. */
    public static final int RSA_MIN_BITS = 2048;

    /** Tamanho do salt do RSA-PSS em bytes (igual ao tamanho do hash SHA-256 = 32 bytes, D6). */
    public static final int PSS_SALT_BYTES = 32;

    /** Tamanho da chave simétrica AES-128 em bytes (128 bits = 16 bytes). */
    public static final int AES_KEY_BYTES = 16;

    /** Tamanho da tag de autenticação do AES-GCM em bytes (128 bits = 16 bytes). */
    public static final int GCM_TAG_BYTES = 16;

    /** Tamanho da tag de autenticação do AES-GCM em bits (128 bits). */
    public static final int GCM_TAG_BITS = 128;

    /** Tamanho total do nonce do AES-GCM (12 bytes = IV_base 4B || seq_no 8B). */
    public static final int NONCE_BYTES = 12;

    /** Tamanho do prefixo base do nonce (IV_base de 4 bytes no E2E, ou direction de 4 bytes no controle). */
    public static final int IV_BASE_BYTES = 4;

    /** Tamanho do número de sequência monotônico seq_no (inteiro de 64 bits big-endian = 8 bytes). */
    public static final int SEQ_NO_BYTES = 8;

    /** Tamanho do fingerprint truncado (SHA-256 da chave pública) para logs e conferência visual. */
    public static final int FINGERPRINT_BYTES = 8;

    // =========================================================================
    // Strings de contexto ("info") do HKDF-Expand e direção do canal de controle
    // =========================================================================

    /** Contexto HKDF-Expand para derivar a chave do canal de controle Servidor -> Cliente. */
    public static final String HKDF_INFO_S2C = "S2C";

    /** Contexto HKDF-Expand para derivar a chave E2E na direção A -> B (menor client_id -> maior). */
    public static final String HKDF_INFO_A2B = "A2B";

    /** Contexto HKDF-Expand para derivar a chave E2E na direção B -> A (maior client_id -> menor). */
    public static final String HKDF_INFO_B2A = "B2A";

    /** Prefixo fixo de 4 bytes do nonce no canal de controle Servidor -> Cliente (0x00000001). */
    public static final int CTRL_DIRECTION_S2C = 0x00000001;

    // =========================================================================
    // Framing TCP e tipos de mensagem no fio (Decisão D5)
    // =========================================================================

    /** Tamanho do prefixo big-endian que indica o comprimento do frame TCP (4 bytes). */
    public static final int FRAME_LEN_PREFIX_BYTES = 4;

    /** Tamanho do campo type no início do frame TCP (1 byte). */
    public static final int MSG_TYPE_BYTES = 1;

    /** Frame 0x01 HELLO (Cliente -> Servidor): client_id (16B) || pk_C (32B). */
    public static final byte TYPE_HELLO = 0x01;

    /** Frame 0x02 HELLO_REPLY (Servidor -> Cliente): pk_S || salt_srv || sig || cert. */
    public static final byte TYPE_HELLO_REPLY = 0x02;

    /** Frame 0x03 CONTROL (Servidor -> Cliente): seq_no (8B) || ciphertext+tag. */
    public static final byte TYPE_CONTROL = 0x03;

    /** Frame 0x04 E2E (Cliente -> Servidor -> Cliente): repassado sem alteração pelo servidor. */
    public static final byte TYPE_E2E = 0x04;

    // =========================================================================
    // Opcodes internos do canal de controle (1º byte do plaintext de TYPE_CONTROL)
    // =========================================================================

    /** Confirmação de registro do cliente após o handshake. */
    public static final byte CTRL_REGISTER_OK = 0x01;

    /** Lista dos peers ativos no momento do registro: n (2B) || n * [client_id || pk_C || salt_srv]. */
    public static final byte CTRL_PEER_LIST = 0x02;

    /** Notificação de entrada (ou reconexão) de um peer: client_id (16B) || pk_C (32B) || salt_srv (16B). */
    public static final byte CTRL_PEER_JOINED = 0x03;

    /** Notificação de saída de um peer: client_id (16B). */
    public static final byte CTRL_PEER_LEFT = 0x04;

    /** Mensagem administrativa de erro: código (1B) || texto curto UTF-8. */
    public static final byte CTRL_ERROR = 0x05;

    // =========================================================================
    // Códigos de erro do opcode CTRL_ERROR
    // =========================================================================

    /** Erro: tentativa de conexão com um client_id que já possui sessão ativa (D4). */
    public static final byte ERR_DUPLICATE_CLIENT_ID = 0x01;

    /** Erro: destinatário informado no frame E2E não está conectado. */
    public static final byte ERR_UNKNOWN_RECIPIENT = 0x02;

    /** Erro: servidor atingiu o limite máximo de clientes simultâneos. */
    public static final byte ERR_SERVER_FULL = 0x03;

    /** Erro genérico de violação de protocolo. */
    public static final byte ERR_PROTOCOL = 0x04;

    // =========================================================================
    // Limites de tamanho de mensagem e de frame TCP (proteção de memória)
    // =========================================================================

    /** Tamanho máximo permitido para o texto claro (plaintext) de uma mensagem E2E (4096 bytes). */
    public static final int MAX_PLAINTEXT = 4096;

    /**
     * Tamanho fixo do cabeçalho do payload E2E antes do ciphertext:
     * nonce (12B) + sender_id (16B) + recipient_id (16B) + seq_no (8B) = 52 bytes.
     */
    public static final int E2E_HEADER_BYTES =
            NONCE_BYTES + CLIENT_ID_BYTES + CLIENT_ID_BYTES + SEQ_NO_BYTES;

    /**
     * Tamanho exato de um frame E2E com plaintext máximo:
     * 1 (type) + 52 (cabeçalho E2E) + 4096 (plaintext) + 16 (tag GCM) = 4165 bytes.
     */
    public static final int MAX_E2E_FRAME =
            MSG_TYPE_BYTES + E2E_HEADER_BYTES + MAX_PLAINTEXT + GCM_TAG_BYTES;

    /**
     * Tamanho máximo absoluto aceito no prefixo de 4 bytes do framing TCP.
     * Derivado de MAX_E2E_FRAME (4165 B) com folga pequena (total 8192 B) para acomodar
     * também o certificado DER no HELLO_REPLY e listas de peers no canal de controle.
     * Qualquer valor <= 0 ou > MAX_FRAME causa rejeição imediata antes de alocar memória.
     */
    public static final int MAX_FRAME = 8192;

    // =========================================================================
    // Parâmetros operacionais padrão (rede, concorrência e certificados)
    // =========================================================================

    /** Porta TCP padrão do servidor. */
    public static final int DEFAULT_PORT = 8443;

    /** Timeout de leitura de socket durante o handshake (10 segundos). */
    public static final int HANDSHAKE_TIMEOUT_MS = 10_000;

    /** Limite máximo de clientes simultâneos conectados ao servidor. */
    public static final int MAX_CLIENTS = 64;

    /** Caminho padrão do certificado público DER pinado pelos clientes. */
    public static final String DEFAULT_CERT_PATH = "certs/server.crt";

    /** Caminho padrão do keystore PKCS#12 privado do servidor. */
    public static final String DEFAULT_KEYSTORE_PATH = "certs/server.p12";

    /** Nome da variável de ambiente para a senha do keystore do servidor. */
    public static final String ENV_KEYSTORE_PASS = "SERVER_KEYSTORE_PASS";

    /** Senha padrão didática do keystore caso a variável de ambiente não esteja definida. */
    public static final String DEFAULT_KEYSTORE_PASS = "changeit";

    /** Alias da entrada RSA no keystore PKCS#12 do servidor. */
    public static final String KEYSTORE_ALIAS = "server";
}

