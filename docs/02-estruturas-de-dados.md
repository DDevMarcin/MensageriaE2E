# 02 — Estruturas de Dados (Java 21)

## Tipos auxiliares
- `ClientId`: classe `final` imutável que embrulha `byte[16]`. Implementa `equals`/`hashCode` com `Arrays.equals`/`Arrays.hashCode`, `compareTo` com `Arrays.compareUnsigned`, `toString()` curto (primeiros bytes em hex, via `HexFormat`). **Não usar `byte[]` como chave de `Map`** (compara por referência).
- `seq_no`: `long`. Faixa válida `0 .. Long.MAX_VALUE`. Ao ler do fio com `ByteBuffer.getLong()`, valor negativo é **inválido** (rejeitar). Quando `seqSend` chegar em `Long.MAX_VALUE`, recusar novo envio (e, opcionalmente, forçar re-handshake).

## Servidor — `SessionRegistry` e `Session`
```java
final class Session {
    final ClientId clientId;
    final Socket socket;
    final DataOutputStream out;          // escrita SEMPRE sob writeLock
    final ReentrantLock writeLock;       // várias threads escrevem neste socket (relay)
    final byte[] publicKey;              // pk_C, 32 B raw X25519
    final byte[] salt;                   // salt_srv, 16 B
    final byte[] keyCtrl;                // Key_S2C, 16 B — canal de CONTROLE; NÃO é chave E2E
    long seqRecv = -1;                   // último seq_no recebido do cliente (init -1)
    long seqSend = 0;                    // próximo seq_no de mensagens de CONTROLE do servidor (init 0)
}

final class SessionRegistry {
    private final ConcurrentHashMap<ClientId, Session> sessions = new ConcurrentHashMap<>();
    // register (putIfAbsent -> rejeita client_id duplicado ativo), remove, get, snapshot()
}
```
- `seqSend` existe porque o servidor envia mensagens administrativas (registro, lista de clientes, saída de cliente, erros) que precisam de ordenação e anti-replay. **Não interfere no E2E** entre clientes.
- `seqRecv` do servidor: mantido na estrutura `Session` (inicializado em `-1`) por compatibilidade com o modelo de dados do enunciado, mas **o servidor não bloqueia frames E2E usando um `seqRecv` único por sessão**, pois no cliente o `seq_no` E2E é independente por par `(remetente, destinatário)`. A verificação obrigatória de anti-replay (`seq_no > seqRecv`) é feita pelo cliente destinatário em `PeerState.seqRecv`.
- Incrementar `seqSend` e escrever o frame de controle **dentro do mesmo `writeLock`** (garante que a ordem de `seq_no` no fio == ordem de escrita).
- Remover a entrada ao desconectar (bloco `finally` do `ClientConnection`, somente se a conexão era a dona registrada da sessão), fechar o socket e notificar `PEER_LEFT`.
- A chave privada X25519 efêmera do servidor (`sk_S`) é descartada logo após derivar `keyCtrl`.

## Cliente — `PeerTable` e `PeerState`
```java
final class PeerState {
    final ClientId peerId;
    final byte[] publicKey;              // pk do peer, 32 B raw
    final byte[] salt;                   // salt do par (D2), 16 B
    final byte[] keySend;                // 16 B — A2B se eu tenho o menor client_id, senão B2A
    final byte[] keyRecv;                // 16 B
    final byte[] ivBaseSend;             // 4 B aleatórios (SecureRandom)
    byte[] ivBaseRecv = null;            // 4 B — aprendido no 1º frame válido (D3)
    long seqSend = 0;                    // próximo seq_no a enviar
    long seqRecv = -1;                   // último seq_no aceito (anti-replay)
    // Z_AB: NÃO armazenar (usar local, zerar com Arrays.fill após derivar)
    // métodos sob lock do próprio PeerState: nextSendSeq(), acceptRecvSeq(seq)
}

final class PeerTable {
    private final ConcurrentHashMap<ClientId, PeerState> peers = new ConcurrentHashMap<>();
}
```
Estado adicional do cliente: `ClientId self`, `PrivateKey skClient` (só memória), `byte[] pkClient`, `X509Certificate certPinado`, `byte[] keyCtrl` (S2C), `long ctrlSeqRecv = -1`.

## Regras de concorrência
- **Uma thread de leitura por conexão** (servidor: uma por cliente; cliente: uma para o socket do servidor) + a thread do CLI (stdin).
- Escrita em socket: sempre sob `ReentrantLock` (não usar `synchronized` envolvendo I/O: em Java 21 isso "fixa" (pin) a virtual thread no carrier).
- Tabelas em `ConcurrentHashMap`; operações compostas (substituir peer em reconexão) via `put`/`compute` atômicos.

## Regras de consistência
- Entrada em `PeerTable` criada ao receber `PEER_LIST` / `PEER_JOINED`; removida em `PEER_LEFT`.
- `PEER_JOINED` de um `client_id` já existente = reconexão → **substituir** o `PeerState` inteiro (novas chaves, contadores zerados).
- `seqSend` só incrementa **depois** de montar o frame com sucesso; nunca decrementa.
- `seqRecv` só atualiza depois da tag GCM validar.
