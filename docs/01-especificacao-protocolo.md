# 01 — Especificação do Protocolo (normalizada)

## 1. Visão geral
Três papéis: **Cliente A**, **Cliente B**, **Servidor (relay)**.
O servidor autentica-se com RSA-PSS sobre o material do handshake, registra a chave pública X25519 de cada cliente e distribui as chaves públicas entre os clientes. Os clientes derivam chaves E2E entre si via ECDH + HKDF e trocam frames AES-128-GCM que o servidor apenas encaminha.

## 2. Primitivas e parâmetros
| Item | Valor |
|---|---|
| ECDHE | X25519, chaves públicas **raw de 32 bytes** |
| Assinatura do servidor | RSA-PSS (SHA-256, MGF1-SHA-256, salt de 32 B, trailer 0xBC), RSA ≥ 2048 bits, certificado autoassinado `server.crt` (DER) pinado nos clientes |
| KDF | HKDF com HMAC-SHA256 (Extract + Expand) |
| Cifra | AES-128-GCM (chave de 16 B, nonce de 12 B, tag de 16 B anexada ao fim do ciphertext) |
| `client_id` / `sender_id` / `recipient_id` | 16 bytes binários, UUID v4 (network byte order) |
| `salt_srv` | 16 bytes aleatórios gerados pelo servidor no handshake de cada cliente |
| `seq_no` | 8 bytes, inteiro 64 bits **big-endian**, monotônico por direção |
| Nonce | 12 bytes = `IV_base (4B) \|\| seq_no (8B)` |
| Framing TCP | prefixo de 4 bytes big-endian com o tamanho do que vem a seguir |
| Plaintext máximo | 4096 bytes por mensagem |

## 3. Glossário de chaves
- `sk_X` = chave privada (secreta, local, nunca enviada/logada). `pk_X` = chave pública correspondente.
- `sk_client`/`pk_client`: par X25519 efêmero, gerado a cada execução do cliente.
- `sk_server`/`pk_server`: **ver decisão D1** (par X25519 efêmero por conexão). A chave privada RSA e o certificado do servidor ficam no keystore PKCS#12 `certs/server.p12`, e o certificado público exportado em `certs/server.crt` (DER).
- `Z_AB = ECDH(sk_A, pk_B)` = segredo compartilhado (IKM do HKDF). Nunca transmitido.

## 4. Handshake cliente ↔ servidor
1. Cliente abre TCP, gera `client_id` (UUID v4) e par X25519 efêmero.
2. **Cliente → Servidor:** `client_id (16B) || pk_C (32B)`.
3. Servidor gera `salt_srv` (16B) e um par X25519 efêmero (`sk_S`, `pk_S`) para essa conexão.
4. Servidor calcula `H = SHA256(pk_S || pk_C || client_id || salt_srv)` e assina `H` com RSA-PSS(SHA-256) usando a chave privada RSA de `certs/server.p12`.
5. **Servidor → Cliente:** `pk_S (32B) || salt_srv (16B) || assinatura RSA || server.crt`.
6. Cliente valida: (a) `server.crt` recebido é **idêntico ao certificado pinado** localmente (`certs/server.crt`); (b) a assinatura RSA-PSS sobre o `H` recalculado localmente é válida. Se falhar: encerra a conexão e loga o motivo.
7. Ambos derivam `Key_S2C` (seção 5) e o servidor descarta `sk_S`. O servidor tenta registrar em `sessions` (`putIfAbsent`): `client_id`, `pk_C`, `salt_srv`, `writer`, com `seq_send = 0` e `seq_recv = -1`. Se o `client_id` já estiver ativo (D4), o servidor envia `CONTROL(ERROR)` cifrado com a `Key_S2C` dessa nova conexão e encerra o socket sem alterar a sessão existente nem notificar os demais clientes.
8. Se o registro suceder, o servidor envia mensagens de controle (ver seção 5): confirmação de registro (`REGISTER_OK`) e a lista dos **demais** peers ativos (`PEER_LIST`, contendo `client_id`, `pk_C`, `salt_srv` de cada um, excluindo o próprio cliente recém-conectado) ao novo cliente; e `PEER_JOINED` (dados do novo cliente) a todos os outros. (Por defesa em profundidade, o cliente também ignora entradas com seu próprio `client_id` ao processar `PEER_LIST`.)

Função da assinatura: provar a autenticidade do servidor e impedir MITM no registro das chaves públicas (o `H` amarra `pk_S`, `pk_C`, `client_id` e `salt`).

## 5. Canal de controle servidor → cliente (mensagens não-E2E)
Mensagens administrativas: confirmação de registro, lista de clientes, entrada/saída de cliente, erros. Precisam de ordenação e anti-replay → usam `seq_send` do servidor.
- Chave de controle: `PRK_ctrl = HKDF-Extract(salt_srv, ECDH(sk_S, pk_C))`; `Key_S2C = HKDF-Expand(PRK_ctrl, info="S2C", L=16)`.
- Nonce: `direction (4B) || seq_no (8B)` com `direction = 0x00000001` (s2c). (Alternativa prevista no enunciado.)
- AES-128-GCM com AAD = `client_id (16B) || seq_no (8B)`.
- Cliente rejeita se `seq_no <= último seq_no de controle recebido`.
- Conteúdo (plaintext cifrado), primeiro byte = opcode:
  - `0x01 REGISTER_OK`
  - `0x02 PEER_LIST`: `n (2B) || n × [client_id 16B || pk_C 32B || salt_srv 16B]`
  - `0x03 PEER_JOINED`: `client_id 16B || pk_C 32B || salt_srv 16B`
  - `0x04 PEER_LEFT`: `client_id 16B`
  - `0x05 ERROR`: `código 1B || texto curto UTF-8`

## 6. Tipos de mensagem no fio
Cada frame TCP: `[len 4B big-endian] [type 1B] [payload ...]`, onde `len` = tamanho de `type + payload`.
| type | Sentido | Payload |
|---|---|---|
| `0x01 HELLO` | C→S | `client_id 16B \|\| pk_C 32B` |
| `0x02 HELLO_REPLY` | S→C | `pk_S 32B \|\| salt_srv 16B \|\| sig_len 2B \|\| sig \|\| cert_len 2B \|\| cert (DER)` |
| `0x03 CONTROL` | S→C | `seq_no 8B \|\| ciphertext+tag` (cifrado com `Key_S2C`) |
| `0x04 E2E` | C→S→C | frame E2E (seção 8), repassado pelo servidor **sem alteração** |

## 7. Derivação das chaves E2E (entre A e B)
- Definição de ordem: **A = cliente com o menor `client_id`** (comparação byte a byte); **B = o outro**. Assim ambos concordam sobre `A2B` / `B2A`.
- `salt_par` = `salt_srv` do cliente **A** (o de menor `client_id`), recebido na lista de peers (D2).
- `Z_AB = X25519(sk_self, pk_peer)`.
- `PRK = HKDF-Extract(salt = salt_par, IKM = Z_AB)`.
- `Key_A2B = HKDF-Expand(PRK, info="A2B", L=16)`; `Key_B2A = HKDF-Expand(PRK, info="B2A", L=16)`.
- Se self é A: `key_send = Key_A2B`, `key_recv = Key_B2A`. Se self é B: `key_send = Key_B2A`, `key_recv = Key_A2B`.
- Estado inicial por par: `seq_send = 0`, `seq_recv = -1`, `IV_base_send = random(4B)`, `IV_base_recv` = definido ao receber o primeiro frame válido (D3).
- Após derivar as chaves, descartar `Z_AB` da memória (não armazenar).

## 8. Frame E2E (payload do tipo 0x04)
```
[nonce 12B][sender_id 16B][recipient_id 16B][seq_no 8B][ciphertext + tag GCM (16B)]
 nonce  = IV_base_send (4B) || seq_no (8B, big-endian)
 AAD    = sender_id || recipient_id || seq_no
```
Envio (A→B): `seq = seq_send; seq_send += 1`; monta nonce; cifra com `key_send`; envia.
Recebimento (B): lê campos; confere `recipient_id == meu client_id`; `seq_no` do nonce **igual** ao campo `seq_no`; `seq_no > seq_recv`; extrai `IV_base` do nonce (se for o primeiro frame, guarda como `IV_base_recv`; senão deve ser igual); decifra com `key_recv` e AAD; **só se a tag validar**, atualiza `seq_recv = seq_no`.
Servidor: lê `recipient_id`, confere que `sender_id` do frame == `client_id` da conexão de origem (anti-spoof), e encaminha os bytes ao `writer` do destinatário. Destinatário inexistente → mensagem de controle `ERROR`.

## 9. Encerramento e reconexão
- Cliente desconecta → servidor remove a entrada de `sessions` e envia `PEER_LEFT` aos demais; clientes removem o peer da tabela `peers`.
- Reconexão com o mesmo `client_id`: handshake completo, **novo** par X25519, **novo** `salt_srv`, `seq_no` zerado; peers re-derivam chaves ao receber `PEER_JOINED` (substituem o estado antigo). Nunca reutilizar salt ou `seq_no` anteriores.
- Se um `client_id` já estiver conectado, o servidor rejeita o novo handshake enviando `CONTROL(ERROR)` cifrado com a `Key_S2C` da conexão recusada e fecha o socket, preservando a sessão ativa intacta — D4.
- Opcional (extra): rotação de chaves após N mensagens ou T minutos.

## 10. Decisões de projeto (resolvem ambiguidades do enunciado)
- **D1 — `pk_S` é uma chave X25519 efêmera do servidor**, gerada por conexão. O enunciado fala em "assinar a chave efêmera ECDHE" e usa `pk_server` como raw bytes no `H`; a chave RSA fica só no keystore `certs/server.p12` / certificado `certs/server.crt`. Isso permite o canal de controle cifrado e garante sigilo perfeito do handshake.
- **D2 — Salt do par E2E:** como cada cliente recebe um `salt_srv` diferente, o servidor distribui o salt de cada cliente junto com sua `pk_C` e ambos usam o salt do cliente de menor `client_id`. (Salt não é segredo no HKDF.)
- **D3 — `IV_base_recv`:** o receptor aprende o `IV_base` do remetente a partir do nonce do primeiro frame válido e exige que seja o mesmo nos seguintes.
- **D4 — `client_id` duplicado ativo** é rejeitado após o `HELLO_REPLY` / derivação de `Key_S2C`, enviando `CONTROL(ERROR)` na nova conexão e encerrando-a sem afetar a sessão original.
- **D5 — Byte de tipo (`type`)** no início de cada frame TCP para distinguir handshake/controle/E2E (necessário para roteamento; não altera o formato do frame E2E em si).
- **D6 — Parâmetros RSA-PSS fixos:** hash SHA-256, MGF1 com SHA-256, salt de 32 bytes, trailer 0xBC (`PSSParameterSpec`), idênticos em servidor e cliente. O dado assinado é o `H` de 32 bytes.
- **D7 — Formato do certificado:** `server.crt` em DER; o cliente compara os bytes recebidos com o certificado pinado (igualdade exata) antes de usar a chave pública para verificar a assinatura.
- **Limitação a documentar:** o servidor distribui as `pk_C` dos peers; um servidor malicioso poderia trocá-las (MITM de chave). Mitigação opcional: exibir **fingerprint** (SHA-256 truncado) da `pk_C` do peer para verificação fora de banda.
