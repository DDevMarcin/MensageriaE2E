# 04 — Tasks de Desenvolvimento (Java 21 puro)

> Execute **em ordem**, uma por vez. Ao terminar cada task: compila com `-Xlint:all` → testes passando (`scripts/test`) → atualizar `EXPLICACAO_SISTEMA.txt` → marcar `[x]`.
> Consulte `docs/06-guia-java-21.md` antes de T02.
> Sugestão de divisão entre integrantes para a apresentação: T02–T05 (handshake e cripto), T06–T07 (servidor e derivação), T08 (mensageria), T09–T10 (testes de segurança e logs).

- [ ] **T00 — Setup do projeto**
  - Criar estrutura de pastas (ver `AGENTS.md` §7), `.gitignore` (`out/`, `certs/server.p12`), `README.md` básico.
  - Scripts `scripts/build`, `scripts/test`, `scripts/run-server`, `scripts/run-client`, `scripts/gen-cert` (versões `.sh` e `.bat`). `build` usa `javac -Xlint:all --release 21 -d out`.
  - `securechat.common.Constants` com todos os tamanhos, tipos de mensagem, opcodes e limites (inclusive `MAX_PLAINTEXT = 4096`, `MAX_FRAME`).
  - Runner de testes próprio (`TestRunner`, `Assert`) conforme `docs/06` §9, com 1 teste trivial.
  - Esqueleto de `EXPLICACAO_SISTEMA.txt` com todas as seções (ver `docs/05`) e changelog.
  - *Aceite:* `java -version` é 21; `scripts/build` compila; `scripts/test` roda e retorna 0; `.txt` existe com seções "a preencher".

- [ ] **T01 — Utilitários, framing e logger seguro**
  - `ClientId`, `Bytes` (concat, big-endian, hex curto, fingerprint), `Framing` (`send`/`read` com prefixo de 4 B big-endian, limite máximo, `readFully`, EOF/truncamento), `FramingException`, `ProtocolException`.
  - `SecureLog`: métodos tipados (`connected(clientId)`, `disconnected(clientId)`, `rejected(clientId, motivo, tamanho)`, `info(...)`), **sem** API que aceite bytes arbitrários; helper `fingerprint`.
  - *Aceite:* testes: frame ok; truncado; tamanho 0; tamanho negativo; tamanho acima do máximo → `FramingException`; `ClientId` como chave de `HashMap`; comparação unsigned.

- [ ] **T02 — Primitivas criptográficas (wrappers do JDK)**
  - `X25519Util` (par, raw 32 B ↔ JCA com little-endian, ECDH, rejeita Z zero), `Hkdf` (extract/expand manual), `AesGcm` (Cipher novo por operação, AAD, nonce), `RsaPss` (parâmetros fixos D6), `Messages.handshakeHash(pkS, pkC, clientId, salt)` ou helper equivalente.
  - *Aceite:* testes: vetores **RFC 7748 §6.1** (X25519) e **RFC 5869 A.1** (HKDF); ECDH simétrico; AES-GCM round-trip e falha (`AEADBadTagException`) com 1 bit alterado no ciphertext, na tag e no AAD; RSA-PSS válido/inválido/parâmetros trocados falham.

- [ ] **T03 — Certificado autoassinado e identidade do servidor**
  - `scripts/gen-cert` com `keytool` (ver `docs/06` §5): gera `certs/server.p12` e exporta `certs/server.crt` (DER). Classes/métodos para carregar `PrivateKey`+cert DER no servidor e o cert pinado no cliente.
  - *Aceite:* scripts geram os arquivos; teste carrega chave e cert, assina com a chave e verifica com `cert.getPublicKey()`; `server.p12` está no `.gitignore`.

- [ ] **T04 — Protocolo: empacotamento de mensagens**
  - `Messages`: pack/unpack de `HELLO`, `HELLO_REPLY`, `CONTROL` (+ opcodes internos: `REGISTER_OK`, `PEER_LIST`, `PEER_JOINED`, `PEER_LEFT`, `ERROR`) e `E2E` (12+16+16+8+ct). Construção dos nonces (`IV_base||seq_no` e `direction||seq_no`).
  - *Aceite:* testes de round-trip de todos os formatos; entradas truncadas/malformadas/campos de tamanho inconsistentes → `ProtocolException` (sem `IndexOutOfBounds`/`BufferUnderflow` vazando).

- [ ] **T05 — Handshake (servidor e cliente)**
  - `ServerHandshake` e `ClientHandshake` conforme `docs/01` §4: HELLO → HELLO_REPLY assinado; cliente valida cert pinado e assinatura; derivação de `Key_S2C` nos dois lados; timeouts via `setSoTimeout`.
  - *Aceite:* teste de integração: handshake ok; cert diferente → cliente aborta; assinatura adulterada → cliente aborta; `H` com `client_id` trocado → falha; timeout tratado.

- [ ] **T06 — Servidor: registro, sessions e controle**
  - `Session`, `SessionRegistry`, `ClientConnection`, `Server` (virtual threads). Após handshake: registrar, enviar `REGISTER_OK` + `PEER_LIST` ao novo cliente, `PEER_JOINED` aos demais, `PEER_LEFT` na saída, `ERROR` quando cabível; controle cifrado com `Key_S2C` e `seqSend` sob `writeLock`.
  - Rejeitar `client_id` duplicado ativo; `MAX_CLIENTS` (`Semaphore`); limpeza em `finally`.
  - *Aceite:* 3 clientes (de teste, em threads) conectam/desconectam e as notificações chegam corretas e na ordem; logs conforme política.

- [ ] **T07 — Cliente: peers e derivação E2E**
  - `Client`, `PeerState`, `PeerTable`: ao receber `PEER_LIST`/`PEER_JOINED`, derivar `keySend/keyRecv` (ordem A/B e salt do par em `docs/01` §7), inicializar contadores/IVs, zerar `Z_AB`. Tratar `PEER_LEFT` e reconexão (substituir estado). Validar `seq_no` do canal de controle (anti-replay).
  - *Aceite:* testes: A e B derivam **as mesmas** chaves cruzadas (`A.keySend == B.keyRecv` e vice-versa); reconexão do mesmo `client_id` gera chaves diferentes; controle repetido (replay) é rejeitado.

- [ ] **T08 — Mensageria E2E (envio, relay e recebimento)**
  - `Cli` (`/peers`, `/msg <id|prefixo> <texto>`, `/quit`), envio (limite 4096 B, `seqSend`, nonce, AAD, AES-GCM), recebimento com as validações da seção 8 de `docs/01` (`seqRecv` só atualiza após tag válida; `IV_base_recv` D3). Servidor: roteamento por `recipient_id`, checagem de `sender_id`, **sem decifrar**.
  - *Aceite:* A↔B trocam mensagens nos dois sentidos; mensagem > 4096 B recusada no cliente; destinatário inexistente → `ERROR` exibido ao remetente; o servidor não possui nenhuma chave E2E (revisão do código).

- [ ] **T09 — Testes de segurança (os obrigatórios do professor)**
  - `securechat.tools.TamperProxy`: proxy TCP entre cliente e servidor com modos `sniff` (mostra tamanhos/bytes cifrados, nunca o conteúdo), `bitflip`, `replay` (reenvia o último frame E2E), `badframe` (tamanho inválido).
  - Testes automatizados: bitflip → rejeição por tag; replay → rejeição; framing inválido → desconexão segura sem derrubar o servidor; `sender_id` forjado descartado; reconexão.
  - *Aceite:* todos os testes mínimos de `docs/03` §2 passam; cada um tem comando de demo documentado no `README.md`.

- [ ] **T10 — Robustez e política de logs**
  - Revisar tratamento de erros (conexão caindo, EOF, exceções no handshake, limite de recursos, `RuntimeException` não tratada em thread). Auditar logs: nenhum segredo/nonce/salt/conteúdo; `grep` por `System.out`, `printStackTrace`, `System.err` fora de `SecureLog`/`Cli`.
  - Opcional: fingerprint da `pk` do peer no CLI; rotação de chaves por N mensagens/T minutos.
  - *Aceite:* auditoria limpa; servidor sobrevive a cliente malicioso/mal-formado (teste com bytes aleatórios no socket).

- [ ] **T11 — Demo e README**
  - Scripts de demo (`scripts/demo-*`) que sobem servidor, 2–3 clientes e rodam cada cenário (E2E, bitflip, replay, framing inválido). `README.md`: requisitos (JDK 21), `gen-cert`, build, rodar servidor/clientes/testes.
  - *Aceite:* seguindo só o README, alguém roda a demo completa do zero.

- [ ] **T12 — Fechamento da documentação explicativa**
  - Revisão completa de `EXPLICACAO_SISTEMA.txt`: mapa do código (classe → métodos → parte do protocolo), roteiro de apresentação, perguntas prováveis com respostas, decisões D1–D7 e limitações (inclui: `PrivateKey` do JCA não é zerável).
  - Conferir se tudo que está no `.txt` bate com o código real (nomes de classes/métodos).
  - *Aceite:* `.txt` coerente com o código, em linguagem simples, pronto para ser usado como roteiro de fala.
