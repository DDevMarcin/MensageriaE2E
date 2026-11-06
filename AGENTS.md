# AGENTS.md — Trabalho Prático 3: Mensageria Segura Multi-Cliente (E2E) — Java 21 puro

> Ponto de entrada para o agente. **Leia este arquivo inteiro e depois os arquivos de `docs/` na ordem indicada, antes de escrever qualquer código.**

## 1. Contexto
- Disciplina: Segurança da Informação — Professor: Michel Sales.
- Objetivo: aplicação de mensageria multi-cliente com criptografia ponta-a-ponta (E2E). O **servidor é apenas relay/rendezvous** e NÃO pode decifrar mensagens entre clientes.
- Garantias exigidas: confidencialidade, integridade, autenticidade do servidor, sigilo perfeito (forward secrecy) e anti-replay.
- O aluno precisará **explicar o sistema ao professor** (não só demonstrar). Por isso o código deve ser simples, legível, bem comentado, e a documentação explicativa (seção 5) é parte da entrega.

## 2. Stack (decisão fixa)
- **Java 21 puro**: somente o JDK 21 (módulo `java.base`, `java.security`, `javax.crypto`, `java.net`, `java.nio`). **Zero bibliotecas de terceiros** (nada de Bouncy Castle, JUnit, Lombok, Maven/Gradle com dependências).
- Compilação com `javac` e execução com `java`, via scripts em `scripts/` (versões `.sh` e `.bat`).
- Concorrência: sockets bloqueantes (`java.net.Socket`/`ServerSocket`) com **virtual threads** (uma por conexão).
- Testes: sem JUnit — runner de testes próprio, mínimo, em `test/` (ver `docs/06` §9).
- Cliente em linha de comando (CLI), sem GUI.
- Pacote base: `securechat` (`securechat.common`, `securechat.server`, `securechat.client`, `securechat.tools`).

## 3. Ordem de leitura
1. `docs/01-especificacao-protocolo.md` — protocolo, formatos de bytes, derivação de chaves.
2. `docs/02-estruturas-de-dados.md` — `Session` / `SessionRegistry` (servidor) e `PeerState` / `PeerTable` (cliente).
3. `docs/03-seguranca-testes-avaliacao.md` — logs, limites, testes obrigatórios, rubrica.
4. `docs/06-guia-java-21.md` — **APIs do JDK a usar, armadilhas (X25519 raw, HKDF manual, GCM, PSS) e padrões de código.**
5. `docs/07-estrutura-do-projeto.md` — estrutura de pastas/pacotes **como base flexível**, dependências entre pacotes e princípios a manter.
6. `docs/04-tasks.md` — lista de tasks. **Execute uma por vez, em ordem.**
7. `docs/05-documentacao-explicativa.md` — como criar e manter `EXPLICACAO_SISTEMA.txt`.

## 4. Regras de ouro (nunca violar)
1. O servidor **nunca** recebe, calcula ou armazena chaves E2E (`Z_AB`, `Key_A2B`, `Key_B2A`).
2. Chaves privadas (`sk_*`) **nunca** saem da memória do dono, nunca são logadas.
3. Chaves públicas X25519 trafegam como **32 bytes raw** (não X.509/DER/PEM).
4. Nonce **nunca** se repete para a mesma chave. `seq_no` só avança.
5. Rejeitar qualquer frame cuja tag GCM falhe ou cujo `seq_no <= seqRecv`; **atualizar `seqRecv` somente após a tag validar**.
6. Não invente criptografia própria: somente `KeyPairGenerator/KeyAgreement ("X25519")`, `Mac ("HmacSHA256")`, `Cipher ("AES/GCM/NoPadding")`, `Signature ("RSASSA-PSS")`, `MessageDigest ("SHA-256")`, `SecureRandom`.
7. Proibido usar `sun.*` / `jdk.internal.*`, serialização Java (`ObjectInputStream`) ou reflexão para o protocolo: o parsing é **manual**, byte a byte (`ByteBuffer`/`DataInputStream`).
8. Validar **todo tamanho antes de alocar** (`new byte[n]`): nunca confiar em tamanho vindo da rede.
9. Comparar segredos/bytes de autenticação com `MessageDigest.isEqual` (tempo constante).
10. Um `Cipher` GCM **novo por operação** (nunca reutilizar a instância com o mesmo IV).
11. Não logar: chaves, `Z`, `salt`, nonces, conteúdo de mensagens. Todo log passa por `SecureLog` (ver `docs/03`). Proibido `System.out`/`printStackTrace()` fora de `SecureLog` e do CLI.
12. Se algo na especificação for ambíguo, siga a decisão registrada em `docs/01` (seção "Decisões de projeto"). Se surgir nova ambiguidade, **registre a decisão** em `docs/01` e em `EXPLICACAO_SISTEMA.txt` — não decida em silêncio.

## 5. Documentação obrigatória (`EXPLICACAO_SISTEMA.txt`)
- Na raiz do projeto deve existir `EXPLICACAO_SISTEMA.txt` explicando todo o sistema em português simples, para o aluno apresentar oralmente.
- **Ao concluir CADA task**, antes de marcá-la como feita, atualize o `.txt` (seções afetadas + changelog no final).
- Detalhes e estrutura obrigatória em `docs/05-documentacao-explicativa.md`.

## 6. Fluxo de trabalho por task
1. Leia a task em `docs/04-tasks.md` e seus critérios de aceitação.
2. Implemente apenas o escopo da task.
3. Escreva/rode os testes da task (`scripts/test`). Tudo precisa compilar sem warnings relevantes (`javac -Xlint:all`).
4. Atualize `EXPLICACAO_SISTEMA.txt`.
5. Marque a task com `[x]` em `docs/04-tasks.md` e resuma em 3–5 linhas o que foi feito e como o aluno pode demonstrar.
6. Só então passe para a próxima.

## 7. Estrutura de pastas e pacotes
A estrutura está em `docs/07-estrutura-do-projeto.md` e é uma **base de referência, não uma regra absoluta**: pode ser adaptada quando fizer sentido, respeitando os princípios da seção 4 daquele documento (principalmente: derivação de chaves E2E só no cliente, dependências em um único sentido, criptografia isolada, logs via `SecureLog`). Toda mudança estrutural deve ser refletida no MAPA DO CÓDIGO de `EXPLICACAO_SISTEMA.txt` na mesma task.

Resumo mínimo: `src/securechat/{common,server,client,tools}`, `test/securechat`, `scripts/`, `certs/`, `docs/`.
