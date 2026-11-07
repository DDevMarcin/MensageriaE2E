# SecureChat — Mensageria Multi-Cliente E2E

Implementação de um sistema de mensageria instantânea multi-cliente com criptografia ponta-a-ponta (*End-to-End Encryption*) em **Java 21 puro**, desenvolvido para a disciplina de Segurança da Informação (Prof. Michel Sales).

O servidor atua exclusivamente como *relay/rendezvous* e gerenciamento de presença, sem acesso às chaves de sessão E2E ou ao texto claro das mensagens trocadas entre os clientes.

---

## Especificações Técnicas

- **Linguagem e Runtime:** Java 21 (`java.base`, `java.security`, `javax.crypto`, `java.net`, `java.nio`), zero dependências externas.
- **Concorrência:** Sockets TCP bloqueantes com *Virtual Threads* (Project Loom) e sincronização via `ReentrantLock`.
- **Primitivas Criptográficas (JCA):**
  - **Acordo de Chaves (Forward Secrecy):** `X25519` (RFC 7748) com chaves efêmeras de 32 bytes *raw*.
  - **Derivação de Chaves:** `HKDF-SHA256` (RFC 5869) com chaves simétricas segregadas por direção (`Key_A2B`, `Key_B2A`, `Key_S2C`).
  - **Cifragem Autenticada (AEAD):** `AES-128-GCM` com nonce de 12 bytes (`IV_base || seq_no`), tag de 128 bits e metadados de cabeçalho autenticados via `AAD`.
  - **Autenticidade do Servidor:** `RSASSA-PSS` (`SHA-256`, `MGF1-SHA-256`, salt de 32 B) validado contra certificado X.509 (`DER`) fixado via *Certificate Pinning*.

---

## Estrutura do Repositório

```text
├── certs/                  # Certificado público pinado (server.crt) e keystore privado (server.p12)
├── docs/                   # Especificação do protocolo, estruturas de dados e guia de arquitetura
├── scripts/                # Scripts de automação (.sh e .bat) para build, execução, testes e demos
├── src/securechat/
│   ├── common/             # Framing TCP, empacotamento binário, wrappers criptográficos e SecureLog
│   ├── server/             # Servidor relay, handshake e registro concorrente de sessões
│   ├── client/             # Cliente E2E, tabela de peers, derivação de chaves e interface CLI
│   └── tools/              # Proxy de inspeção/adulteração (TamperProxy) e runner de demonstrações
├── test/securechat/        # Suíte de 43 testes automatizados e runner próprio (sem JUnit)
├── EXPLICACAO_SISTEMA.txt  # Documentação técnica detalhada e roteiro de apresentação
└── TUTORIAL_TESTES_MANUAIS.md # Guia passo a passo para execução manual dos cenários de teste
```

---

## Pré-requisitos

- **JDK 21** configurado no `PATH` (`java`, `javac` e `keytool`).

---

## Build, Testes e Execução

| Ação | Linux / macOS | Windows |
|---|---|---|
| **Gerar certificado do servidor** | `./scripts/gen-cert.sh` | `.\scripts\gen-cert.bat` |
| **Compilar projeto** | `./scripts/build.sh` | `.\scripts\build.bat` |
| **Executar suíte de testes** | `./scripts/test.sh` | `.\scripts\test.bat` |
| **Iniciar servidor** | `./scripts/run-server.sh [porta]` | `.\scripts\run-server.bat [porta]` |
| **Iniciar cliente (CLI)** | `./scripts/run-client.sh [host] [porta]` | `.\scripts\run-client.bat [host] [porta]` |

### Scripts de Demonstração Automatizada

| Cenário | Linux / macOS | Windows |
|---|---|---|
| **Executar todos os cenários** | `./scripts/demo-all.sh` | `.\scripts\demo-all.bat` |
| **Mensageria E2E + Sniff** | `./scripts/demo-e2e.sh` | `.\scripts\demo-e2e.bat` |
| **Adulteração de Ciphertext (Bitflip)** | `./scripts/demo-bitflip.sh` | `.\scripts\demo-bitflip.bat` |
| **Ataque de Repetição (Replay)** | `./scripts/demo-replay.sh` | `.\scripts\demo-replay.bat` |
| **Framing TCP Inválido (Badframe)** | `./scripts/demo-badframe.sh` | `.\scripts\demo-badframe.bat` |

---

## Documentação Complementar

- [EXPLICACAO_SISTEMA.txt](EXPLICACAO_SISTEMA.txt) — Detalhamento do protocolo binário, derivação de chaves, decisões de projeto (D1–D7), mapa do código e perguntas frequentes.
- [TUTORIAL_TESTES_MANUAIS.md](TUTORIAL_TESTES_MANUAIS.md) — Instruções passo a passo para testar manualmente cada cenário em terminais separados e utilizar o `TamperProxy`.
- [docs/01-especificacao-protocolo.md](docs/01-especificacao-protocolo.md) — Especificação formal do protocolo e formatos de mensagens.
