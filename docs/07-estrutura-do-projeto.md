# 07 — Estrutura do Projeto (base de referência)

> **Isto é um ponto de partida, não uma regra absoluta.** A estrutura abaixo foi pensada para deixar o código fácil de explicar ao professor e dividir entre os integrantes. Se durante o desenvolvimento algo ficar mais claro de outra forma (mais ou menos classes, outro nome, outro pacote), **adapte** — desde que siga os "Princípios que valem mesmo ao adaptar" (seção 4) e registre a mudança (seção 5).

## 1. Árvore base
```
trabalho-pratico-3/
├── AGENTS.md                        # regras para o agente (lido automaticamente pelo Antigravity)
├── EXPLICACAO_SISTEMA.txt           # explicação do sistema, mantida pelo agente
├── README.md                        # como compilar, gerar cert, rodar, demo
├── .gitignore                       # out/, certs/server.p12
├── .agents/rules/                   # OPCIONAL: regras curtas por tema (ver seção 6)
├── docs/                            # instruções e especificação (lidas sob demanda)
│   ├── 01-especificacao-protocolo.md
│   ├── 02-estruturas-de-dados.md
│   ├── 03-seguranca-testes-avaliacao.md
│   ├── 04-tasks.md
│   ├── 05-documentacao-explicativa.md
│   ├── 06-guia-java-21.md
│   └── 07-estrutura-do-projeto.md   # este arquivo
├── scripts/                         # build, test, gen-cert, run-server, run-client, demo-* (.sh e .bat)
├── certs/
│   ├── server.crt                   # público (DER), pinado nos clientes
│   └── server.p12                   # PRIVADO (PKCS12) — fora do Git
├── src/
│   └── securechat/                  # pacote base
│       ├── common/                  # package securechat.common
│       ├── server/                  # package securechat.server
│       ├── client/                  # package securechat.client
│       └── tools/                   # package securechat.tools
├── test/
│   └── securechat/                  # espelha os pacotes de src/
└── out/                             # saída do javac (gerada, fora do Git)
```
Em Java, **pacote = pasta**: `src/securechat/common/Hkdf.java` começa com `package securechat.common;`. Arquivos `.md`/`.txt` não pertencem a pacotes e ficam fora de `src/`.

## 2. Pacotes e classes sugeridas
| Pacote | Responsabilidade | Classes sugeridas | Task |
|---|---|---|---|
| `securechat.common` | Tudo que cliente **e** servidor usam: constantes, bytes, framing, primitivas criptográficas, certificados, formato das mensagens, log | `Constants`, `ClientId`, `Bytes`, `Framing`, `FramingException`, `ProtocolException`, `X25519Util`, `Hkdf`, `AesGcm`, `RsaPss`, `CertUtil`, `Messages`, `SecureLog` | T01, T02, T03, T04 |
| `securechat.server` | Aceitar conexões, handshake do lado servidor, registrar sessões, rotear frames, canal de controle | `Server`, `ServerHandshake`, `ClientConnection`, `Session`, `SessionRegistry` | T03, T05, T06 |
| `securechat.client` | Handshake do lado cliente, tabela de peers, derivação E2E, envio/recebimento, CLI | `Client`, `ClientHandshake`, `PeerState`, `PeerTable`, `Cli` | T05, T07, T08 |
| `securechat.tools` | Utilitários de demonstração e teste (não fazem parte do protocolo) | `TamperProxy`, `DemoScenarioRunner` | T09, T11 |
| `test/securechat` | Testes automatizados e runner próprio | `TestRunner`, `Assert`, `...Test` por classe | todas |

## 3. Direção das dependências (quem pode usar quem)
```
tools ──► common ◄── server
              ▲
              └────── client
```
- `server` e `client` usam `common`; **nunca um ao outro**.
- `common` **não** importa `server`, `client` nem `tools`.
- `tools` pode usar `common` (e iniciar `Server`/`Client` em scripts), mas o protocolo não depende dele.
- Motivo (bom para explicar ao professor): a separação deixa visível que o servidor é só um relay e não participa da criptografia E2E.

## 4. Princípios que valem mesmo ao adaptar
Estes sim são importantes; a estrutura pode mudar, estes pontos não:
1. **Código de derivação das chaves E2E (`Key_A2B`/`Key_B2A`) mora no lado cliente** (`client`), e o pacote `server` não deve chamar nada que derive ou guarde chaves E2E.
2. **Dependências sempre em um sentido** (seção 3): sem ciclos entre pacotes.
3. **Uma classe, uma responsabilidade clara**, explicável em uma frase. Se uma classe passa de ~300 linhas ou mistura rede com criptografia, divida.
4. **Criptografia isolada** (`X25519Util`, `Hkdf`, `AesGcm`, `RsaPss`): nada de chamar `Cipher`/`Signature` direto espalhado pelo código.
5. **Tudo que sai em log passa por `SecureLog`.**
6. **Testes espelham os pacotes** de `src/` para facilitar achar o teste de cada classe.
7. Sem bibliotecas externas e sem `sun.*`/`jdk.internal.*` (regras do `AGENTS.md`).

## 5. Quando adaptar — e como registrar
Adapte sem cerimônia quando fizer sentido, por exemplo:
- Dividir `Messages` em classes menores (`HelloMessage`, `E2eFrame`, `ControlMessage`) se ficar grande.
- Criar um pacote `securechat.protocol` (formatos e opcodes) separado de `securechat.common`.
- Unir `ServerHandshake` dentro de `ClientConnection` se o handshake for curto.
- Renomear classes para termos que o grupo explique melhor.
- Adicionar `securechat.client.ui` ou outro pacote para organizar o CLI.

Ao mudar, o agente deve, **na mesma task**:
1. Atualizar o **MAPA DO CÓDIGO** (seção 10) de `EXPLICACAO_SISTEMA.txt` com as classes reais.
2. Se a mudança for estrutural (novo pacote, dependência diferente), registrar uma linha no CHANGELOG do `.txt` e **ajustar a seção 1 ou 2 deste documento** para refletir o que existe de fato.
3. Conferir que os princípios da seção 4 continuam valendo.

Não é preciso pedir permissão ao aluno para mudanças pequenas de organização; mudanças que quebrem um princípio da seção 4 devem ser **avisadas e justificadas** antes.

## 6. Onde ficam os `.md` (Antigravity)
- `AGENTS.md` (ou `GEMINI.md`) na **raiz**: lido automaticamente.
- `.agents/rules/*.md` (nome antigo `.agent/rules/` também aceito): regras adicionais carregadas automaticamente. Opcional neste projeto; use só se o grupo quiser separar regras curtas por tema.
- `docs/`: especificação e tasks, **lidas sob demanda** porque o `AGENTS.md` manda o agente lê-las.
- Mantenha regras automáticas curtas (há relato de limite de ~12.000 caracteres por arquivo de regra); conteúdo longo fica em `docs/`.

## 7. Convenções de nomes
- Classes em `PascalCase`, métodos/variáveis em `camelCase`, constantes em `UPPER_SNAKE_CASE`.
- Nomes de código em inglês; **comentários e Javadoc em português**, explicando o "porquê" criptográfico.
- Classes de teste: `<Classe>Test` no mesmo pacote espelhado em `test/`.
- Scripts: `kebab-case` (`run-server`, `gen-cert`), com `.sh` e `.bat`.
