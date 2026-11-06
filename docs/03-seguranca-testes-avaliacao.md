# 03 — Segurança, Testes e Avaliação

## 1. Garantias a entregar
| Garantia | Mecanismo | Como demonstrar |
|---|---|---|
| Confidencialidade | AES-128-GCM | Capturar tráfego (`TamperProxy` em modo "sniff"): só bytes ilegíveis; só o destinatário decifra |
| Integridade | Tag GCM (16B) | Bitflip no frame → destinatário rejeita (tag inválida) |
| Autenticidade do servidor | RSA-PSS + cert pinado | Cliente recusa servidor com outro certificado ou assinatura inválida |
| Sigilo perfeito | X25519 efêmero + descarte de `sk`/`Z` | Explicar: chaves por sessão; vazar `server.key` não revela chaves passadas |
| Anti-replay | `seq_no` monotônico | Reenviar frame antigo → rejeitado |
| Servidor cego | Chaves E2E só nos clientes | Servidor não tem `key_send/key_recv`; mostrar na `sessions` |

## 2. Testes mínimos obrigatórios (serão avaliados na apresentação)
1. **E2E básico:** ≥ 2 clientes conectados trocam mensagens nos dois sentidos; destinatário decifra corretamente.
2. **Adulteração (bitflip):** um byte do ciphertext (ou do AAD) alterado em trânsito → destinatário rejeita por falha de tag; log registra o motivo.
3. **Replay:** reenviar um frame com `seq_no` já usado → rejeitado pelo destinatário.
4. **Framing inválido:** tamanho declarado incorreto/absurdo/negativo ou truncado → erro tratado, **desconexão segura** (sem crash do servidor).
5. Extras recomendados: cert diferente do pinado → cliente aborta; assinatura corrompida → cliente aborta; `sender_id` forjado → servidor descarta; destinatário inexistente → `ERROR`; reconexão com mesmo `client_id` gera chaves novas; mensagem > 4096 bytes recusada.

Todos devem ter teste automatizado (runner próprio, `scripts/test`) **e** um script de demonstração (`scripts/demo-*` / `securechat.tools.TamperProxy`) que o aluno consiga rodar ao vivo.

## 3. Política de logs
- **Proibido registrar:** chaves privadas, segredos compartilhados (`Z`), `salt` em texto claro, nonces, conteúdo das mensagens (nem em hex).
- **Permitido:** conexão/desconexão, `client_id`, tamanhos de mensagem, razões de rejeição (ex.: `tag mismatch`, `replay`, `framing inválido`), fingerprints/hashes de chaves (SHA-256 truncado).
- Implementar em `securechat.common.SecureLog` a **única** saída de log, com métodos tipados (sem aceitar `byte[]` arbitrário). Auditar com `grep` por `System.out`, `System.err`, `printStackTrace` e `Logger` fora de `SecureLog`/`Cli`.

## 4. Limites e parâmetros
- Salt: 16 B. Nonce: 12 B (`IV_base || seq_no`). Max plaintext: 4096 B (constante em `Constants.java`).
- Tamanho máximo de frame TCP aceito: derivado do máximo (4096 + 16 tag + 12 + 16 + 16 + 8 + 1 type, com folga pequena); acima disso → erro de framing + desconexão.
- Nº de clientes concorrentes: livre, mas tratar erros de recurso (ex.: `IOException`, limite configurável `MAX_CLIENTS` com `ERROR` ao exceder).
- Timeouts de leitura no handshake com `socket.setSoTimeout(...)` (evita conexão pendurada).

## 5. Rubrica (priorize nesta ordem)
| Critério | Peso |
|---|---|
| Handshake e rendezvous E2E corretos | 30% |
| AES-GCM E2E com nonce e `seq_no` corretos | 25% |
| Proteções contra replay e tampering demonstradas | 20% |
| Código organizado, documentação e demo | 15% |
| Práticas de segurança (logs, não expor chaves) | 10% |

## 6. Checklist da apresentação
- [ ] Cada integrante fala e apresenta parte do trabalho.
- [ ] Explicar o protocolo (handshake ECDHE + RSA + HKDF e troca AES-GCM).
- [ ] Demo: iniciar servidor, conectar vários clientes, enviar mensagens.
- [ ] Validação: só o destinatário decifra.
- [ ] Explicar estrutura de dados do servidor (sessões, chaves, contadores).
- [ ] Explicar o código (handshake, derivação, criptografia, roteamento) — um trecho por aluno.
- [ ] Encerramento: resumo das garantias.
