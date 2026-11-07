# Tutorial Passo a Passo — Como Testar Manualmente Cada Situação de Estudo

Este guia mostra como reproduzir **manualmente**, em terminais separados, cada uma das situações exigidas pelo professor na apresentação do **Trabalho Prático 3 (Mensageria Segura Multi-Cliente E2E)**.

> **Dica:** Abra todos os terminais na pasta raiz do projeto (`c:\Users\marci\IdeaProjects\MensageriaE2E`).
> Nos exemplos abaixo usamos os comandos de **Windows (PowerShell / CMD)**; no Linux/macOS basta trocar `.\scripts\...bat` por `./scripts/...sh`.

---

## 0. Preparação Inicial (Executar 1 vez antes de começar)

No primeiro terminal, gere o certificado do servidor (caso ainda não exista) e compile o projeto:

```powershell
.\scripts\gen-cert.bat
.\scripts\build.bat
```

---

## Situação 1 — Conversa E2E Normal (Multi-Cliente) + Fingerprints e Servidor Cego

**Objetivo:** Demonstrar 3 clientes (Alice, Bob e Carol) conectando ao servidor, conferindo os fingerprints SHA-256 das chaves públicas X25519 (`/peers`) e trocando mensagens cifradas ponta-a-ponta (`/msg`) nos dois sentidos.

### Passo a passo:
1. **Terminal 1 (Servidor):**
   ```powershell
   .\scripts\run-server.bat
   ```
   *O que observar:* `Servidor iniciado na porta 8443`.

2. **Terminal 2 (Cliente A — Alice):**
   ```powershell
   .\scripts\run-client.bat
   ```
   *O que observar:* O banner exibe `Meu client_id : <id_curto_A>` (ex.: `64d05d6c`) e `Meu pk_fp : <hash_8_bytes>`.

3. **Terminal 3 (Cliente B — Bob):**
   ```powershell
   .\scripts\run-client.bat
   ```
   *O que observar:*
   - No **Terminal 2 (Alice)** aparece na hora: `[EVENTO] Peer entrou: <id_curto_B> (...)` (notificação `PEER_JOINED` enviada pelo servidor no canal de controle cifrado com `Key_S2C`).

4. **Terminal 4 (Cliente C — Carol):**
   ```powershell
   .\scripts\run-client.bat
   ```
   *O que observar:* Alice e Bob recebem `[EVENTO] Peer entrou: <id_curto_C>`.

5. **Conferir a tabela de peers e os contadores (`seqSend` / `seqRecv`):**
   No **Terminal 2 (Alice)** e no **Terminal 3 (Bob)**, digite:
   ```text
   /peers
   ```
   *O que explicar ao professor:*
   - Compare o `pk_fp` de Bob listado na tela de Alice com o `Meu pk_fp` impresso no banner de Bob: são idênticos (mitigação contra MITM na distribuição de chaves).
   - Note que `seqSend=0` e `seqRecv=-1` antes da primeira mensagem.

6. **Enviar mensagens E2E entre os clientes:**
   - No **Terminal 2 (Alice)**, digite os 4 primeiros caracteres do ID de Bob:
     ```text
     /msg <prefixo_do_Bob> Ola Bob! Mensagem cifrada ponta-a-ponta com AES-128-GCM!
     ```
   - No **Terminal 3 (Bob)**, veja a mensagem decifrada (`[MSG de <id_Alice>]: Ola Bob!...`) e responda:
     ```text
     /msg <prefixo_da_Alice> Oi Alice! Recebido com integridade validada!
     ```
   - Digite `/peers` novamente nos dois terminais: veja que `seqSend` subiu para `1` e `seqRecv` subiu para `0`.
   - Olhe o **Terminal 1 (Servidor)**: ele só registra `Relay E2E: de=... para=... tam=...B` — ele jamais vê o texto claro nem possui `Key_A2B` ou `Key_B2A`.

---

## Situação 2 — Confidencialidade no Fio (`TamperProxy` em modo `sniff`)

**Objetivo:** Provar que um interceptador na rede (ou o próprio servidor) só enxerga metadados de roteamento e ciphertext de alta entropia, nunca o conteúdo da mensagem.

### Passo a passo:
1. **Terminal 1 (Servidor na porta 8443):**
   ```powershell
   .\scripts\run-server.bat
   ```
2. **Terminal 2 (`TamperProxy` em modo `sniff` na porta 9443 -> repassando para 8443):**
   ```powershell
   java -cp out securechat.tools.TamperProxy --listen 9443 --target 127.0.0.1:8443 --mode sniff
   ```
3. **Terminal 3 (Alice conectada no Proxy — porta 9443):**
   ```powershell
   .\scripts\run-client.bat 127.0.0.1 9443
   ```
4. **Terminal 4 (Bob conectado direto no Servidor — porta 8443):**
   ```powershell
   .\scripts\run-client.bat 127.0.0.1 8443
   ```
5. No **Terminal 3 (Alice)**, envie uma mensagem para Bob:
   ```text
   /msg <prefixo_do_Bob> Segredo confidencial 12345
   ```
6. *O que observar:*
   - No **Terminal 2 (`TamperProxy`)**: aparece `[TamperProxy SNIFF] Frame E2E de=... para=... seq=0 ct_len=42B ct_sha256_fp=...`.
   - No **Terminal 4 (Bob)**: Bob decifra normalmente `"Segredo confidencial 12345"`.

---

## Situação 3 — Integridade / Adulteração de 1 bit (`TamperProxy` em modo `bitflip`)

**Objetivo:** Demonstrar que a alteração de 1 único bit no ciphertext/tag em trânsito faz o destinatário rejeitar o frame por falha na tag GCM (`AEADBadTagException`), **sem avançar `seqRecv`**, de modo que a próxima mensagem legítima continua funcionando.

### Passo a passo:
1. **Terminal 1 (Servidor na porta 8443):**
   ```powershell
   .\scripts\run-server.bat
   ```
2. **Terminal 2 (`TamperProxy` em modo `bitflip` com `--once` na porta 9443):**
   *(A flag `--once` adultera apenas a 1ª mensagem E2E e deixa as seguintes passarem intactas, ideal para demonstrar a recuperação do `seqRecv`!)*
   ```powershell
   java -cp out securechat.tools.TamperProxy --listen 9443 --target 127.0.0.1:8443 --mode bitflip --once
   ```
3. **Terminal 3 (Alice no Proxy — porta 9443):**
   ```powershell
   .\scripts\run-client.bat 127.0.0.1 9443
   ```
4. **Terminal 4 (Bob no Servidor — porta 8443):**
   ```powershell
   .\scripts\run-client.bat 127.0.0.1 8443
   ```
5. **1º envio (será adulterado pelo Proxy):**
   No **Terminal 3 (Alice)**:
   ```text
   /msg <prefixo_do_Bob> Transferir R$ 100,00
   ```
   *O que observar:*
   - No **Terminal 2 (`TamperProxy`)**: `[TamperProxy BITFLIP] 1 bit invertido no byte 52 do payload E2E`.
   - No **Terminal 4 (Bob)**: `[WARN] Rejeitado: id=... motivo="tag mismatch: falha de integridade/autenticidade no AES-GCM"`. Nenhuma mensagem é exibida ao usuário!
   - Digite `/peers` no **Terminal 4 (Bob)**: veja que `seqRecv` continua em **`-1`** (Regra de Ouro 5: `seqRecv` só atualiza se a tag GCM validar).

6. **2º envio (passará sem adulteração):**
   No **Terminal 3 (Alice)**:
   ```text
   /msg <prefixo_do_Bob> Segunda mensagem integra!
   ```
   *O que observar:*
   - No **Terminal 4 (Bob)**: Bob recebe e decifra `[MSG de ...]: Segunda mensagem integra!` (`seq=1 > seqRecv=-1`) e seu `seqRecv` atualiza para `1`.

---

## Situação 4 — Proteção Anti-Replay (`TamperProxy` em modo `replay`)

**Objetivo:** Demonstrar que, se um atacante capturar um frame E2E legítimo e reenviá-lo na rede, o destinatário aceita o original e descarta a cópia duplicada porque `seq_no <= seqRecv`.

### Passo a passo:
1. **Terminal 1 (Servidor na porta 8443):**
   ```powershell
   .\scripts\run-server.bat
   ```
2. **Terminal 2 (`TamperProxy` em modo `replay` com `--once` na porta 9443):**
   ```powershell
   java -cp out securechat.tools.TamperProxy --listen 9443 --target 127.0.0.1:8443 --mode replay --once
   ```
3. **Terminal 3 (Alice no Proxy — porta 9443):**
   ```powershell
   .\scripts\run-client.bat 127.0.0.1 9443
   ```
4. **Terminal 4 (Bob no Servidor — porta 8443):**
   ```powershell
   .\scripts\run-client.bat 127.0.0.1 8443
   ```
5. No **Terminal 3 (Alice)**, envie **uma única vez**:
   ```text
   /msg <prefixo_do_Bob> Autorizo pagamento unico
   ```
6. *O que observar:*
   - No **Terminal 2 (`TamperProxy`)**: `[TamperProxy REPLAY] Reenviando cópia idêntica do frame E2E`.
   - No **Terminal 4 (Bob)**:
     1. A 1ª cópia (`seq=0`) é decifrada e exibida: `[MSG de ...]: Autorizo pagamento unico` (e `seqRecv` passa a ser `0`).
     2. Milissegundos depois, a 2ª cópia (`seq=0`) chega e é bloqueada: `[WARN] Rejeitado: id=... motivo="replay detectado: seq_no recebido (0) <= último seq_no aceito (0)"`.

---

## Situação 5 — Framing Inválido e Sobrevivência do Servidor (`TamperProxy` em modo `badframe`)

**Objetivo:** Demonstrar que quando um cliente/atacante envia um prefixo de tamanho de frame inválido (`-42` ou acima de `MAX_FRAME`), o servidor valida o tamanho **antes de alocar memória**, desconecta apenas o infrator e mantém os demais clientes conversando normalmente.

### Passo a passo:
1. **Terminal 1 (Servidor na porta 8443):**
   ```powershell
   .\scripts\run-server.bat
   ```
2. **Terminal 2 (`TamperProxy` em modo `badframe` na porta 9443):**
   ```powershell
   java -cp out securechat.tools.TamperProxy --listen 9443 --target 127.0.0.1:8443 --mode badframe
   ```
3. **Terminal 3 (Alice no Proxy — porta 9443):**
   ```powershell
   .\scripts\run-client.bat 127.0.0.1 9443
   ```
4. **Terminal 4 (Bob direto no Servidor — porta 8443)** e **Terminal 5 (Carol direto no Servidor — porta 8443):**
   ```powershell
   .\scripts\run-client.bat 127.0.0.1 8443
   ```
5. No **Terminal 3 (Alice)**, tente enviar qualquer mensagem para Bob:
   ```text
   /msg <prefixo_do_Bob> Teste badframe
   ```
6. *O que observar:*
   - O **Terminal 2 (`TamperProxy`)** injeta o tamanho inválido `-42`.
   - O **Terminal 1 (Servidor)** loga `[WARN] Rejeitado: id=<Alice> motivo="framing invalido: Tamanho de frame inválido (<= 0): -42"` e desconecta Alice, notificando `[EVENTO] Peer saiu: <Alice>` para Bob e Carol.
   - Agora, no **Terminal 4 (Bob)**, envie `/msg <prefixo_da_Carol> Servidor continua vivo!`: Carol recebe normalmente no **Terminal 5**!

---

## Situação 6 — Autenticidade do Servidor (Certificado Falso vs. Certificado Pinado)

**Objetivo:** Demonstrar que o cliente recusa imediatamente conectar a um servidor cujo certificado X.509 difere do certificado pinado local (Decisão D7).

### Passo a passo:
1. Com o **Servidor** rodando no **Terminal 1** (`.\scripts\run-server.bat`), gere um certificado falso temporário em outro terminal:
   ```powershell
   keytool -genkeypair -alias fake -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -dname "CN=FakeServer" -validity 365 -storetype PKCS12 -keystore out\fake.p12 -storepass changeit
   keytool -exportcert -alias fake -keystore out\fake.p12 -storepass changeit -file out\fake.crt
   ```
2. Inicie um cliente passando `out\fake.crt` como certificado pinado esperado:
   ```powershell
   java -cp out securechat.client.Client 127.0.0.1 8443 out\fake.crt
   ```
3. *O que observar:*
   - O cliente aborta imediatamente o handshake com:
     `[WARN] Rejeitado: id=... motivo="certificado do servidor diferente do certificado pinado (D7)"`
     `[ERROR] Falha ao iniciar cliente: Certificado do servidor não corresponde ao certificado pinado (possível MITM)`.

---

## Situação 7 — Destinatário Inexistente e Entrada/Saída de Peers

**Objetivo:** Demonstrar o tratamento de `PEER_LEFT` e erros de roteamento no canal de controle.

1. Com Alice e Bob conectados (`.\scripts\run-client.bat`), digite `/quit` no terminal de **Bob**.
2. No terminal de **Alice**, observe `[EVENTO] Peer saiu: <id_Bob>` e digite `/peers` para ver que a chave de Bob foi removida e zerada da `PeerTable`.
3. Se um pacote E2E chegar ao servidor endereçado a um `recipient_id` que não está mais conectado, o servidor retorna `CONTROL(ERROR, cod=3)` (`[ERRO DO SERVIDOR (cod=3)]: Destinatario nao encontrado`).

---

## Atalho para Demonstração Rápida em 1 Único Terminal

Caso queira demonstrar todos os cenários acima de forma automática durante a apresentação sem precisar alternar entre várias janelas:

```powershell
# Roda os 4 cenários (E2E+Sniff, Bitflip, Replay e Badframe) com logs completos
.\scripts\demo-all.bat

# Ou rode cada cenário individualmente:
.\scripts\demo-e2e.bat
.\scripts\demo-bitflip.bat
.\scripts\demo-replay.bat
.\scripts\demo-badframe.bat
```

