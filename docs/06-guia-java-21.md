# 06 — Guia Java 21 puro (APIs, armadilhas e padrões)

> Só JDK 21. Nada de bibliotecas externas. Este guia existe para evitar os erros clássicos ao implementar o protocolo em Java.

## 1. X25519 com chave pública **raw de 32 bytes** (principal armadilha)
O JDK representa a chave pública X25519 como `XECPublicKey` com a coordenada `u` em `BigInteger`. O protocolo exige **32 bytes raw little-endian** (RFC 7748). Implementar em `X25519Util`:
- Gerar par: `KeyPairGenerator.getInstance("X25519")` → `generateKeyPair()`.
- **Exportar** pk → `byte[32]`: `((XECPublicKey) pub).getU()` → `toByteArray()` (big-endian, pode ter byte de sinal ou ser mais curto) → ajustar para 32 bytes e **inverter** para little-endian.
- **Importar** `byte[32]` → `PublicKey`: copiar, inverter para big-endian, **zerar o bit mais significativo do último byte do formato little-endian** (`raw[31] &= 0x7F` antes de inverter, regra do RFC 7748), `new BigInteger(1, bytes)`, `KeyFactory.getInstance("X25519").generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, u))`.
- ECDH: `KeyAgreement.getInstance("X25519")` → `init(sk)` → `doPhase(pkPeer, true)` → `generateSecret()` = `Z` (32 B). **Rejeitar `Z` todo zero** (ponto de ordem baixa) com `ProtocolException`.
- Validar entrada: `raw.length == 32`, senão `ProtocolException`.
- Testes obrigatórios: round-trip `raw → PublicKey → raw` e **vetores do RFC 7748 §6.1** (o agente deve consultar o RFC para os valores) comprovando que `ECDH(A,B) == ECDH(B,A)` e batendo com o vetor.

## 2. HKDF-SHA256 manual (`Hkdf`)
O JDK 21 **não** tem API pública de HKDF (ela surge só no JDK 25). Implementar com `Mac.getInstance("HmacSHA256")`:
- `extract(salt, ikm)`: `PRK = HMAC(key = salt, data = ikm)` (32 B). Salt de 16 B (se vazio, usar 32 zeros — não ocorre neste projeto).
- `expand(prk, info, L)`: `T(0)=vazio; T(i) = HMAC(prk, T(i-1) || info || (byte) i)`; concatenar e truncar para `L` (aqui `L = 16`, então basta `T(1)`). Implementar o laço geral (`L ≤ 255*32`) e validar.
- `info` em ASCII: `"A2B"`, `"B2A"`, `"S2C"` (`StandardCharsets.US_ASCII`).
- Teste obrigatório: **RFC 5869, Apêndice A.1** (Test Case 1, SHA-256).

## 3. AES-128-GCM (`AesGcm`)
- `Cipher.getInstance("AES/GCM/NoPadding")`; chave: `new SecretKeySpec(key16, "AES")`; parâmetros: `new GCMParameterSpec(128, nonce12)`.
- AAD: `cipher.updateAAD(aad)` **antes** de `doFinal`.
- `doFinal` na cifra devolve `ciphertext || tag(16 B)` — exatamente o formato do enunciado.
- Decifrar com tag inválida lança `AEADBadTagException` → converter em rejeição (`SecureLog.rejected("tag mismatch")`), **nunca** repassar o texto parcial.
- **Armadilha:** o JDK proíbe reusar o mesmo (chave, IV) numa instância de `Cipher` em modo de cifragem. Criar **um `Cipher` novo por operação**.
- Nonce: `ByteBuffer.allocate(12).put(ivBase4).putLong(seqNo).array()` (`ByteBuffer` é big-endian por padrão — exatamente o exigido).

## 4. RSA-PSS (`RsaPss`)
- `Signature.getInstance("RSASSA-PSS")` e, **antes** de `initSign/initVerify`: `sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, PSSParameterSpec.TRAILER_FIELD_BC))`.
- Servidor e cliente **devem usar exatamente os mesmos parâmetros** (decisão D6 em `docs/01`).
- O dado assinado é `H = SHA256(pk_S || pk_C || client_id || salt)` (32 B), conforme o enunciado: `sig.update(H)`.
- Chave RSA ≥ 2048 bits.

## 5. Certificado autoassinado e pinning
- Geração (ferramenta do próprio JDK, `scripts/gen-cert`): 
  `keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 365 -dname "CN=localhost" -keystore certs/server.p12 -storetype PKCS12 -storepass <senha>`
  e `keytool -exportcert -alias server -keystore certs/server.p12 -storepass <senha> -file certs/server.crt` (DER).
- Servidor: `KeyStore.getInstance("PKCS12")` + `load(...)` → `getKey("server", senha)` (`PrivateKey`) e `getCertificate("server").getEncoded()` (bytes DER enviados no `HELLO_REPLY`). Senha lida de variável de ambiente `SERVER_KEYSTORE_PASS` (com valor padrão didático documentado no README); **`server.p12` fica no `.gitignore`**.
- Cliente (pinning): carregar `certs/server.crt` com `CertificateFactory.getInstance("X.509")`; comparar `getEncoded()` com os bytes recebidos usando `MessageDigest.isEqual`; só então usar `cert.getPublicKey()` para verificar a assinatura.

## 6. Rede, framing e bytes
- `DataInputStream.readInt()` (big-endian) para o prefixo de 4 bytes; validar `0 < len <= MAX_FRAME` **antes** de alocar; `readFully` para o corpo (EOF → `FramingException`).
- Montar/ler campos fixos com `ByteBuffer`; checar `remaining()` antes de cada `get`.
- `UUID.randomUUID()` → 16 B: `ByteBuffer.allocate(16).putLong(msb).putLong(lsb)`.
- Comparar `client_id` (ordem A/B) com `Arrays.compareUnsigned`.
- Hex/fingerprint: `HexFormat.of()`; fingerprint = SHA-256 da `pk` truncado (ex.: 8 bytes).
- `SecureRandom`: uma instância compartilhada (thread-safe).
- `socket.setSoTimeout(...)` durante o handshake; depois, remover timeout (0) ou usar timeout ocioso longo.
- Zerar `byte[]` sensíveis (Z, chaves de sessão ao desconectar) com `Arrays.fill(a, (byte) 0)`. Obs.: objetos `PrivateKey` do JCA não podem ser zerados — citar como limitação em `EXPLICACAO_SISTEMA.txt`.

## 7. Concorrência (Java 21)
- Servidor: `ServerSocket` + `Executors.newVirtualThreadPerTaskExecutor()` (ou `Thread.ofVirtual().start(...)`), uma thread por conexão, com `try/finally` que remove a sessão.
- Escritas em socket sob `ReentrantLock` (ver `docs/02`). Evitar `synchronized` em volta de I/O.
- `MAX_CLIENTS` com `java.util.concurrent.Semaphore`.

## 8. Estilo de código
- Pacotes e nomes em inglês (classes/métodos), comentários e Javadoc **em português** explicando o "porquê" criptográfico (o aluno vai usá-los para explicar).
- `records` para mensagens imutáveis (`HelloMsg`, `HelloReply`, `E2eFrame`, `ControlMsg`), `final` por padrão, sem `static` mutável.
- Erros do protocolo: `ProtocolException` / `FramingException` (checked ou unchecked — escolher uma e documentar). Nunca engolir exceção em silêncio: logar o motivo via `SecureLog` e agir (descartar frame, encerrar conexão).
- Compilar com `-Xlint:all` e `--release 21`.

## 9. Testes sem JUnit (runner próprio)
- Em `test/securechat/`: classe `TestRunner` (main) que executa uma lista explícita de casos, imprime `PASS`/`FAIL nome — motivo`, resumo final e **sai com código ≠ 0 se algum falhar**.
- Helper `Assert` mínimo: `assertTrue`, `assertEquals`, `assertArrayEquals`, `assertThrows(Class, Runnable)`.
- Testes de integração sobem `Server` e `Client` na mesma JVM em porta efêmera (`new ServerSocket(0)`).
- `scripts/test` compila e roda `securechat.TestRunner`.
