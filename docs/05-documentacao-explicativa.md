# 05 — Documentação Explicativa (`EXPLICACAO_SISTEMA.txt`)

## Propósito
O aluno precisa **explicar** o sistema ao professor (por que cada decisão foi tomada, como cada garantia é obtida), além de demonstrar. O agente deve manter, na raiz do projeto, o arquivo **`EXPLICACAO_SISTEMA.txt`**: texto puro, em português, linguagem simples e didática, que funcione como material de estudo e roteiro de fala.

## Regras de manutenção
1. Criar o esqueleto na **T00**.
2. **Atualizar ao final de cada task** (antes de marcá-la como concluída): preencher/ajustar as seções afetadas e adicionar uma linha no CHANGELOG.
3. Nunca deixar o `.txt` contradizer o código: se o código mudar, o texto muda na mesma task.
4. Citar sempre **arquivo e função reais** (ex.: `securechat/common/Hkdf.java::expand`).
5. Explicar o "porquê", não só o "o quê". Evitar jargão sem definição; definir cada sigla na primeira vez.
6. Não colocar segredos, chaves reais ou dumps de tráfego com conteúdo no arquivo (exemplos com bytes fictícios/truncados).
7. Largura de linha ≤ 100 colunas; usar diagramas ASCII quando ajudarem.

## Estrutura obrigatória (seções, nesta ordem)
```
1. VISÃO GERAL
   - O que o sistema faz, em 5-8 linhas; quem são Cliente, Servidor, Relay.
2. GLOSSÁRIO
   - sk/pk, X25519, ECDH, ECDHE, Z_AB, HKDF (Extract/Expand), PRK, AES-GCM, AEAD, nonce, tag,
     AAD, RSA-PSS, certificado autoassinado, pinning, forward secrecy, replay, seq_no, IV_base.
3. ARQUITETURA
   - Diagrama ASCII Cliente A <-> Servidor <-> Cliente B; responsabilidades de cada um;
     o que o servidor SABE e o que ele NÃO SABE.
4. HANDSHAKE PASSO A PASSO
   - Cada mensagem, cada byte (campos e tamanhos), o que é assinado (H) e por quê,
     o que o cliente valida e o que acontece se falhar.
5. DERIVAÇÃO DAS CHAVES E2E
   - Z_AB, salt do par (decisão D2), HKDF, Key_A2B/Key_B2A, quem usa qual,
     por que as chaves são diferentes por direção.
6. FORMATO DO FRAME E2E
   - Diagrama ASCII do frame (nonce, sender, recipient, seq, ciphertext+tag), AAD,
     construção do nonce, framing TCP de 4 bytes e byte de tipo (D5).
7. ENVIO E RECEBIMENTO
   - Passo a passo do remetente, do servidor (relay) e do destinatário; validações em ordem.
8. ANTI-REPLAY E INTEGRIDADE
   - seq_send/seq_recv, quando seq_recv é atualizado e por quê, o que a tag GCM cobre.
9. ESTRUTURAS DE DADOS
   - sessions (servidor) e peers (cliente): cada campo e sua função; por que existe seq_send
     no servidor (canal de controle).
10. MAPA DO CÓDIGO
   - Tabela: classe (.java) -> métodos principais -> qual parte do protocolo implementa
     -> sugestão de qual integrante apresenta.
11. GARANTIAS DE SEGURANÇA
   - Para cada garantia: mecanismo, onde está no código, como é demonstrada.
12. TESTES E DEMONSTRAÇÃO
   - Cada teste obrigatório: o que faz, comando para rodar, resultado esperado e o que dizer.
13. DECISÕES DE PROJETO E LIMITAÇÕES
   - D1–D7 (e novas) com justificativa; limitações honestas (ex.: servidor distribui pk dos
     peers; mitigação por fingerprint).
14. ROTEIRO DE APRESENTAÇÃO
   - Sequência sugerida de fala + demo, com tempo estimado por parte.
15. PERGUNTAS PROVÁVEIS DO PROFESSOR
   - Pelo menos 12 perguntas com resposta curta (ex.: "Por que não reutilizar o nonce no GCM?",
     "O que acontece se a chave RSA vazar amanhã?", "O servidor consegue ler as mensagens?",
     "Por que HKDF em vez de usar Z direto?", "Por que duas chaves (A2B/B2A)?").
16. CHANGELOG
   - Uma linha por atualização: data/task, o que mudou no texto.
```

## Critério de qualidade
Um colega que não escreveu o código deve conseguir, lendo só o `.txt`, explicar o protocolo completo e responder às perguntas do professor.
