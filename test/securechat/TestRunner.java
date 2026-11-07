package securechat;

import securechat.common.CertUtilTest;
import securechat.common.Constants;
import securechat.common.CryptoPrimitivesTest;
import securechat.common.FramingAndUtilsTest;
import securechat.common.MessagesTest;
import securechat.common.SecureLog;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Runner de testes automatizados próprio (JDK 21 puro, sem JUnit).
 *
 * <p>Executa sequencialmente todos os casos de teste registrados, imprime o resultado
 * individual ({@code PASS} ou {@code FAIL}) e encerra com código de saída diferente
 * de zero caso qualquer teste falhe.</p>
 */
public final class TestRunner {

    /** Representa um caso de teste nomeado. */
    public record TestCase(String name, Assert.ThrowingRunnable body) {}

    private static final PrintWriter OUT = new PrintWriter(
            new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8);

    private TestRunner() {
        // Classe executável não instanciável.
    }

    public static void main(String[] args) {
        SecureLog.setSilent(true);
        List<TestCase> tests = new ArrayList<>();

        // T00 — Teste trivial inicial validando as constantes do protocolo
        tests.add(new TestCase("T00: Constants sanity check", TestRunner::testConstantsSanity));

        // T01 — Utilitários, framing e logger seguro
        tests.add(new TestCase("T01: Framing round-trip OK", FramingAndUtilsTest::testFrameOk));
        tests.add(new TestCase("T01: Framing truncado -> FramingException", FramingAndUtilsTest::testFrameTruncated));
        tests.add(new TestCase("T01: Framing tamanho 0 -> FramingException", FramingAndUtilsTest::testFrameZeroLength));
        tests.add(new TestCase("T01: Framing tamanho negativo -> FramingException", FramingAndUtilsTest::testFrameNegativeLength));
        tests.add(new TestCase("T01: Framing acima de MAX_FRAME -> FramingException", FramingAndUtilsTest::testFrameExceedsMaxLength));
        tests.add(new TestCase("T01: ClientId imutável e chave de HashMap", FramingAndUtilsTest::testClientIdAsMapKey));
        tests.add(new TestCase("T01: ClientId comparação unsigned (0x7F < 0x80)", FramingAndUtilsTest::testClientIdUnsignedComparison));
        tests.add(new TestCase("T01: Bytes concat, big-endian, wipe e fingerprint", FramingAndUtilsTest::testBytesAndFingerprint));

        // T02 — Primitivas criptográficas (wrappers do JDK)
        tests.add(new TestCase("T02: X25519 vetor oficial RFC 7748 §6.1", CryptoPrimitivesTest::testX25519Rfc7748Vector));
        tests.add(new TestCase("T02: X25519 round-trip raw 32B, ECDH simétrico e rejeição Z zero", CryptoPrimitivesTest::testX25519RoundTripAndLowOrderRejection));
        tests.add(new TestCase("T02: HKDF-SHA256 vetor oficial RFC 5869 A.1", CryptoPrimitivesTest::testHkdfRfc5869Vector));
        tests.add(new TestCase("T02: AES-128-GCM round-trip e detecção de bitflip (ct, tag, AAD, nonce)", CryptoPrimitivesTest::testAesGcmRoundTripAndTamperDetection));
        tests.add(new TestCase("T02: RSA-PSS assinatura/verificação sobre H e falha com parâmetros trocados", CryptoPrimitivesTest::testRsaPssSignVerifyAndMismatchedParams));

        // T03 — Certificado autoassinado e identidade do servidor
        tests.add(new TestCase("T03: Carregar server.p12 + server.crt, pinning D7 e assinatura RSA-PSS", CertUtilTest::testLoadKeystoreAndVerifyPinnedCert));
        tests.add(new TestCase("T03: Verificar server.p12 no .gitignore", CertUtilTest::testServerP12InGitignore));

        // T04 — Protocolo: empacotamento de mensagens
        tests.add(new TestCase("T04: HELLO pack/unpack e rejeição de tamanho inválido", MessagesTest::testHelloRoundTripAndMalformed));
        tests.add(new TestCase("T04: HELLO_REPLY pack/unpack e rejeição de sig_len/cert_len inconsistentes", MessagesTest::testHelloReplyRoundTripAndMalformed));
        tests.add(new TestCase("T04: CONTROL (5 opcodes) pack/unpack/seal e rejeição de malformados", MessagesTest::testControlMessagesRoundTripAndMalformed));
        tests.add(new TestCase("T04: E2E pack/unpack e validação de consistência nonce vs seq_no", MessagesTest::testE2eFrameRoundTripAndMalformed));

        // T05 — Handshake (servidor e cliente)
        tests.add(new TestCase("T05: Handshake completo OK e derivação idêntica de Key_S2C", HandshakeTest::testHandshakeSuccess));
        tests.add(new TestCase("T05: Handshake com certificado diferente do pinado -> aborta", HandshakeTest::testHandshakeWrongCertificateAborts));
        tests.add(new TestCase("T05: Handshake com assinatura RSA-PSS adulterada -> aborta", HandshakeTest::testHandshakeCorruptedSignatureAborts));
        tests.add(new TestCase("T05: Handshake com client_id trocado no hash H -> aborta", HandshakeTest::testHandshakeSwappedClientIdInHashAborts));
        tests.add(new TestCase("T05: Handshake com cliente inativo -> timeout tratado", HandshakeTest::testHandshakeTimeoutHandled));

        // T06 — Servidor: registro, sessions e controle
        tests.add(new TestCase("T06: 3 clientes conectam/desconectam e recebem REGISTER_OK, PEER_LIST, PEER_JOINED e PEER_LEFT", ServerSessionControlTest::testThreeClientsJoinAndLeaveNotifications));
        tests.add(new TestCase("T06: Rejeição de client_id duplicado ativo com CONTROL(ERROR) preservando sessão original (D4)", ServerSessionControlTest::testDuplicateActiveClientIdRejected));

        // T07 — Cliente: peers e derivação E2E
        tests.add(new TestCase("T07: Derivação cruzada simétrica A<->B (A.keySend == B.keyRecv e D2)", ClientPeerDerivationTest::testCrossKeyDerivationSymmetry));
        tests.add(new TestCase("T07: Reconexão do mesmo client_id substitui chaves e reseta contadores", ClientPeerDerivationTest::testReconnectionGeneratesNewKeysAndResetsCounters));
        tests.add(new TestCase("T07: Canal de controle rejeita replay e não avança seqRecv em falha de tag", ClientPeerDerivationTest::testControlChannelReplayAndTamperRejected));

        // T08 — Mensageria E2E (envio, relay e recebimento)
        tests.add(new TestCase("T08: Mensageria E2E bidirecional A<->B via Servidor e comandos CLI", E2eMessagingTest::testBidirectionalE2eMessagingAndCli));
        tests.add(new TestCase("T08: Limite de 4096 bytes de plaintext imposto no cliente", E2eMessagingTest::testMaxPlaintextLimitEnforcedOnClient));
        tests.add(new TestCase("T08: Destinatário inexistente retorna CONTROL(ERROR) ao remetente", E2eMessagingTest::testUnknownRecipientReturnsControlErrorToSender));
        tests.add(new TestCase("T08: Mudança de IV_base no meio da sessão é rejeitada (D3)", E2eMessagingTest::testIvBaseRecvChangedMidSessionRejected));

        // T09 — Testes de segurança (os obrigatórios do professor)
        tests.add(new TestCase("T09: TamperProxy SNIFF comprova confidencialidade no fio", SecurityTests::testSniffModeConfidentiality));
        tests.add(new TestCase("T09: TamperProxy BITFLIP detectado pela tag GCM no destinatário", SecurityTests::testBitflipRejectedByRecipient));
        tests.add(new TestCase("T09: TamperProxy REPLAY detectado e descartado pelo seq_no monotônico", SecurityTests::testReplayRejectedByRecipient));
        tests.add(new TestCase("T09: TamperProxy BADFRAME desconecta infrator sem derrubar o servidor", SecurityTests::testBadFrameDisconnectsSafelyWithoutCrashingServer));
        tests.add(new TestCase("T09: Servidor descarta frame E2E com sender_id forjado (anti-spoof)", SecurityTests::testForgedSenderIdDiscardedByServer));
        tests.add(new TestCase("T09: Reconexão fim-a-fim com mesmo client_id gera novas chaves E2E", SecurityTests::testEndToEndReconnectionWithSameClientId));

        // T10 — Robustez e política de logs
        tests.add(new TestCase("T10: Servidor sobrevive a bytes aleatórios, EOF e tráfego malformado", RobustnessAndLogPolicyTest::testServerSurvivesRandomBytesEofAndMalformedTraffic));
        tests.add(new TestCase("T10: Servidor aplica limite MAX_CLIENTS com CONTROL(ERROR) e recupera vaga", RobustnessAndLogPolicyTest::testServerMaxClientsLimitAndRecovery));
        tests.add(new TestCase("T10: Auditoria estática da política de logs e SecureLog sem byte[]", RobustnessAndLogPolicyTest::testSourceCodeLogPolicyAudit));

        int passed = 0;
        int failed = 0;

        OUT.println("=== Executando testes do SecureChat (Java " + Runtime.version() + ") ===");
        for (TestCase tc : tests) {
            try {
                tc.body().run();
                passed++;
                OUT.println("PASS " + tc.name());
            } catch (Throwable t) {
                failed++;
                OUT.println("FAIL " + tc.name() + " — " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }

        OUT.println("--------------------------------------------------");
        OUT.println("Resumo: " + passed + " passaram, " + failed + " falharam (total: " + tests.size() + ")");
        if (failed > 0) {
            System.exit(1);
        }
    }

    /**
     * Teste inicial da T00: confere invariantes básicos das constantes de protocolo
     * (tamanhos de chave, nonce, tag GCM, limite de plaintext e frame máximo).
     */
    private static void testConstantsSanity() {
        Assert.assertEquals(16, Constants.CLIENT_ID_BYTES, "client_id deve ter 16 bytes");
        Assert.assertEquals(32, Constants.X25519_KEY_BYTES, "pk X25519 raw deve ter 32 bytes");
        Assert.assertEquals(16, Constants.SALT_BYTES, "salt_srv deve ter 16 bytes");
        Assert.assertEquals(16, Constants.AES_KEY_BYTES, "chave AES-128 deve ter 16 bytes");
        Assert.assertEquals(12, Constants.NONCE_BYTES, "nonce GCM deve ter 12 bytes");
        Assert.assertEquals(Constants.IV_BASE_BYTES + Constants.SEQ_NO_BYTES, Constants.NONCE_BYTES,
                "nonce deve ser IV_base (4B) + seq_no (8B)");
        Assert.assertEquals(4096, Constants.MAX_PLAINTEXT, "MAX_PLAINTEXT deve ser 4096 bytes");
        Assert.assertTrue(Constants.MAX_FRAME >= Constants.MAX_E2E_FRAME,
                "MAX_FRAME deve comportar um frame E2E de tamanho máximo");
    }
}

