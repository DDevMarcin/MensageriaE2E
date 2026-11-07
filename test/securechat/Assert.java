package securechat;

import java.util.Arrays;
import java.util.Objects;

/**
 * Utilitário mínimo de asserções para o runner de testes próprio (sem JUnit).
 *
 * <p>Lança {@link AssertionError} sempre que uma condição falha, permitindo que
 * o {@link TestRunner} capture e relate o motivo exato da falha.</p>
 */
public final class Assert {

    /**
     * Interface funcional para blocos de código que podem lançar exceções verificadas
     * ou não verificadas durante um teste com {@link #assertThrows}.
     */
    @FunctionalInterface
    public interface ThrowingRunnable {
        void run() throws Throwable;
    }

    private Assert() {
        // Classe utilitária não instanciável.
    }

    /** Verifica que a condição fornecida é verdadeira. */
    public static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    /** Verifica que a condição fornecida é verdadeira. */
    public static void assertTrue(boolean condition) {
        assertTrue(condition, "Esperado true, mas foi false");
    }

    /** Verifica que a condição fornecida é falsa. */
    public static void assertFalse(boolean condition, String message) {
        if (condition) {
            throw new AssertionError(message);
        }
    }

    /** Verifica que a condição fornecida é falsa. */
    public static void assertFalse(boolean condition) {
        assertFalse(condition, "Esperado false, mas foi true");
    }

    /** Verifica que dois objetos ou valores são iguais segundo {@link Objects#equals}. */
    public static void assertEquals(Object expected, Object actual, String message) {
        if (!Objects.equals(expected, actual)) {
            throw new AssertionError(
                    message + " (esperado: <" + expected + ">, obtido: <" + actual + ">)");
        }
    }

    /** Verifica que dois objetos ou valores são iguais segundo {@link Objects#equals}. */
    public static void assertEquals(Object expected, Object actual) {
        assertEquals(expected, actual, "Valores diferentes");
    }

    /** Verifica que dois inteiros longos são iguais. */
    public static void assertEquals(long expected, long actual, String message) {
        if (expected != actual) {
            throw new AssertionError(
                    message + " (esperado: " + expected + ", obtido: " + actual + ")");
        }
    }

    /** Verifica que dois inteiros longos são iguais. */
    public static void assertEquals(long expected, long actual) {
        assertEquals(expected, actual, "Valores numéricos diferentes");
    }

    /** Verifica que dois arrays de bytes possuem exatamente o mesmo comprimento e conteúdo. */
    public static void assertArrayEquals(byte[] expected, byte[] actual, String message) {
        if (!Arrays.equals(expected, actual)) {
            int expLen = expected == null ? -1 : expected.length;
            int actLen = actual == null ? -1 : actual.length;
            throw new AssertionError(
                    message + " (arrays de bytes divergem; len esperado=" + expLen + ", len obtido=" + actLen + ")");
        }
    }

    /** Verifica que dois arrays de bytes possuem exatamente o mesmo comprimento e conteúdo. */
    public static void assertArrayEquals(byte[] expected, byte[] actual) {
        assertArrayEquals(expected, actual, "Arrays de bytes diferentes");
    }

    /**
     * Verifica que a execução de {@code runnable} lança uma exceção do tipo {@code expectedType}
     * (ou subclasse). Retorna a exceção capturada para inspeções adicionais se necessário.
     */
    public static <T extends Throwable> T assertThrows(Class<T> expectedType, ThrowingRunnable runnable) {
        try {
            runnable.run();
        } catch (Throwable thrown) {
            if (expectedType.isInstance(thrown)) {
                return expectedType.cast(thrown);
            }
            throw new AssertionError(
                    "Esperada exceção " + expectedType.getSimpleName()
                            + ", mas foi lançada " + thrown.getClass().getSimpleName()
                            + ": " + thrown.getMessage(),
                    thrown);
        }
        throw new AssertionError(
                "Esperada exceção " + expectedType.getSimpleName() + ", mas nenhuma exceção foi lançada");
    }
}

