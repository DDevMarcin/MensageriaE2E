package securechat.server;

import securechat.common.ClientId;
import securechat.common.Messages;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tabela concorrente de sessões ativas no servidor ({@code ConcurrentHashMap<ClientId, Session>}).
 *
 * <p>Implementa o registro atômico via {@link ConcurrentHashMap#putIfAbsent} para rejeitar
 * conexões com {@code client_id} duplicado ativo (Decisão de Projeto D4) e a remoção
 * condicional {@link ConcurrentHashMap#remove(Object, Object)} para garantir que uma
 * conexão rejeitada nunca remova acidentalmente a sessão legítima original.</p>
 */
public final class SessionRegistry {

    private final ConcurrentHashMap<ClientId, Session> sessions = new ConcurrentHashMap<>();

    /**
     * Registra uma nova sessão somente se o {@code client_id} ainda não estiver ativo (D4).
     *
     * @return {@code true} se o registro sucedeu; {@code false} se já existe sessão ativa
     *         com o mesmo {@code client_id}.
     */
    public boolean register(Session session) {
        Objects.requireNonNull(session, "session não pode ser nula");
        return sessions.putIfAbsent(session.clientId(), session) == null;
    }

    /**
     * Remove a sessão associada a {@code clientId} somente se a instância armazenada for
     * exatamente {@code expectedSession}.
     *
     * @return {@code true} se a sessão foi removida por esta chamada.
     */
    public boolean removeIfSame(ClientId clientId, Session expectedSession) {
        if (clientId == null || expectedSession == null) {
            return false;
        }
        return sessions.remove(clientId, expectedSession);
    }

    /**
     * Busca a sessão ativa de um destinatário pelo seu {@link ClientId}.
     */
    public Session get(ClientId clientId) {
        if (clientId == null) {
            return null;
        }
        return sessions.get(clientId);
    }

    /**
     * Retorna um snapshot das informações públicas ({@link Messages.PeerInfo}) de todos os
     * clientes conectados, <b>excluindo</b> o próprio {@code excludedClientId} (passo 8 do
     * handshake em {@code docs/01}).
     */
    public List<Messages.PeerInfo> snapshotOtherPeerInfos(ClientId excludedClientId) {
        List<Messages.PeerInfo> list = new ArrayList<>();
        for (Session s : sessions.values()) {
            if (!s.clientId().equals(excludedClientId)) {
                list.add(s.toPeerInfo());
            }
        }
        return list;
    }

    /**
     * Retorna um snapshot das instâncias {@link Session} de todos os demais clientes ativos,
     * exceto {@code excludedClientId}, para envio de broadcast ({@code PEER_JOINED} / {@code PEER_LEFT}).
     */
    public List<Session> snapshotOtherSessions(ClientId excludedClientId) {
        List<Session> list = new ArrayList<>();
        for (Session s : sessions.values()) {
            if (!s.clientId().equals(excludedClientId)) {
                list.add(s);
            }
        }
        return list;
    }

    /** Retorna o número atual de sessões registradas. */
    public int size() {
        return sessions.size();
    }

    /** Fecha e limpa todas as sessões ativas durante o encerramento do servidor. */
    public void closeAll() {
        for (Session s : sessions.values()) {
            s.closeAndWipe();
        }
        sessions.clear();
    }
}

