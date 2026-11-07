package securechat.client;

import securechat.common.ClientId;
import securechat.common.Messages;
import securechat.common.ProtocolException;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tabela concorrente de peers conhecidos pelo cliente ({@code ConcurrentHashMap<ClientId, PeerState>}).
 *
 * <p>Regras de consistência implementadas ({@code docs/02}):</p>
 * <ul>
 *   <li>Entradas são criadas ao processar {@code PEER_LIST} ou {@code PEER_JOINED}.</li>
 *   <li>Se chegar {@code PEER_JOINED} para um {@code client_id} já existente (reconexão),
 *       o {@link PeerState} antigo tem suas chaves zeradas ({@link PeerState#wipe()}) e é
 *       substituído atomicamente por um novo {@link PeerState} com chaves recém-derivadas e
 *       contadores {@code seqSend = 0} / {@code seqRecv = -1}.</li>
 *   <li>Entradas são removidas e limpas em {@code PEER_LEFT}.</li>
 * </ul>
 */
public final class PeerTable {

    private final ConcurrentHashMap<ClientId, PeerState> peers = new ConcurrentHashMap<>();

    /**
     * Deriva e insere (ou substitui em caso de reconexão) o estado E2E para {@code peerInfo}.
     * Se {@code peerInfo.clientId()} for igual a {@code selfId}, ignora por defesa em profundidade.
     *
     * @return o novo {@link PeerState} instalado, ou {@code null} se era o próprio cliente.
     */
    public PeerState upsertPeer(
            ClientId selfId,
            PrivateKey skSelf,
            byte[] selfSalt,
            Messages.PeerInfo peerInfo) throws ProtocolException {

        Objects.requireNonNull(selfId, "selfId não pode ser nulo");
        Objects.requireNonNull(peerInfo, "peerInfo não pode ser nulo");

        if (selfId.equals(peerInfo.clientId())) {
            return null;
        }

        PeerState newState = PeerState.derive(selfId, skSelf, selfSalt, peerInfo);
        PeerState previous = peers.put(peerInfo.clientId(), newState);
        if (previous != null) {
            previous.wipe();
        }
        return newState;
    }

    /**
     * Remove um peer ao receber {@code PEER_LEFT} e limpa suas chaves da memória.
     */
    public PeerState removePeer(ClientId peerId) {
        if (peerId == null) {
            return null;
        }
        PeerState removed = peers.remove(peerId);
        if (removed != null) {
            removed.wipe();
        }
        return removed;
    }

    /**
     * Busca o estado de um peer pelo seu {@link ClientId} exato.
     */
    public PeerState get(ClientId peerId) {
        if (peerId == null) {
            return null;
        }
        return peers.get(peerId);
    }

    /**
     * Localiza um único peer pelo prefixo hexadecimal ou ID completo (para o comando
     * {@code /msg <id|prefixo> <texto>} do CLI).
     *
     * @throws ProtocolException se nenhum peer corresponder ou se o prefixo for ambíguo.
     */
    public PeerState resolveByPrefix(String token) throws ProtocolException {
        List<PeerState> matches = new ArrayList<>();
        for (PeerState ps : peers.values()) {
            if (ps.peerId().matchesPrefix(token)) {
                matches.add(ps);
            }
        }
        if (matches.isEmpty()) {
            throw new ProtocolException("Nenhum peer conectado corresponde a '" + token + "'");
        }
        if (matches.size() > 1) {
            throw new ProtocolException(
                    "Prefixo '" + token + "' é ambíguo (" + matches.size() + " peers correspondem)");
        }
        return matches.get(0);
    }

    /**
     * Retorna uma lista ordenada de todos os peers ativos.
     */
    public List<PeerState> snapshotAll() {
        List<PeerState> list = new ArrayList<>(peers.values());
        list.sort(Comparator.comparing(PeerState::peerId));
        return list;
    }

    /** Retorna a quantidade de peers atualmente na tabela. */
    public int size() {
        return peers.size();
    }

    /** Limpa todas as chaves E2E da memória e esvazia a tabela. */
    public void clearAndWipeAll() {
        for (PeerState ps : peers.values()) {
            ps.wipe();
        }
        peers.clear();
    }
}

