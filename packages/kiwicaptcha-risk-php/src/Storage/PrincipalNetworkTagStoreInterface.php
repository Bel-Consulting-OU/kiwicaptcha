<?php

declare (strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

/**
 * Optional capability: the principal first-seen network tag records.
 * One record per principal and network bucket. Written with SET NX.
 * This mirrors the Rust PrincipalNetworkTagStore trait. The record
 * marks a network bucket as established. The write is once-only. A
 * later login from the same bucket is no longer novel.
 *
 * Session tags (prefixed `session:`) carry a per-principal cap and a
 * TTL on inactivity (suggested 90 days), with least-recently-used
 * eviction, so every browser a principal ever uses cannot grow the
 * set without bound. Network and ASN tags are small and stable.
 */
interface PrincipalNetworkTagStoreInterface
{
    /**
     * Whether the principal has been seen (established) from this
     * network bucket: `true` = seen before, `false` = never seen (the
     * first-attempt novel-network signal), `null` = no record surface
     * (neutral: never novel).
     *
     * @throws RiskStoreException when the state backend fails
     */
    public function principalNetworkSeen (string $principalId, string $network): ?bool;

    /**
     * Records the first-seen network tag for the (principal, network)
     * pair (SET NX, first write wins). Called when a session credit is
     * granted for a login from this network. Answers whether the record
     * was newly created.
     *
     * @throws RiskStoreException when the state backend fails
     */
    public function recordPrincipalNetworkTag (string $principalId, string $network): bool;

    /**
     * Whether the account carries ANY established network: the "no
     * prior trusted network" half of the novel-network gate.
     * `true` = the account has a trusted network, `false` = none,
     * `null` = no record surface.
     *
     * @throws RiskStoreException when the state backend fails
     */
    public function principalHasTrustedNetwork (string $principalId): ?bool;
}
