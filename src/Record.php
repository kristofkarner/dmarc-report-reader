<?php

declare(strict_types=1);

namespace KK\Dmarc;

/**
 * One row of an aggregate report: a sending source, and how the
 * messages it sent were judged.
 *
 * The two pairs of results are the part that trips everyone up.
 *
 * `$dkimAligned` and `$spfAligned` come from <policy_evaluated>: these
 * are the ALIGNED results, the ones DMARC actually acts on. A message
 * can authenticate perfectly and still fail here, because the domain
 * that authenticated is not the domain the reader sees in the From
 * field.
 *
 * `$dkimAuth` and `$spfAuth` come from <auth_results>: the raw
 * verdicts, before alignment is considered. They are useful for
 * diagnosis — "SPF passed, so the sending server is legitimate, it is
 * only the domain that does not line up" — but a policy is never
 * decided on them.
 */
final class Record
{
    /**
     * @param list<string> $dkimAuthDomains domains that signed, from <auth_results>
     */
    public function __construct(
        public readonly string $sourceIp,
        public readonly int $count,
        public readonly string $disposition,   // none | quarantine | reject
        public readonly string $dkimAligned,   // pass | fail
        public readonly string $spfAligned,    // pass | fail
        public readonly string $headerFrom,
        public readonly array $dkimAuthDomains = [],
        public readonly ?string $spfAuthDomain = null,
        public readonly ?string $spfAuthResult = null,
    ) {
    }

    /**
     * DMARC passes if EITHER aligned check passes — not both.
     *
     * This is worth saying out loud, because most people read their
     * first report in a panic over the "spf fail" rows. A source that
     * fails aligned SPF but passes aligned DKIM is fine, and will stay
     * fine when the policy is tightened. Forwarders behave exactly like
     * this: forwarding breaks SPF and leaves the DKIM signature intact.
     */
    public function passesDmarc(): bool
    {
        return $this->dkimAligned === 'pass' || $this->spfAligned === 'pass';
    }

    /**
     * Authenticated, but under the wrong domain.
     *
     * This is the single most common real finding: a newsletter tool or
     * an invoicing service sends on your behalf, its own SPF is in
     * order, but the envelope domain is theirs — so DMARC sees nothing
     * that belongs to you. It is fixed by configuration at the sender,
     * not by editing your DNS record.
     */
    public function isMisaligned(): bool
    {
        return !$this->passesDmarc() && $this->spfAuthResult === 'pass';
    }
}
