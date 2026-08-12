<?php

declare(strict_types=1);

namespace KK\Dmarc;

/**
 * One aggregate report: what a single receiver saw from your domain
 * over one day.
 *
 * "One day" matters. Reports arrive per receiver, per day, so a real
 * picture is only built by reading many of them together — one report
 * from one provider says almost nothing.
 */
final class AggregateReport
{
    /** @param list<Record> $records */
    public function __construct(
        public readonly string $orgName,
        public readonly string $reportId,
        public readonly \DateTimeImmutable $begin,
        public readonly \DateTimeImmutable $end,
        public readonly string $domain,
        public readonly string $policy,        // none | quarantine | reject
        public readonly string $subdomainPolicy,
        public readonly int $percentage,
        public readonly string $dkimAlignment, // r (relaxed) | s (strict)
        public readonly string $spfAlignment,
        public readonly array $records,
    ) {
    }

    /** Total messages covered by this report. */
    public function messageCount(): int
    {
        return array_sum(array_map(static fn (Record $r): int => $r->count, $this->records));
    }

    public function passingCount(): int
    {
        return array_sum(array_map(
            static fn (Record $r): int => $r->passesDmarc() ? $r->count : 0,
            $this->records
        ));
    }
}
