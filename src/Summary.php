<?php

declare(strict_types=1);

namespace KK\Dmarc;

/** One sending source, added up across every report that mentioned it. */
final class Source
{
    public function __construct(
        public readonly string $ip,
        public int $total = 0,
        public int $passing = 0,
        /** @var array<string,true> */
        public array $dkimDomains = [],
        /** @var array<string,true> */
        public array $spfDomains = [],
        public bool $sawSpfAuthPass = false,
    ) {
    }

    public function failing(): int
    {
        return $this->total - $this->passing;
    }

    /**
     * Everything from this source failed, yet SPF itself passed
     * somewhere — the classic "authenticated under the wrong domain".
     */
    public function looksMisaligned(): bool
    {
        return $this->passing === 0 && $this->sawSpfAuthPass;
    }
}

/**
 * Many reports, read together.
 *
 * A single report from a single receiver says very little. The question
 * a summary has to answer is not "what is the pass rate" but "is there
 * a sender here I do not recognise" — because that is what stands
 * between p=none and anything stricter.
 */
final class Summary
{
    /** @param array<string,Source> $sources */
    private function __construct(
        public readonly array $sources,
        public readonly int $total,
        public readonly int $passing,
        public readonly ?\DateTimeImmutable $from,
        public readonly ?\DateTimeImmutable $to,
        /** @var list<string> */
        public readonly array $reporters,
        /** @var list<string> */
        public readonly array $policies,
    ) {
    }

    /** @param list<AggregateReport> $reports */
    public static function fromReports(array $reports): self
    {
        /** @var array<string,Source> $sources */
        $sources = [];
        $total = $passing = 0;
        $from = $to = null;
        $reporters = $policies = [];

        foreach ($reports as $report) {
            $reporters[$report->orgName] = true;
            $policies[$report->policy] = true;
            $from = ($from === null || $report->begin < $from) ? $report->begin : $from;
            $to = ($to === null || $report->end > $to) ? $report->end : $to;

            foreach ($report->records as $record) {
                $source = $sources[$record->sourceIp] ??= new Source($record->sourceIp);
                $source->total += $record->count;
                $total += $record->count;

                if ($record->passesDmarc()) {
                    $source->passing += $record->count;
                    $passing += $record->count;
                }
                if ($record->spfAuthResult === 'pass') {
                    $source->sawSpfAuthPass = true;
                }
                foreach ($record->dkimAuthDomains as $domain) {
                    $source->dkimDomains[$domain] = true;
                }
                if ($record->spfAuthDomain !== null && $record->spfAuthDomain !== '') {
                    $source->spfDomains[$record->spfAuthDomain] = true;
                }
            }
        }

        uasort($sources, static fn (Source $a, Source $b): int => $b->total <=> $a->total);

        return new self(
            $sources,
            $total,
            $passing,
            $from,
            $to,
            array_keys($reporters),
            array_keys($policies),
        );
    }

    public function passRate(): float
    {
        return $this->total === 0 ? 0.0 : $this->passing / $this->total;
    }

    /**
     * The sources that would be affected by a stricter policy.
     *
     * This list is the whole point of the exercise. A pass rate on its
     * own decides nothing: what matters is whether every name on this
     * list is one you recognise and are willing to lose.
     *
     * @return list<Source>
     */
    public function failingSources(): array
    {
        return array_values(array_filter(
            $this->sources,
            static fn (Source $s): bool => $s->failing() > 0
        ));
    }
}
