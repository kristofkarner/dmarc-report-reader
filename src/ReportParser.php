<?php

declare(strict_types=1);

namespace KK\Dmarc;

/**
 * Turns an aggregate report into objects.
 *
 * Reports arrive as email attachments, and in practice in three
 * shapes: plain .xml, gzipped .xml.gz, and zipped .zip. Which one you
 * get depends on the receiver, not on you — so all three are handled
 * here rather than left to whoever downloads them.
 */
final class ReportParser
{
    /** @return list<AggregateReport> one file may hold several reports */
    public function parseFile(string $path): array
    {
        if (!is_readable($path)) {
            throw new DmarcException("Cannot read: {$path}");
        }

        $name = strtolower(basename($path));

        if (str_ends_with($name, '.zip')) {
            return $this->parseZip($path);
        }

        $raw = file_get_contents($path);
        if ($raw === false) {
            throw new DmarcException("Cannot read: {$path}");
        }

        if (str_ends_with($name, '.gz')) {
            $raw = @gzdecode($raw);
            if ($raw === false) {
                throw new DmarcException("Damaged gzip: {$path}");
            }
        }

        return [$this->parseXml($raw)];
    }

    /** @return list<AggregateReport> */
    private function parseZip(string $path): array
    {
        $zip = new \ZipArchive();
        if ($zip->open($path) !== true) {
            throw new DmarcException("Cannot open zip: {$path}");
        }

        $reports = [];
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $entry = $zip->getNameIndex($i);
            if ($entry === false || !str_ends_with(strtolower($entry), '.xml')) {
                continue;
            }
            $xml = $zip->getFromIndex($i);
            if ($xml !== false) {
                $reports[] = $this->parseXml($xml);
            }
        }
        $zip->close();

        if ($reports === []) {
            throw new DmarcException("No XML inside the zip: {$path}");
        }

        return $reports;
    }

    public function parseXml(string $xml): AggregateReport
    {
        // These files arrive by email from strangers. A report never needs
        // a DTD, so one is refused outright: that closes external entities
        // (reading local files on request) and entity-expansion bombs
        // alike. LIBXML_NOENT must not be passed here — despite its name,
        // it turns entity substitution ON.
        if (preg_match('/<!DOCTYPE/i', $xml) === 1) {
            throw new DmarcException('Refusing a report with a DOCTYPE.');
        }

        $previous = libxml_use_internal_errors(true);
        $feedback = simplexml_load_string($xml, options: LIBXML_NONET);
        libxml_use_internal_errors($previous);

        if ($feedback === false) {
            throw new DmarcException('Unparseable XML.');
        }

        $meta = $feedback->report_metadata;
        $policy = $feedback->policy_published;

        $records = [];
        foreach ($feedback->record as $record) {
            $evaluated = $record->row->policy_evaluated;

            $dkimDomains = [];
            foreach ($record->auth_results->dkim ?? [] as $dkim) {
                $domain = trim((string) $dkim->domain);
                if ($domain !== '') {
                    $dkimDomains[] = $domain;
                }
            }

            $spf = $record->auth_results->spf[0] ?? null;

            $records[] = new Record(
                sourceIp: (string) $record->row->source_ip,
                count: (int) $record->row->count,
                disposition: (string) ($evaluated->disposition ?: 'none'),
                dkimAligned: (string) ($evaluated->dkim ?: 'fail'),
                spfAligned: (string) ($evaluated->spf ?: 'fail'),
                headerFrom: (string) $record->identifiers->header_from,
                dkimAuthDomains: $dkimDomains,
                spfAuthDomain: $spf !== null ? (string) $spf->domain : null,
                spfAuthResult: $spf !== null ? (string) $spf->result : null,
            );
        }

        return new AggregateReport(
            orgName: (string) $meta->org_name,
            reportId: (string) $meta->report_id,
            begin: (new \DateTimeImmutable())->setTimestamp((int) $meta->date_range->begin),
            end: (new \DateTimeImmutable())->setTimestamp((int) $meta->date_range->end),
            domain: (string) $policy->domain,
            // <p> is required; the rest have defaults the RFC spells out,
            // and receivers do leave them out.
            policy: (string) ($policy->p ?: 'none'),
            subdomainPolicy: (string) ($policy->sp ?: ($policy->p ?: 'none')),
            percentage: (int) ($policy->pct ?: 100),
            dkimAlignment: (string) ($policy->adkim ?: 'r'),
            spfAlignment: (string) ($policy->aspf ?: 'r'),
            records: $records,
        );
    }
}
