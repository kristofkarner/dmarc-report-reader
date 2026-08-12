#!/usr/bin/env php
<?php

declare(strict_types=1);

/*
 * Reads a folder of DMARC aggregate reports and prints what is in them.
 *
 *   php bin/dmarc-summary.php ~/Downloads/dmarc/
 *   php bin/dmarc-summary.php report1.xml.gz report2.zip
 *
 * Save the attachments from the reports mailbox into one folder and
 * point this at it. Nothing is uploaded anywhere; the files are read
 * where they are.
 */

require __DIR__ . '/../src/DmarcException.php';
require __DIR__ . '/../src/Record.php';
require __DIR__ . '/../src/AggregateReport.php';
require __DIR__ . '/../src/ReportParser.php';
require __DIR__ . '/../src/Summary.php';

use KK\Dmarc\{DmarcException, ReportParser, Source, Summary};

$args = array_slice($argv, 1);
if ($args === []) {
    fwrite(STDERR, "Usage: php bin/dmarc-summary.php <folder or files>\n");
    exit(1);
}

$paths = [];
foreach ($args as $arg) {
    if (is_dir($arg)) {
        foreach (['*.xml', '*.xml.gz', '*.gz', '*.zip'] as $pattern) {
            $paths = array_merge($paths, glob(rtrim($arg, '/') . '/' . $pattern) ?: []);
        }
    } else {
        $paths[] = $arg;
    }
}
$paths = array_values(array_unique($paths));

if ($paths === []) {
    fwrite(STDERR, "No report found there.\n");
    exit(1);
}

$parser = new ReportParser();
$reports = [];
$skipped = 0;

foreach ($paths as $path) {
    try {
        $reports = array_merge($reports, $parser->parseFile($path));
    } catch (DmarcException $e) {
        // One damaged attachment must not take the rest with it — but
        // say so, rather than quietly reading fewer reports than the
        // folder contains.
        fwrite(STDERR, "skipped: {$path} — {$e->getMessage()}\n");
        $skipped++;
    }
}

if ($reports === []) {
    fwrite(STDERR, "Nothing could be read.\n");
    exit(1);
}

$summary = Summary::fromReports($reports);

printf("%d report(s) from %d receiver(s)%s\n", count($reports), count($summary->reporters), $skipped > 0 ? sprintf(', %d skipped', $skipped) : '');
printf("period:   %s — %s\n", $summary->from?->format('Y-m-d') ?? '?', $summary->to?->format('Y-m-d') ?? '?');
printf("policy:   p=%s\n", implode(', p=', $summary->policies));
printf("messages: %d, of which DMARC-passing: %d (%.1f%%)\n\n", $summary->total, $summary->passing, $summary->passRate() * 100);

printf("%-40s %8s %8s  %s\n", 'SOURCE', 'TOTAL', 'PASSING', 'AUTHENTICATED AS');
printf("%s\n", str_repeat('-', 78));

/** @var Source $source */
foreach ($summary->sources as $source) {
    $domains = array_keys($source->dkimDomains + $source->spfDomains);
    printf(
        "%-40s %8d %8d  %s%s\n",
        $source->ip,
        $source->total,
        $source->passing,
        $domains === [] ? '—' : implode(', ', array_slice($domains, 0, 3)),
        $source->looksMisaligned() ? '  [misaligned]' : ''
    );
}

$failing = $summary->failingSources();
if ($failing === []) {
    echo "\nNo failing source in this period.\n";
    exit(0);
}

echo "\nSources a stricter policy would affect:\n";
foreach ($failing as $source) {
    printf("  %-40s %d message(s)%s\n", $source->ip, $source->failing(), $source->looksMisaligned()
        ? ' — SPF passed, but under another domain: this one is fixed at the sender'
        : '');
}

// Deliberately no "safe to tighten" verdict. The number does not decide
// it; whether every line above is a sender you recognise does.
echo "\nGo through the list. Anything you do not recognise is worth finding out about\n"
   . "before the policy is tightened — after it, those messages stop arriving.\n";
