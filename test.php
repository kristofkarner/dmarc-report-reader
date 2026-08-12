<?php

declare(strict_types=1);

/*
 * Runs against the made-up report in sample/. No network, no mailbox.
 *
 *   php test.php
 */

require __DIR__ . '/src/DmarcException.php';
require __DIR__ . '/src/Record.php';
require __DIR__ . '/src/AggregateReport.php';
require __DIR__ . '/src/ReportParser.php';
require __DIR__ . '/src/Summary.php';

use KK\Dmarc\{DmarcException, ReportParser, Summary};

$fail = static function (string $message): never {
    fwrite(STDERR, "FAILED: {$message}\n");
    exit(1);
};

$parser = new ReportParser();
[$report] = $parser->parseFile(__DIR__ . '/sample/example-report.xml');

// 1 · Metadata
$report->orgName === 'google.com' || $fail('reporting organisation');
$report->domain === 'example.com' || $fail('domain');
$report->policy === 'none' || $fail('policy');
$report->percentage === 100 || $fail('percentage');
count($report->records) === 4 || $fail('number of records');
echo "parsing OK — {$report->orgName}, {$report->begin->format('Y-m-d')}, "
   . count($report->records) . " sources\n";

// 2 · One aligned pass is enough. The forwarder fails SPF and still passes.
$forwarder = $report->records[1];
$forwarder->spfAligned === 'fail' || $fail('the forwarder should fail aligned SPF');
$forwarder->passesDmarc() || $fail('DKIM alone should carry DMARC');
echo "forwarder passes on DKIM alone OK\n";

// 3 · The interesting case: SPF passed, but under someone else's domain
$newsletter = $report->records[2];
$newsletter->passesDmarc() === false || $fail('the newsletter should fail DMARC');
$newsletter->spfAuthResult === 'pass' || $fail('raw SPF should be a pass');
$newsletter->isMisaligned() || $fail('this is misalignment, not an SPF failure');
echo "misalignment recognised OK ({$newsletter->spfAuthDomain})\n";

// 4 · And the one where nothing authenticates at all
$spoof = $report->records[3];
$spoof->isMisaligned() === false || $fail('softfail is not misalignment');
echo "unauthenticated source not confused with misalignment OK\n";

// 5 · Totals
$report->messageCount() === 600 || $fail('total message count');
$report->passingCount() === 142 || $fail('passing message count');
echo "totals OK — {$report->passingCount()}/{$report->messageCount()}\n";

// 6 · The summary, and the list the whole thing exists for
$summary = Summary::fromReports([$report]);
count($summary->sources) === 4 || $fail('number of sources');
abs($summary->passRate() - 142 / 600) < 0.0001 || $fail('pass rate');
count($summary->failingSources()) === 2 || $fail('failing sources');
$summary->failingSources()[0]->ip === '203.0.113.55' || $fail('sorted by volume');
$summary->failingSources()[0]->looksMisaligned() || $fail('misaligned source not flagged');
$summary->failingSources()[1]->looksMisaligned() === false || $fail('spoofed source wrongly flagged');
printf("summary OK — pass rate %.1f%%, %d source(s) a stricter policy would hit\n",
    $summary->passRate() * 100, count($summary->failingSources()));

// 7 · The same report gzipped: same result
$gz = sys_get_temp_dir() . '/dmarc-test-' . getmypid() . '.xml.gz';
file_put_contents($gz, gzencode(file_get_contents(__DIR__ . '/sample/example-report.xml')));
[$fromGz] = $parser->parseFile($gz);
unlink($gz);
$fromGz->messageCount() === 600 || $fail('gzip read');
echo "gzipped report read OK\n";

// 8 · A damaged file is an error, not a silently empty report
try {
    $parser->parseXml('this is not xml');
    $fail('accepted unparseable input');
} catch (DmarcException) {
    echo "damaged input rejected OK\n";
}

echo "\nall checks passed\n";
