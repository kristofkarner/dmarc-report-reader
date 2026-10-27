# DMARC report reader

Turn on DMARC and the reports start arriving: zipped XML, every day,
from every mail provider on earth. This reads them and tells you the one
thing you need before tightening the policy — **which senders would stop
being delivered.**

```
$ php bin/dmarc-summary.php ~/Downloads/dmarc/

31 report(s) from 6 receiver(s)
period:   2026-08-01 — 2026-08-10
policy:   p=none
messages: 4218, of which DMARC-passing: 3960 (93.9%)

SOURCE                                      TOTAL  PASSING  AUTHENTICATED AS
------------------------------------------------------------------------------
192.0.2.10                                   3811     3811  example.com
203.0.113.55                                  244        0  mail.newsletter-tool.example  [misaligned]
198.51.100.7                                  149      149  example.com, forwarder.example.net
203.0.113.201                                  14        0  example.com
```

## The distinction the whole thing turns on

A DMARC report gives you two sets of results, and they are not the same
thing. Almost every misreading starts here.

**`policy_evaluated`** holds the *aligned* results — the ones DMARC acts
on. **`auth_results`** holds the raw verdicts, before alignment is
considered. A message can authenticate perfectly and still fail DMARC,
because the domain that authenticated is not the domain the reader sees
in the From field.

That gap is where the real finding usually is. A newsletter tool or an
invoicing service sends on your behalf; its own SPF is in order, but the
envelope domain is theirs, so DMARC sees nothing that belongs to you.
The fix is configuration at the sender, not another edit to your DNS
record — and no amount of staring at your own SPF line will reveal it.
The tool marks these `[misaligned]`.

Two more things worth knowing before you read your first report:

**DMARC passes if *either* aligned check passes — not both.** Most
people read their first report in a panic over the `spf fail` rows. A
source that fails aligned SPF but passes aligned DKIM is fine, and stays
fine when the policy is tightened. Forwarding does exactly this: it
breaks SPF and leaves the DKIM signature intact.

**One report says almost nothing.** Reports arrive per receiver, per
day. A picture only emerges from reading a couple of weeks of them
together, which is why this reads a whole folder rather than one file.

## What it does not do

**It does not tell you it is safe to tighten the policy.** No pass rate
decides that. The question is whether every source on the failing list is
one you recognise and are willing to lose — and only you know that. The
tool's job is to make the list short and readable; the judgement stays
yours.

It also does not fetch, unpack or delete anything from a mailbox. Save
the attachments into a folder and point it there. Nothing leaves the
machine.

## Usage

No dependencies beyond PHP 8.1 and the `simplexml`, `zip` and `zlib`
extensions.

```bash
php bin/dmarc-summary.php ~/Downloads/dmarc/
```

It takes a folder or individual files, and accepts the three shapes
reports actually arrive in: `.xml`, `.xml.gz` and `.zip`. Which one you
get depends on the receiver, not on you.

There is a made-up report in `sample/` covering the four cases you will
meet — your own server, a forwarder, a misaligned sender, and somebody
using your domain who has nothing to do with you:

```bash
php test.php     # runs against the sample, no network
```

## Reading it into your own code

```php
$reports = (new ReportParser())->parseFile('report.zip');
$summary = Summary::fromReports($reports);

foreach ($summary->failingSources() as $source) {
    echo $source->ip, ' ', $source->failing(), $source->looksMisaligned() ? ' [misaligned]' : '', PHP_EOL;
}
```

The parser refuses any report that carries a DOCTYPE, and never substitutes
entities. These files arrive by email from strangers, and an XML parser that
resolves external entities will happily read local files on request. Copies
from before 27 October 2026 passed `LIBXML_NOENT`, which — despite its name —
turns substitution on; if you use one, update it.

It reads both the original format (RFC 7489) and the one in RFC 9990: a
namespace on the root element, and `<testing>` where `<pct>` used to be.

## Related writing

Why business mail lands in spam, and how the three records fit together:

- [Email authentication: SPF, DKIM, DMARC](https://kristofkarner.com/en/writing/email-authentication-spf-dkim-dmarc/)

> *Magyarul:*
> [E-mail-hitelesítés: SPF, DKIM, DMARC](https://kristofkarner.com/irasok/email-hitelesites-spf-dkim-dmarc/)

## Licence

MIT — use it freely. A star is appreciated if it helped.

---

Built by [Kristóf Karner](https://kristofkarner.com) · independent web
developer, Budapest
