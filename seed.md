# Seeding the public threat graph — a curator's guide

How to fill the **public threat graph** (the on-chain VM tier) with data that
actually protects users. This is the operational companion to
[CURATOR_README.md](CURATOR_README.md) — read that first for the trust model.

---

## What the public graph is (and isn't)

It's a **verification database of confirmed, known-bad *identities***. An agent
about to act computes a canonical identifier for what it's doing
(`dep:npm:node-ipc@9.1.6`) and asks the graph: *"is this a confirmed threat?"*
If yes → **found in the public threat graph** → flagged (and blocked in block
mode), with a link to the advisory.

So the graph answers exactly one question well: **"is this specific artifact
known-bad?"** It is **not** a behavioral engine — novel attacks, new phrasings,
and structural patterns are caught by the *local* detector and only reach the
graph after a curator confirms them. Seed accordingly: put **stable identities**
in the graph, leave **behaviors** to local rules.

---

## The five golden rules

1. **Precision over recall — always.** One false block on a legitimate package
   and the user disables Guardian forever. It is better to ship 500 entries with
   zero false positives than 5,000 with two. When unsure, **don't seed it**.
2. **Distinguish malicious from merely-vulnerable — and act on them
   differently.** Both belong in the graph, but they are not the same threat.
   *Malicious* (malware / compromised release / typosquat) → severity `critical`
   → **blocks** in block mode. *Vulnerable-but-legit* (a CVE in otherwise-good
   code) → severity `high` at most → **flags, never auto-blocks** (block mode
   only stops `critical`). **Tag every entry** with its `kind` (`malware` vs
   `vulnerability`) so the UI and the block policy can tell them apart —
   otherwise you'll false-block widely-used packages that merely have an open CVE.
3. **Provenance on every entry — the more proof, the better.** Each threat
   carries *two* proofs: (a) the **official advisory page** (GHSA / OSV / Socket
   URL) in `references[]`, and (b) the **on-chain DKG asset** (its UAL) once
   published — tamper-proof and publicly verifiable. The "found in the public
   graph" panel links to **both**. No source → no entry.
4. **Curate, don't dump.** Raw feeds are noisy (the first bumblebee import threw
   ~1,885 errors and produced malformed ids like `dep:npm:@@antv/...`). Clean,
   normalize, dedupe **before** publishing.
5. **Never hand-write identifiers.** Always feed *structured fields* and let the
   builders compute the id. The identifier a curator seeds must be byte-identical
   to what the local detector derives, or the lookup silently misses. The tooling
   guarantees this — you just supply `ecosystem`/`name`/`version`, etc.

---

## What belongs in the graph

| Type | Identifier | Seed it for | Notes |
|------|-----------|-------------|-------|
| **dependency** | `dep:{eco}:{name}@{version}` | compromised/malicious packages (Shai-Hulud, node-ipc, event-stream, typosquats) | **the flagship — ~80% of value** |
| **skill** | `skill:{name}@{version}` or `skill:{name}:{shape}` | known-malicious agent skills/plugins | version-specific or behavior-shape |
| **injection** | `injection:{sha256(pattern)}` | **confirmed** prompt-injection *signatures* (regex) | curated regex library; novel wording is local's job |
| **escalation** | `escalation:{tool}:{argShape}` | dangerous command shapes (curl-pipe-bash) | mostly *structural* — see note below |
| **fileaccess** | `fileaccess:{tool}:{category}` | known sensitive-path access patterns | mostly *structural* — see note below |

> **Note on injection / escalation / fileaccess:** these are more *behavioral*
> than *identity*. Universal shapes (`curl … | bash`, `rm -rf /`, reading
> `~/.ssh`) are better shipped as **always-on local rules** — they never change
> and should work offline. Reserve the graph for these only when a pattern is
> *specific and evolving* (a new injection campaign, a novel escalation seen in
> the wild). Don't try to enumerate universal behaviors into the graph.

**Missing category worth adding:** **bad domains / exfil & C2 endpoints**
(`net:domain:evil.sh`) — pure identity, hugely collective ("this agent is about
to POST your data to a known exfil host"). Strong candidate for the next builder.

---

## Identifiers & deduplication

The identifier **is** the dedup key: one knowledge asset per canonical id.
Duplicates only happen when the *same* threat produces *different* ids, so
canonicalize the inputs before import:

- **ecosystem** → lowercased (`npm`, `pypi`, `rubygems`, `cargo`, `go`).
- **npm package names** → lowercase (npm treats names case-insensitively;
  `Node-IPC` and `node-ipc` are the same package). Strip stray characters — the
  `@@antv` bug was a double-`@` in the source name.
- **version** → exact published string, no `v` prefix, no ranges (see below).
- **injection pattern** → the id hashes the *regex source*, so two curators
  writing the same regex differently (`ignore\s+previous` vs `ignore +previous`)
  create two entries. Agree on a canonical form; prefer the simplest regex that
  matches the campaign.

**Version granularity — the one real design choice.** Two cases:
- *Compromised release* (node-ipc@9.1.6 bad, 9.1.7 fine) → seed the **exact
  bad versions**. This is what `dep:{eco}:{name}@{version}` does today.
- *Wholly-malicious package* (a typosquat — every version is malware) →
  **enumerate the known-bad versions** (keeps the id scheme simple and exact).
  Caveat: a *new* malicious version isn't caught until a curator adds it, so
  re-check these packages whenever the source feed updates. (If typosquats become
  common, revisit a package-level `dep:{eco}:{name}@*` entry.)

---

## The seed file format

`hermes guardian curate import --file catalog.json` accepts a JSON catalog. Use
the **split format** (clearest for hand-curation):

```json
{
  "dependencies": [
    {
      "ecosystem": "npm",
      "name": "node-ipc",
      "version": "9.1.6",
      "kind": "malware",
      "severity": "critical",
      "title": "node-ipc protestware (peacenotwar)",
      "summary": "Overwrites files on disk based on geolocation.",
      "advisoryId": "GHSA-97m3-w2cp-4xx6",
      "references": ["https://github.com/advisories/GHSA-97m3-w2cp-4xx6"]
    }
  ],
  "injection": [
    {
      "pattern": "ignore (all )?previous instructions",
      "severity": "high",
      "owasp": "LLM01",
      "title": "Instruction override",
      "summary": "Classic direct prompt injection."
    }
  ],
  "escalation": [
    { "toolName": "shell", "argShape": "remote-script-pipe",
      "severity": "critical", "title": "curl | bash" }
  ],
  "skills": [
    { "skillName": "totally-safe-helper", "version": "1.0.3",
      "severity": "critical", "title": "Skill exfiltrates env on install" }
  ]
}
```

**Required fields per type** (everything else is optional but *provenance is
strongly encouraged*):
- **dependency**: `ecosystem`, `name` (or `package`), `version`. Recommended:
  `kind` (`malware` | `vulnerability`), `severity`, `title`, `summary`,
  `advisoryId`, `references[]`.
- **injection**: `pattern` (regex). Recommended: `severity`, `owasp`, `title`.
- **escalation**: `toolName` + `argShape`.
- **fileaccess**: `toolName` (or `tool`) + `category`.
- **skill**: `skillName` (or `skill`) + `version` (or a `dangerShape`).

Other accepted shapes: a generic `{ "threats": [ { "type": "dependency", … } ] }`
list, a bare `[ … ]` array with `--type dependency`, and the raw bumblebee
`{ "entries": [ { "package", "versions": […] } ] }` (auto-fanned per version).

**`severity` + `kind` drive behavior.** Block mode stops **`critical` only**, so:
- **malware** (`kind: malware`) → `critical` → **blocks**. Reserve this for "the
  agent doing this is compromised right now" (malware install, active exfil).
- **vulnerability** (`kind: vulnerability`) → `high` at most → **flags, never
  auto-blocks**. This is how a legit-but-vulnerable package (an open CVE) shows up
  as a warning without stopping the agent from using it.

That split — malware blocks, vulns flag — is what lets you include vulnerabilities
without false-blocking half of npm.

---

## Where to get good data

Aggregate + curate — don't reinvent. Priority order:

1. **OSV.dev** — the canonical open-source vuln/malware feed. Guardian already
   has an OSV client; `curate import --osv-enrich` backfills advisory metadata on
   dependency entries. **Filter to `MAL`/malware advisories first.**
2. **GitHub Advisory Database (GHSA)** — well-structured, has malware category.
3. **Socket.dev** malware feeds — the source behind your bumblebee data; strong
   on npm supply-chain worms (Shai-Hulud, GlassWorm).
4. **npm / PyPI takedown & malware lists** — packages already removed for
   malware are safe, high-precision seeds.
5. **Your bumblebee `threat_intel/`** — Socket-derived; **curate it** (dedupe,
   fix names, drop malformed) before publishing.

For each source, map its fields into the split-format catalog above, then run it
through the workflow below.

### Hitting ~100k, high-precision

Realistic volume, malware-first (blockable), toward the 100k target:

| Source | Rough volume | Notes |
|--------|-------------|-------|
| **OSV `MAL-` malware advisories** (npm + PyPI + others) | ~90k–100k+ | The bulk. Confirmed-malicious, structured, provenance built in. This alone can carry the 100k. |
| **GHSA malware-category** | thousands | Overlaps OSV; dedup handles it. |
| **Socket.dev / bumblebee** | thousands | Freshest npm supply-chain worms; curate before publishing. |
| **npm/PyPI takedown lists** | thousands | Already-removed = high precision. |
| High-severity **vulnerabilities** (OSV non-`MAL`) | as many as you want, but `kind: vulnerability` | Flag-only; keep severity ≤ `high` so they never block. |

Recommendation: **seed malware first** (the 90k+ from OSV `MAL-`), prove
detection over a few batches, *then* layer in vulnerabilities as flag-only. That
front-loads the blockable, high-value threats and de-risks the TRAC spend.

---

## The seeding workflow (mainnet, batched)

We publish **directly to mainnet** — the real public threat graph. Every VM
publish costs TRAC, so the flow is built to spend TRAC only on genuinely-new
threats. Target: **~100k assets, seeded in ~5k batches** so you can watch
detection light up batch by batch.

```bash
# 0. one-time: create the public graph on mainnet (curator wallet only)
hermes guardian setup-graph --network mainnet-base

# 1. DRY RUN first — see how many are NEW after dedup. Spends no TRAC.
hermes guardian curate import --file batch-01.json --osv-enrich --dry-run
#   → "Dry run: 4,812 NEW threats would publish, 188 skipped as duplicates, 0 errors."

# 2. publish the batch to mainnet. Dedup skips anything already seeded, so this
#    only pays TRAC for new identifiers. Re-running a batch is safe — never
#    double-publishes.
hermes guardian curate import --file batch-01.json --osv-enrich

# 3. (optional) also skip anything already on-chain — authoritative dedup if the
#    local ledger was lost or you seed from a second machine.
hermes guardian curate import --file batch-02.json --osv-enrich --check-graph

# 4. verify detection with a real agent before the next batch, then repeat.
hermes guardian curate reject dep:npm:some-legit-pkg@1.0.0 --dispute   # pull a false positive fast
```

### Deduplication — how TRAC is protected

- **The identifier is the dedup key** (one asset per canonical id), and dedup is
  enforced at *three* layers so you never pay to publish the same threat twice:
  1. **In-batch** — the same id twice in one file publishes once.
  2. **Seeded ledger** — `curate import` records every published identifier in
     `$GUARDIAN_HOME/seeded_identifiers.txt` and skips it next time. Overlapping
     batches and re-runs cost nothing.
  3. **`--check-graph`** — optionally queries the VM once and skips everything
     already on-chain (the authoritative set).
- **Always `--dry-run` a batch first.** It applies all dedup and tells you the
  exact number of *new* publishes — i.e. your TRAC bill — before you spend it.
- Normalize inputs before import (lowercase npm names, strip junk) so two
  spellings of the same package don't become two paid publishes.

### Storage life vs cost (`--epochs`)

A DKG asset is stored for the number of **epochs** you pay for, then expires
unless renewed. `curate import` defaults to `--epochs 1` (cheapest), but a
*persistent* public threat graph shouldn't evaporate after one epoch — decide
your storage horizon up front:

```bash
hermes guardian curate import --file batch-01.json --epochs 12   # ~longer on-chain life, more TRAC
```

Higher epochs = longer life = more TRAC per asset, so at 100k assets this is your
biggest cost lever. Pick an epoch count that matches how long a threat stays
relevant, and plan a renewal pass for anything that must outlive it.

### Seeding bumblebee

Bumblebee's `threat_intel/` is Socket-confirmed compromised packages — seed all
of it. `--dir` imports every catalog; the importer auto-tags them `kind: malware`
and repairs the malformed `@@scope` names so they match real installs:

```bash
hermes guardian curate import --dir ~/Desktop/bumblebee/threat_intel --dry-run   # preview (~2,937 threats)
hermes guardian curate import --dir ~/Desktop/bumblebee/threat_intel             # publish to mainnet
```

(Worth fixing at the source too: ~26% of bumblebee packages carry a double-`@`
(`@@antv/...`). The importer normalizes it, but cleaner upstream data avoids
relying on that.)

---

## Step-by-step: rehearse on staging, then production

Publishing to mainnet **registers the graph name on-chain** — once you seed under
a name, it's spent. So **rehearse the whole pipeline under a throwaway `-staging`
name first**, prove detection end-to-end, then run the real seed under the
reserved production name.

> ### ⚠️ Set two things before any seeding command
> ```bash
> export GUARDIAN_CONTEXT_GRAPH_ID="umanitek/guardian-threats-staging"   # NOT the production name
> export GUARDIAN_HOME="$HOME/.guardian-staging"                         # isolate the dedup ledger
> ```
> Verify — `hermes guardian status | grep "context graph"` **must** end in
> `-staging`. If it shows the bare production name, stop and re-export, or you'll
> burn that name on-chain.
>
> **Why the separate `GUARDIAN_HOME`:** the dedup ledger
> (`$GUARDIAN_HOME/seeded_identifiers.txt`) is a single global file, **not** keyed
> by graph name. Seed staging against the default home and the production run
> later sees every id as "already published" and skips them — leaving production
> empty. A separate home keeps the staging ledger isolated.

**0. Preconditions**
- Curator wallet funded: **ETH** (gas) + **TRAC** (publish).
- Local DKG node on **mainnet-base**, reachable: `dkg hermes setup --network mainnet-base`
  → `curl -s http://127.0.0.1:9200/api/status`.
- `hermes guardian status` runs.
- A **small** first batch (`batch-01.json`, 20–50 known-bad packages) — enough to
  prove detection. Save the 100k for production.

**1. Isolated staging shell** — set the two env vars above; confirm the graph name.

**2. Create + register the staging graph** (one-time, on-chain, small ETH/TRAC):
```bash
hermes guardian setup-graph --network mainnet-base
```

**3. Dry-run** (spends nothing — prints the TRAC bill):
```bash
hermes guardian curate import --file batch-01.json --osv-enrich --dry-run
```
Fix any `errors` first; zero errors + a sane new-count → proceed.

**4. Publish the batch:**
```bash
hermes guardian curate import --file batch-01.json --osv-enrich --epochs 1
```
Re-running is safe — the ledger skips anything already published.

**5. Verify a real catch:**
```bash
hermes guardian sync         # pull the new threats into the local ruleset
hermes guardian dashboard    # Public tab shows your seeds
```
Then in an agent, `npm install <a-seeded-bad-package>@<seeded-version>` → it shows
in live findings as a **confirmed public-graph match**. Add `GUARDIAN_MODE=block`
to see it actually blocked.

**6. Iterate** the remaining batches (steps 3–5 each). Lost the ledger / seeding
from another machine? Add `--check-graph`. False positive? `curate reject <id> --dispute`.

**7. Production run** — identical steps, only two things change:
1. The **reserved production name** (not `-staging`).
2. A **clean ledger** — use the default `GUARDIAN_HOME` (`unset` the staging one)
   so production actually receives every threat. Plus a longer `--epochs` and the
   full batch set.

---

## Maintenance

- **Freshness:** malicious packages get taken down and re-published under new
  versions. Re-run source feeds periodically; add new bad versions as they appear.
- **Corrections:** if you publish a false positive, `curate reject --dispute`
  and remove it fast — trust is the whole product.
- **Don't let it rot:** a graph full of stale or low-quality entries is worse
  than a small sharp one. Prune aggressively.

---

## Anti-patterns — do NOT seed

- ❌ CVE-vulnerable-but-legit packages as blocking `critical` (alert fatigue,
  false blocks).
- ❌ Hand-written identifiers or entries without a source.
- ❌ Whole ecosystems dumped raw from a feed without review.
- ❌ Universal behaviors (`curl | bash`) as thousands of graph entries — that's a
  local rule.
- ❌ Overly-broad injection regexes that match benign text (test them first).

---

## Decisions (locked)

1. **Typosquats / whole-package malware:** enumerate known-bad versions;
   re-check on feed updates. (Package-level `@*` revisited later if needed.)
2. **Scope:** confirmed-malicious **and** high-severity vulnerabilities — but
   `kind`-tagged and acted on differently: **malware blocks, vulnerabilities
   flag**. Precision rule #1 matters even more now that legit-but-vulnerable
   packages are in scope.
3. **Proof shown in the UI:** the **official advisory page** *and* the on-chain
   **DKG UAL** — maximum verifiable provenance for every flagged threat.
4. **Network:** publish **directly to mainnet** — no testnet. The valid dkg
   networks are `mainnet-base` (Base, ETH gas) and `mainnet-gnosis` (Gnosis, xDAI
   gas); we use **`mainnet-base`**. Reading is free; only curators pay TRAC.
5. **Scale & cadence:** ~**100k assets**, seeded in ~**5k batches**, malware
   first. `--dry-run` every batch to see the TRAC bill; three-layer dedup
   ensures you only ever pay for genuinely-new threats.
