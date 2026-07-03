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

---

## The seeding workflow

```bash
# 0. one-time: create the public graph (curator wallet only)
hermes guardian setup-graph

# 1. stage a batch to the community tier (SWM) WITHOUT publishing on-chain yet
hermes guardian curate import --file npm-malware-2026-07.json --osv-enrich --no-publish

# 2. review what you staged — grouped, with reporters + provenance
hermes guardian curate list --pending
hermes guardian curate show dep:npm:node-ipc@9.1.6

# 3. promote the good ones to the PUBLIC graph (VM, on-chain)
hermes guardian curate approve dep:npm:node-ipc@9.1.6 --severity critical

# 4. reject a false positive; optionally publish a false-positive note
hermes guardian curate reject dep:npm:some-legit-pkg@1.0.0 --dispute
```

**Always `--no-publish` on the first import.** It stages to SWM so you can review
before anything hits the public, blockable graph. Publishing to VM is the
irreversible, everyone-sees-it step — treat it like a release.

Dedup is automatic (one asset per canonical id), but **review for near-dupes**
across ecosystems/case before approving a large batch.

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
