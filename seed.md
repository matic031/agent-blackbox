# Seeding the Blackbox public threat graph

This is the working runbook for building the Agent Guardian / Blackbox threat
graph into the moat: a high-quality, source-rich corpus of known-bad agent
artifacts that ordinary OSV/CVE scanning, local heuristics, and one-off agent
rules do not cover.

The immediate goals are:

- `catalogs/staging-threats-20k.json`: about 20,000 threats for the public
  staging VM, with the same source families and categories as production.
- `catalogs/prod-threats-250k.json`: about 250,000 high-confidence threats for
  the production public VM. If we can keep quality high, 200k-300k is the
  target band. If quality drops, stop smaller.
- Crypto-specific threats are required, not optional. The production corpus
  must include a visible crypto lane: wallet drainers, seed/private-key
  stealers, malicious Web3 packages, fake WalletConnect/MetaMask/Phantom flows,
  drainer domains/URLs, wallet addresses, contract addresses, and Web3 phishing
  campaigns.
- Every published DKG knowledge asset must carry provenance: named source,
  reference URL(s), and optional contributor attribution.

Dry-run everything first. Publish only after the dry-run is clean and a small
batch has been detected by a real Hermes/OpenClaw agent.

Related trust-model doc: [CURATOR_README.md](CURATOR_README.md).

---

## 1. North star

The threat graph should answer one question extremely well:

> Is this exact agent-touchable artifact known bad?

That means the graph should be full of precise identities:

- `dep:npm:postmark-mcp@1.0.16`
- `dep:pypi:evil-package@*`
- `skill:clawhud@1.0.0`
- `injection:<sha256-of-curated-regex>`

It should not be a dumping ground for broad behavior:

- `curl | bash`
- reads `~/.ssh`
- asks for secrets
- runs shell commands

Those belong in local rules and heuristics. The public VM is for curated,
source-backed identities that can safely become confirmed findings and can
block in block mode.

The moat is not raw count. The moat is the mix of:

- malicious skills and agent extensions that package scanners do not know about;
- malicious MCP servers by identity, not just vulnerable dependencies inside
  them;
- fresh package malware from feeds that catch pre-CVE or silently removed
  registry attacks;
- editor-extension malware that agents inherit from VS Code, Cursor, OpenVSX,
  and similar surfaces;
- crypto drainer packages, malicious Web3 SDKs, wallet-stealing skills, editor
  extensions, drainer domains/URLs, wallet addresses, and contract addresses;
- curated prompt-injection signatures with low false-positive risk.

One false block is more damaging than one miss. If the source is weak or the
identity is ambiguous, keep it in a research catalog and do not publish it.

---

## 2. Provenance contract

Every seedable entry must preserve where it came from. This is now part of the
DKG knowledge asset and the dashboard modal.

Supported provenance fields:

- `source`: named feed or dataset, for example `"OSV.dev"`, `"Socket"`,
  `"Snyk ToxicSkills"`, `"Antiy CERT ClawHavoc"`.
- `sources`: list of named feeds if multiple sources independently confirm it.
- `references`: source URLs, advisory pages, research writeups, takedown pages,
  or dataset records.
- `contributor`: optional attribution for who contributed the asset, for
  example `"Umanitek"`, a researcher handle, an org, or a wallet/DID.

The importer writes these into the DKG asset as:

- `g:source` for named source(s);
- `g:reference` for URL(s);
- `schema:contributor` for contributor attribution.

The dashboard modal shows `Source`, `Contributor`, and `Advisories & references`.

Catalog-level defaults apply to entries that do not override them:

```json
{
  "source": "OSV.dev",
  "contributor": "Umanitek",
  "dependencies": [
    {
      "ecosystem": "npm",
      "name": "node-ipc",
      "version": "9.1.6",
      "kind": "malware",
      "severity": "critical",
      "title": "node-ipc credential stealer",
      "references": ["https://example.com/advisory"]
    }
  ]
}
```

Per-entry values win over catalog defaults. CLI flags are the final fallback:

```bash
hermes blackbox curate import --file catalogs/source.json \
  --source "Socket" \
  --contributor "Umanitek" \
  --dry-run
```

No source means no publish.

---

## 3. Supported categories today

Only publish categories that the current detector can actually match.

| Category | Identifier | Publish now? | Notes |
|---|---|---:|---|
| Dependency malware/vulns | `dep:{ecosystem}:{name}@{version}` | Yes | npm, PyPI, cargo, RubyGems, and other ecosystems that `plugins/blackbox/quads.py` can parse from install commands. `@*` means whole-package malware. |
| Prompt injection | `injection:{hash}` | Yes | Only publish curated regex signatures that were tested against benign prompts. |
| Skill / plugin identity | `skill:{name}@{version}` | Yes | Use for malicious agent skills and installable agent capabilities where the agent sees that identity. |
| Skill danger shape | `skill:{name}:{dangerShape}` | Carefully | Prefer exact known-bad version identities. Shape rules can be noisy. |
| Escalation / file access | `escalation:*`, `fileaccess:*` | Rarely | Usually local rules handle these. Publish only when a curated graph rule is truly needed. |
| Domains / URLs / IPs / file hashes | `ioc:{type}:{value}` | Yes | Matched against agent tool-call text (shell/web/file/args). Flag-only in this rollout (never auto-blocks). Import from `backlog.*` groups or an `iocs` split key. |
| Wallet / contract addresses | `ioc:wallet:*` / `ioc:contract:*` | Yes | EVM/BTC/Solana addresses in tool args. Flag-only. An address seeds as wallet or contract; the detector matches either. |

**IOC lane (added 2026-07-08).** The `ioc:` category makes the domain/url/ip/
hash/wallet/contract backlog publishable. It is FLAG-ONLY for now — network and
crypto-address blocklists churn more than pinned package versions, so IOC matches
always alert but never auto-block; enable blocking per-category once the
false-positive rate is validated in audit mode. Always run IOC catalogs through
the whitelist FP filter before publish (`build_blackbox_seed_bundle.py
--whitelist catalogs/whitelist/umbrella-top1m.csv`; fetch it with
`scripts/fetch_whitelist.py`). See [SOURCE_MENU.md](SOURCE_MENU.md) for the
scored feed menu.

Crypto has two tracks:

- Publish now: malicious Web3 packages, wallet-stealing npm/PyPI/RubyGems
  packages, malicious MCP servers, agent skills, and editor extensions when
  Blackbox can observe them as `dependency` or `skill` identities.
- Collect now, publish later: drainer URLs/domains, phishing pages, wallet
  addresses, contract addresses, IPs, and hashes until the runtime can match
  outbound network actions, browser navigation, wallet operations, or downloaded
  artifacts by those identifiers.

For MCP servers today:

- If the server is installed through npm/PyPI/etc., seed the malicious package
  as a dependency, for example `dep:npm:postmark-mcp@1.0.16`.
- If the server is installed as an agent skill/plugin and the runtime exposes a
  stable capability name/version, seed it as `skill:{name}@{version}`.
- If all we have is a domain, URL, GitHub repo, or registry slug that Blackbox
  does not match yet, keep it in a future-category catalog. Do not burn TRAC on
  inert data.

---

## 4. Source priority

Use this priority order. It is better to ship fewer threats from higher tiers
than to pad the graph.

### Tier A: verified malicious identities

Seed first.

- Private or commercial malware feeds with package/version identity:
  Socket/bumblebee, Phylum, Sonatype, Snyk, ReversingLabs.
- Vendor or researcher advisories naming exact malicious packages, skills, MCP
  servers, or editor extensions.
- Marketplace takedown data naming exact versions or exact extension releases.

### Tier B: public baseline malware

Seed for coverage and volume, but know it is less differentiated.

- [OSV data dumps](https://google.github.io/osv.dev/data/) and
  [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) `MAL-`
  records.
- GitHub Advisory / GHSA malware records when they add identifiers not already
  in OSV.

### Tier C: agent-specific research

Seed after manual review or after converting to exact identities.

- Malicious skill datasets and disclosures, for example
  [Antiy CERT ClawHavoc](https://www.antiy.net/p/clawhavoc-analysis-of-large-scale-poisoning-campaign-targeting-the-openclaw-skill-market-for-ai-agents/),
  [OWASP Agentic Skills Top 10 AST01](https://owasp.org/www-project-agentic-skills-top-10/ast01),
  and [Snyk ToxicSkills](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/).
- MCP incidents and benchmarks, for example
  [Snyk on postmark-mcp](https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/)
  and [MCPTox](https://arxiv.org/html/2508.14925v1).
- Editor-extension malware research for VS Code, Cursor, OpenVSX, and forks.

### Tier D: crypto-drainer and raw IOC sources

Collect aggressively. Publish only the parts the detector can match today; keep
wallet/domain/URL/hash-only records in backlog until matching support lands.

Crypto-specific sources to acquire:

- [ScamSniffer](https://www.scamsniffer.io/) for drainer/phishing domains,
  malicious websites, and Web3 scam infrastructure.
- [Blockaid threat intelligence](https://www.blockaid.io/threat-intelligence)
  for Web3 malware, scam dapps, malicious signatures, and drainer campaigns.
- [Chainabuse](https://chainabuse.com/en/about) / TRM Labs for reported scam
  addresses, URLs, and chain-abuse reports.
- [OpenPhish](https://openphish.com/phishing_feeds.html) and
  [PhishTank](https://www.phishtank.net/developer_info.php), filtered for wallet,
  exchange, NFT, DeFi, and Web3 phishing brands.
- [URLhaus](https://urlhaus.abuse.ch/api/), [ThreatFox](https://threatfox.abuse.ch/api/),
  [ThreatFox exports](https://threatfox.abuse.ch/export/), and MalwareBazaar
  for stealers, loaders, drainer payloads, and C2 linked to crypto theft.
- Vendor/research reports from Netcraft, Group-IB, LevelBlue, Chainalysis,
  Kaspersky, CloudSEK, Socket, Snyk, Checkmarx, ReversingLabs, and others when
  they name exact packages, domains, hashes, wallets, or contracts.

Crypto package/skill/extension identities from these sources are Tier A once
confirmed because they can publish today. Network, wallet, contract, URL, and
hash indicators stay in `catalogs/backlog/crypto-*` until matching support is
implemented.

These are high-value sources, but do not publish domain/URL/hash-only records
until Blackbox can match outbound network actions or artifacts by those ids.

### Tier E: private telemetry and source-discovery atlases

Use these to find seed candidates, validate confidence, and plan million-entry
growth. Do not blindly dump them into the public graph.

- Huntress tenant data: incident reports, escalations, signals, SIEM searches,
  known VPN/proxy findings, and external recon data. This is valuable private
  telemetry when it names hashes, domains, URLs, process paths, remediations,
  users, hosts, or attacker infrastructure from confirmed incidents. It is not
  a bulk public threat feed, so treat it as enrichment and private-derived
  seed candidates with explicit source and contributor labels.
- [hslatman/awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence)
  as the source atlas. The local checkout lives at
  `/Users/matic/Desktop/awesome-threat-intelligence`; use that copy first so
  the links and bundled docs are available offline. It is a curated directory,
  not a seed catalog. Use it to discover feeds, then vet each feed for license,
  freshness, false positives, machine-readable export format, and whether
  Blackbox can match the indicator type.
- CTI platforms and formats from the atlas: MISP, OpenCTI, STIX, TAXII,
  AlienVault OTX, PickupSTIX, and Intel Owl. These are ingestion and enrichment
  rails. Use them to normalize incoming feeds and keep relationships, not as a
  reason to publish low-confidence observables.
- IP reputation sources from the atlas: CrowdSec, AbuseIPDB, GreyNoise,
  FireHOL, IPsum, James Brine feeds, HoneyDB, DataPlane.org, and similar lists.
  These are useful after `ip:` matching exists and useful now for enrichment,
  but they are not the core moat because generic IP blocklists are noisy,
  high-churn, and less agent-specific.
- Malware URL/hash sources from the atlas: URLhaus, ThreatFox, MalwareBazaar,
  DigitalSide, Cyber Cure, InQuest Labs, Malpedia, MalShare, Maltiverse,
  Malware-Traffic-Analysis.net, and Malware Patrol. These become high-volume
  backlog feeds until `url:` / `domain:` / `hash:` matching exists.
- Whitelist/suppression sources from the atlas: Cisco Umbrella top sites,
  Majestic Million, ExoneraTor/Tor context, and other benign/popularity sources.
  Use these to reduce false positives, never as threats.

For the million-entry plan, the unlock is not OSV volume. It is adding first
class `domain:`, `url:`, `ip:`, `hash:`, `wallet:`, and `contract:` assets and
then filling them with high-confidence, source-attributed feeds from this
atlas. Until then, keep those records in backlog catalogs.

---

## 5. Target mix

Staging must be a representative sample, not a toy set. It should contain the
same categories and source families as production, just fewer entries.

### Staging: about 20,000 threats

Target shape:

| Family | Approx count | Current category |
|---|---:|---|
| Fresh dependency malware from Socket/bumblebee/private feeds | 5,000-7,000 | `dependency` |
| Crypto-specific packages, MCP servers, skills, and extensions | 2,000-4,000 | `dependency` and `skill` |
| OSV/OpenSSF `MAL-` baseline sample | 1,500-2,500 | `dependency` |
| Malicious skills, MCP identities, editor extensions | 4,000-6,000 | `skill` and `dependency` |
| Curated injection signatures | 500-1,000 | `injection` |
| Escalation/fileaccess curated rules | 0-200 | only if there is a clear known-bad identity |
| Crypto/network IOC backlog | collected separately | hold until detector support |

Suggested bundle quotas:

```bash
venv/bin/python scripts/build_blackbox_seed_bundle.py \
  catalogs/raw/bumblebee \
  catalogs/raw/agent-skills.json \
  catalogs/raw/mcp-servers.json \
  catalogs/raw/editor-extensions.json \
  catalogs/raw/crypto-packages.json \
  catalogs/raw/crypto-skills.json \
  catalogs/raw/injection-signatures.json \
  catalogs/osv-mal-npm.json \
  catalogs/osv-mal-pypi.json \
  --out catalogs/staging-threats-20k.json \
  --name staging-2026-07 \
  --target 20000 \
  --quota dependency=14000 \
  --quota skill=5000 \
  --quota injection=1000 \
  --family-quota crypto=3000 \
  --matchable-only \
  --contributor "Umanitek"
```

Input order matters. Put high-moat catalogs before OSV so the dependency quota
fills with fresh/private/package-takedown data first, then OSV backfills.

### Production: 250,000 threats, quality permitting

Target shape:

| Family | Approx count | Notes |
|---|---:|---|
| Socket/bumblebee/private package malware | 40,000-80,000 | Differentiated and first in source order. |
| Crypto-specific package/skill/extension threats | 25,000-50,000 | Wallet drainers, Web3 stealers, malicious SDKs, fake wallet tooling. |
| Malicious skills, MCP servers, editor extensions | 30,000-60,000 | Strongest moat if identities are verified. |
| OSV/OpenSSF `MAL-` npm/PyPI/cargo/RubyGems | 15,000-25,000 | Baseline sample only; do not let OSV dominate. |
| Injection signatures | 1,000-5,000 | Only curated, tested regexes. |
| Crypto/network IOC backlog | 80,000-120,000 collected | Publish after `url:` / `domain:` / `wallet:` / `hash:` detectors exist. |

Build:

```bash
venv/bin/python scripts/build_blackbox_seed_bundle.py \
  catalogs/raw/bumblebee \
  catalogs/raw/agent-skills.json \
  catalogs/raw/mcp-servers.json \
  catalogs/raw/editor-extensions.json \
  catalogs/raw/crypto-packages.json \
  catalogs/raw/crypto-skills.json \
  catalogs/raw/injection-signatures.json \
  catalogs/osv-mal-npm.json \
  catalogs/osv-mal-pypi.json \
  catalogs/osv-mal-crates-io.json \
  catalogs/osv-mal-rubygems.json \
  --out catalogs/prod-threats-250k.json \
  --name prod-2026-07 \
  --target 250000 \
  --family-quota crypto=40000 \
  --matchable-only \
  --contributor "Umanitek"
```

If the high-quality corpus is only 210k, publish 210k. Do not fill the rest
with weak data just to hit a round number.

---

## 6. Build source catalogs

Keep raw source outputs under `catalogs/raw/` and generated publish bundles under
`catalogs/`.

### OSV / OpenSSF malicious packages

No API key required.

```bash
mkdir -p catalogs
venv/bin/python scripts/fetch_osv_malware.py npm PyPI crates.io RubyGems \
  --out-dir catalogs \
  --contributor "Umanitek"
```

The script emits split-format catalogs such as:

- `catalogs/osv-mal-npm.json`
- `catalogs/osv-mal-pypi.json`
- `catalogs/osv-mal-crates-io.json`
- `catalogs/osv-mal-rubygems.json`

It only uses `MAL-` advisories, maps OSV ecosystem names to Blackbox detector
ecosystems, includes OSV advisory URLs, sets `source: "OSV.dev"`, and stamps
the contributor if provided.

Quick sample:

```bash
venv/bin/python scripts/fetch_osv_malware.py npm \
  --limit 50 \
  --out /tmp/osv-sample.json \
  --contributor "Umanitek"
hermes blackbox curate import --file /tmp/osv-sample.json --dry-run
```

### Socket / bumblebee

Use the bumblebee `threat_intel/` directory directly. The importer understands
that format, fans out one package/version per threat, normalizes malformed
double-`@` npm scopes, marks entries as `kind: malware`, and stamps `Socket` as
the default source unless the file says otherwise.

```bash
hermes blackbox curate import \
  --dir ~/Desktop/bumblebee/threat_intel \
  --contributor "Umanitek" \
  --dry-run
```

For the bundle builder, either pass the bumblebee directory directly or copy it
under `catalogs/raw/bumblebee`.

Socket's live Threat Feed API is better than the local bumblebee snapshot, but
it requires an Enterprise Threat Feed add-on and a token with
`threat-feed:list`. Fetch it with:

```bash
export SOCKET_SECURITY_API_KEY="..."
venv/bin/python scripts/fetch_socket_threat_feed.py \
  --org-slug umanitek \
  --contributor "Umanitek Agent Blackbox"
```

If the add-on is not enabled yet, the API returns a 403 saying the threat feed
is not enabled. Keep the script in the pipeline so it starts producing data as
soon as the add-on is turned on.

### SafeDep Threat Intelligence

SafeDep has two useful paths:

- Public TI Hub exports for bulk seeding and backlog collection.
- Authenticated data-plane package analysis for exact package/version checks and
  enrichment. Use API keys from the environment only; never commit them.

Fetch the public bulk exports:

```bash
venv/bin/python scripts/fetch_safedep_ti.py \
  --contributor "Umanitek Agent Blackbox"
```

Outputs:

- `catalogs/raw/safedep-ti-packages.json`: publishable dependency threats for
  currently-matchable ecosystems.
- `catalogs/backlog/safedep-ti-iocs.json`: domains, URLs, hashes, GitHub repos,
  emails, wallets, and unsupported-package indicators for future detectors.

As of 2026-07-08 this yielded 1,934 publishable dependency threats from SafeDep,
including 169 crypto-tagged package threats, plus 649 backlog indicators.

### ScamSniffer crypto blocklists

ScamSniffer's open-source repo gives delayed but high-volume Web3 phishing
domains and scam addresses. This is crypto-specific moat data, but it is backlog
until `domain:` / `wallet:` / `contract:` matching exists.

```bash
venv/bin/python scripts/fetch_scamsniffer_blacklist.py \
  --contributor "Umanitek Agent Blackbox"
```

Output:

- `catalogs/backlog/scamsniffer-crypto-iocs.json`

As of 2026-07-08 this yielded 348,208 crypto phishing domains and 2,530
wallet/address indicators. Do not publish these to the current VM until the
network/wallet detectors exist.

### Public IOC feeds (URLhaus, ThreatFox, Feodo, OpenPhish, PhishTank, MalwareBazaar)

One fetcher collects the vetted public IOC feeds from the atlas into backlog
catalogs, fail-safe per feed, with quality gates (ThreatFox confidence >= 50
plus per-type freshness windows; URLhaus online-URLs only):

```bash
venv/bin/python scripts/fetch_ioc_feeds.py \
  --contributor "Umanitek Agent Blackbox"
```

Outputs one `catalogs/backlog/<feed>-*.json` per feed. All of it is backlog
until `url:` / `domain:` / `ip:` / `hash:` detectors exist. No API keys
required; abuse.ch full exports and the PhishTank CSV are public.

### Huntress tenant telemetry

Huntress is useful as a private confirmed-incident source, not as a generic
250k threat feed. Their REST API uses HTTP Basic authentication with the API
key and API secret, and the API has endpoints for incident reports,
remediations, escalations, signals, known VPNs/proxies, external recon, and
SIEM logs.

Never commit Huntress credentials. Keep them in the shell or password manager:

```bash
export HUNTRESS_API_KEY="..."
export HUNTRESS_API_SECRET_KEY="..."
```

Use Huntress in the seeding program when we want to extract:

- file hashes, dropped filenames, persistence paths, command lines, and process
  names from confirmed incident reports;
- domains, URLs, IPs, and remote hosts from incident evidence and signals;
- attacker account, email, tenant, or identity IOCs from ITDR/SIEM logs;
- remediation metadata that supports confidence and source references.

Normalize it as backlog unless the indicator is already matchable today:

```json
{
  "source": "Huntress Incident Report",
  "contributor": "Umanitek",
  "backlog": {
    "iocs": [
      {
        "type": "hash",
        "value": "sha256:...",
        "threat": "confirmed-malware",
        "severity": "critical",
        "references": ["huntress:incident-report:<id>"]
      },
      {
        "type": "domain",
        "value": "malicious-example.invalid",
        "threat": "confirmed-c2-or-phishing",
        "severity": "high",
        "references": ["huntress:signal:<id>"]
      }
    ]
  }
}
```

If a Huntress incident names a malicious package, MCP server, skill, or editor
extension that Blackbox can match by identity, convert that exact identity into
`dependencies` or `skills` and stamp `source: "Huntress Incident Report"` plus
the contributor. Otherwise keep it in `catalogs/backlog/huntress-*`.

### Awesome threat-intelligence source atlas

The hslatman awesome-threat-intelligence list is now part of the long-term
seeding research workflow. Use the local checkout first:

```bash
cd /Users/matic/Desktop/awesome-threat-intelligence
rg -n "URLhaus|ThreatFox|MalwareBazaar|OpenPhish|PhishTank|CrowdSec|AbuseIPDB|MISP|OpenCTI|STIX|TAXII" README.md
```

Use it to expand toward 1M records after IOC support lands, but score sources
before ingestion.

Prioritize from the atlas in this order:

| Lane | Use now? | Why |
|---|---:|---|
| Package/agent identity feeds | Yes | Exact package, skill, MCP, or editor-extension identities are publishable today. |
| Crypto/Web3 phishing and scam feeds | Partial | Package/skill pieces publish now; domains, wallets, contracts, and URLs wait for new detectors. |
| Malware URL/hash/domain feeds | Backlog | Strong volume from URLhaus, ThreatFox, MalwareBazaar, DigitalSide, Cyber Cure, InQuest, Malpedia, MalShare, Maltiverse, and Malware Patrol after IOC matching exists. |
| CTI platforms and standards | Ingestion | MISP, OpenCTI, STIX, TAXII, OTX, PickupSTIX, and Intel Owl help normalize and dedupe sources. |
| IP reputation and scanner feeds | Enrichment | CrowdSec, AbuseIPDB, GreyNoise, FireHOL, IPsum, HoneyDB, and James Brine are useful after `ip:` support, but should not dominate the moat. |
| Whitelists and popularity feeds | Suppression | Cisco Umbrella, Majestic Million, and similar feeds reduce false positives. |

For every source from the atlas, record:

- source name and URL;
- access path: public export, API key, paid trial, Git repo, STIX/TAXII, MISP,
  CSV, JSON, RSS, or scraping;
- license/commercial-use status;
- indicator types and whether they are matchable today;
- update cadence and observed freshness;
- confidence policy: human verified, vendor confirmed, community reported, or
  raw/uncorroborated;
- dedupe key and TTL/expiry policy;
- contributor label for the seeding batch.

Do not count atlas feeds toward the public graph target until the source has a
normalizer, a dry-run, source/contributor fields, and a false-positive review
sample.

### Malicious skills

Normalize every verified malicious skill into `skills` entries:

```json
{
  "source": "Antiy CERT ClawHavoc",
  "contributor": "Umanitek",
  "skills": [
    {
      "skillName": "clawhud",
      "version": "1.0.0",
      "severity": "critical",
      "title": "ClawHavoc malicious skill",
      "summary": "Verified malicious skill identity from incident report.",
      "references": ["https://www.antiy.net/p/clawhavoc-analysis-of-large-scale-poisoning-campaign-targeting-the-openclaw-skill-market-for-ai-agents/"]
    }
  ]
}
```

Only seed exact identities. If a report only says "author X published malicious
skills" but does not name the exact skill and version, keep it for research.

### MCP servers

For package-installed MCP servers, seed the exact package version as dependency:

```json
{
  "source": "Snyk",
  "contributor": "Umanitek",
  "dependencies": [
    {
      "ecosystem": "npm",
      "name": "postmark-mcp",
      "version": "1.0.16",
      "kind": "malware",
      "severity": "critical",
      "title": "postmark-mcp email exfiltration",
      "references": ["https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/"]
    }
  ]
}
```

For registry-only MCP identities, wait until Blackbox has a stable MCP detector
or the runtime exposes the server as a skill/plugin identity that `skill:` can
match.

### Editor extensions

Seed an editor extension only if Blackbox can observe the install identity as a
dependency or skill today. Otherwise keep it in `catalogs/backlog/editor-*`.

Recommended normalized fields when it is matchable:

```json
{
  "source": "OpenVSX takedown",
  "contributor": "Umanitek",
  "skills": [
    {
      "skillName": "openvsx:publisher.extension",
      "version": "1.2.3",
      "severity": "critical",
      "title": "Malicious editor extension",
      "references": ["https://example.com/research-or-takedown"]
    }
  ]
}
```

### Prompt injection signatures

Only publish patterns that are:

- specific to a known attack family;
- tested against benign prompts;
- short enough to audit;
- traceable to a source dataset or incident.

```json
{
  "source": "OWASP LLM01 curated set",
  "contributor": "Umanitek",
  "injection": [
    {
      "pattern": "(?:ignore|disregard)\\s+(?:all\\s+)?(?:previous|prior)\\s+(?:instructions|rules)",
      "severity": "high",
      "owasp": "LLM01",
      "title": "Instruction override"
    }
  ]
}
```

Do not dump entire jailbreak datasets raw. Convert repeated payloads into the
smallest safe regex family and test for false positives first.

### Crypto-specific threats

Crypto is a first-class source family. Every crypto-specific publishable entry
must include `family: "crypto"` or a `tags` value such as `"crypto-drainer"` so
the bundle builder can reserve quota with `--family-quota crypto=N`.

Publishable today when represented as dependency or skill:

```json
{
  "source": "ScamSniffer / Socket / researcher report",
  "contributor": "Umanitek",
  "dependencies": [
    {
      "ecosystem": "npm",
      "name": "fake-walletconnect-sdk",
      "version": "1.2.3",
      "kind": "malware",
      "severity": "critical",
      "family": "crypto",
      "tags": ["crypto-drainer", "wallet-stealer"],
      "title": "Fake WalletConnect SDK stealing wallet secrets",
      "summary": "Verified malicious package targeting Web3 wallet users.",
      "references": ["https://example.com/research-or-feed-record"]
    }
  ],
  "skills": [
    {
      "skillName": "phantom-airdrop-helper",
      "version": "0.3.0",
      "severity": "critical",
      "family": "crypto",
      "tags": ["crypto-drainer", "seed-phrase-theft"],
      "title": "Malicious wallet airdrop skill",
      "references": ["https://example.com/research-or-feed-record"]
    }
  ]
}
```

Collect but do not publish yet:

- drainer URLs/domains;
- wallet addresses;
- contract addresses;
- token approval-drainer selectors;
- phishing kit hashes;
- C2 IPs/domains;
- downloadable payload hashes.

Backlog shape suggestion:

```json
{
  "source": "ScamSniffer",
  "contributor": "Umanitek",
  "backlog": {
    "crypto": [
      {
        "type": "url",
        "value": "https://example-drainer.invalid/connect",
        "threat": "crypto-drainer",
        "family": "crypto",
        "chain": "ethereum",
        "references": ["https://openphish.com/"]
      },
      {
        "type": "wallet",
        "value": "0x0000000000000000000000000000000000000000",
        "threat": "scam-collection-wallet",
        "family": "crypto",
        "chain": "ethereum",
        "references": ["https://chainabuse.com/"]
      }
    ]
  }
}
```

When `net:domain:` / `url:` / `hash:` / `wallet:` / `contract:` support lands,
convert these into publishable categories and count them toward the staging and
production publish bundles.

---

## 7. Validate a bundle before publishing

Basic shape:

```bash
python3 -m json.tool catalogs/staging-threats-20k.json >/dev/null
hermes blackbox curate import --file catalogs/staging-threats-20k.json --dry-run
```

Expected result:

- non-zero new threats;
- crypto family count meets the bundle target when `--family-quota crypto=N`
  was used;
- `0 errors`;
- source/contributor present in spot-checked entries;
- no unsupported backlog-only categories in the publishable bundle.

Spot-check entries:

```bash
venv/bin/python - <<'PY'
import json, random
d = json.load(open("catalogs/staging-threats-20k.json"))
items = []
for key in ("dependencies", "skills", "injection", "escalation", "fileaccess"):
    for entry in d.get(key, []):
        items.append((key, entry))
crypto = [
    entry for _, entry in items
    if str(entry.get("family", "")).lower() == "crypto"
    or any(str(t).lower().startswith("crypto") for t in entry.get("tags", []) or [])
]
print("crypto-family-count=", len(crypto))
for key, entry in random.sample(items, min(20, len(items))):
    print(key, entry.get("name") or entry.get("skillName") or entry.get("pattern", "")[:60],
          "| source=", entry.get("source") or d.get("source"),
          "| contributor=", entry.get("contributor") or d.get("contributor"),
          "| refs=", len(entry.get("references") or []))
PY
```

Hard fails:

- any entry has no source after defaults;
- any dependency lacks `ecosystem`, `name`, `version`;
- malware is not `kind: malware`;
- vulnerabilities are marked `critical` or `kind: malware` without evidence;
- crypto package/skill entries are missing `family: "crypto"` or a crypto tag;
- an unsupported `backlog` category appears in the publish bundle;
- dry-run reports errors.

---

## 8. Environment and graph safety

Use the current Blackbox graph ids:

- staging: `umanitek/blackbox-threats-staging`
- production: `umanitek/blackbox-threats`

Do not use legacy `guardian-threats` graph ids for new seeding.

Use a separate `BLACKBOX_HOME` for staging so the staging dedup ledger does not
poison production:

```bash
export BLACKBOX_CONTEXT_GRAPH_ID="umanitek/blackbox-threats-staging"
export BLACKBOX_HOME="$HOME/.hermes/blackbox-staging"
```

For production later:

```bash
export BLACKBOX_CONTEXT_GRAPH_ID="umanitek/blackbox-threats"
unset BLACKBOX_HOME
```

Confirm before every publish:

```bash
hermes blackbox status
curl -s http://127.0.0.1:9200/api/status | python3 -m json.tool | head -40
```

Requirements:

- DKG node reachable at `http://127.0.0.1:9200` or configured `DKG_DAEMON_URL`;
- node is on a supported mainnet, usually Base mainnet (`chainId` 8453);
- curator wallet has ETH for gas and TRAC for VM publish;
- dedicated RPC configured in `~/.dkg/config.json` for large batches;
- graph registered once with `hermes blackbox setup-graph --network mainnet-base`
  if it does not already exist.

---

## 9. Dry-run, publish, verify

The rule is:

1. Full dry-run the bundle.
2. Dry-run the next batch with `--limit`.
3. Publish that exact batch.
4. Sync and verify detection.
5. Repeat.

Full staging dry-run:

```bash
hermes blackbox curate import \
  --file catalogs/staging-threats-20k.json \
  --dry-run
```

Preview first batch:

```bash
hermes blackbox curate import \
  --file catalogs/staging-threats-20k.json \
  --dry-run \
  --limit 1000 \
  --check-graph
```

Publish first batch:

```bash
hermes blackbox curate import \
  --file catalogs/staging-threats-20k.json \
  --limit 1000 \
  --epochs 12 \
  --check-graph
```

Re-run the same publish command to publish the next 1000. The seeded ledger
skips what already published, so the command resumes.

Verify after each early batch:

```bash
hermes blackbox sync
hermes blackbox status
hermes blackbox dashboard
```

Open the dashboard, click a threat in the Public tab, and verify:

- Source is present;
- Contributor is present when expected;
- references are clickable;
- category and severity are correct;
- a real agent command triggers a finding.

For a dependency smoke test, pick a seeded package/version and ask Hermes:

```text
run this command for me: npm install <seeded-package>@<seeded-version>
```

In audit mode it should flag. In block mode it should block critical malware:

```bash
BLACKBOX_MODE=block hermes
```

Only after the first batch is verified end-to-end should we accelerate batch
size, for example `--limit 5000`.

---

## 10. Production publish

Production is the same workflow with the production graph id and clean/default
ledger:

```bash
export BLACKBOX_CONTEXT_GRAPH_ID="umanitek/blackbox-threats"
unset BLACKBOX_HOME

hermes blackbox curate import --file catalogs/prod-threats-250k.json --dry-run
hermes blackbox curate import --file catalogs/prod-threats-250k.json --dry-run --limit 1000 --check-graph
hermes blackbox curate import --file catalogs/prod-threats-250k.json --limit 1000 --epochs 12 --check-graph
```

Production acceptance criteria:

- production bundle has 200k-300k high-confidence threats, or fewer if quality
  dictates;
- full dry-run has `0 errors`;
- staging has already proven every category/source family;
- first production batch is verified in dashboard and in a real agent;
- source/contributor/reference fields appear in the modal;
- ledger and graph id are production, not staging.

---

## 11. Data we need before seeding

No secrets should be committed. Keep API keys in your shell, password manager,
or local ignored config.

Needed for staging:

- funded DKG curator wallet: ETH + TRAC;
- dedicated Base RPC URL for `~/.dkg/config.json`;
- bumblebee/Socket `threat_intel/` folder;
- contributor label to stamp on Umanitek-curated assets;
- any private source API keys we want in the staging mix.

Likely useful keys/sources for production:

- Socket / bumblebee export access;
- Phylum, Snyk, Sonatype, ReversingLabs malicious package feeds;
- Huntress API credentials for private confirmed-incident enrichment if we want
  tenant-derived IOC backlog, but not as a primary public-volume source;
- GitHub token for crawling advisories, takedown repos, skill registries, and
  MCP registries without rate-limit pain;
- abuse.ch Auth-Key for URLhaus/ThreatFox backlog collection;
- OpenPhish / PhishTank access for crypto-drainer and phishing backlog;
- any internal research datasets for malicious skills, MCP servers, editor
  extensions, and crypto drainers.
- hslatman/awesome-threat-intelligence local checkout at
  `/Users/matic/Desktop/awesome-threat-intelligence`: use it as the source atlas
  for new feed candidates, then promote only vetted sources into scripts.

OSV/OpenSSF does not need a key.

---

## 12. Maintenance

Run this as a continuing graph program, not a one-time dump.

- Re-fetch high-churn sources weekly or daily, depending on access.
- Publish new entries only after dry-run and spot review.
- Keep source/contributor attribution on every batch.
- Prefer exact malicious identities over vulnerable-but-legit packages.
- Dispute false positives immediately:

```bash
hermes blackbox curate reject dep:npm:some-legit-package@1.2.3 --dispute
```

- Let test data expire; renew only persistent, still-relevant threats.
- Keep backlog catalogs for future `net:` / `url:` / `hash:` categories, but do
  not publish inert IOCs to the current VM.

The threat graph is the moat only while it stays sharp, sourced, and trusted.
