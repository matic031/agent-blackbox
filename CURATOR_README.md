# Curator guide

Everything in the public threat graph is **curator-approved**. This guide is for
the people who do that approving. If you just want to protect your agents, the
[main README](README.md) is all you need — you never touch this.

## The trust model

There are two graphs:

- **Community graph (SWM)** — free, shared pool. Every Blackbox writes here the
  anonymized *candidate* threats its agent discovered. Anyone can write; nothing
  here is trusted by others automatically, and it only ever flags, never blocks.
- **Public graph (VM)** — the shared, on-chain curated threat database every
  Blackbox reads. Writing to it is **restricted to the Umanitek curator wallet**,
  enforced on-chain (`publishPolicy: curated`). This is what makes a threat
  "official."

Curators are the bridge: they review what agents discover locally and decide what
becomes public. **Curators are the only manual decision-makers in the system** —
discovery is automatic, protection is automatic, only promotion is human.

## The lifecycle of a threat

```
agent discovers something suspicious
        │  (automatic, anonymized — only a signature leaves the machine)
        ▼
   candidate in the local/community graph (SWM)
        │  curator reviews  ──►  reject  (optional: publish a false-positive note)
        ▼  approve
   curated threat published to the public graph (VM, on-chain)
        │
        ▼
every Blackbox syncs it and starts blocking/flagging it
```

A candidate that many independent agents report is a strong signal - `curate list`
groups by distinct reporters so you can see corroboration before approving.

**You decide what gets merged.** Nothing is auto-promoted. The community graph
(SWM) is an open pool anyone can write to; it only ever *flags*, never blocks. A
threat becomes public (and blockable) only when a curator runs `curate approve`
on it - that is the one and only path from the community graph into the curated
public graph. `curate reject` hides a candidate from `curate list` locally so it
stops resurfacing.

## One-time setup

You need a curator wallet (the one authorized on-chain) configured on your DKG
node, then create the public graph:

```bash
hermes blackbox setup-graph            # create + register the public threat graph (curator wallet only)
hermes blackbox status                 # confirm node health + which graph you're pointed at
```

`context_graph_id` in your `config.yaml` must point at the public Guardian
threat graph you created (default `umanitek/guardian-threats-staging`).

## Day-to-day curation

```bash
# See what agents have discovered, grouped by how many distinct reporters saw it
hermes blackbox curate list --pending

# Inspect one candidate and who reported it
hermes blackbox curate show <identifier>

# Approve → shares to SWM and publishes to the public on-chain graph (VM)
hermes blackbox curate approve <identifier> --severity high --name "..." --description "..."

# Approve locally without the on-chain publish (useful while testing)
hermes blackbox curate approve <identifier> --no-publish

# Reject a candidate; optionally publish a false-positive note so others down-rank it
hermes blackbox curate reject <identifier> --dispute
```

### Malware vs vulnerability (what `approve` carries)

Dependency threats carry a `kind`: **malware** (a compromised/malicious package)
or **vulnerability** (a legit package with an open CVE). It drives the block
policy - malware is floored to `critical` and **blocks** in block mode;
vulnerability **flags only** and never auto-blocks, so a widely-used package with
a CVE keeps working. The `kind` now flows all the way through: report it with
`--kind`, and `approve` preserves it (you can still override with `--severity`).
When in doubt, prefer `vulnerability` - a false block is worse than a missed flag.

Publishing is deduped by a local ledger so you never pay TRAC twice: both
`approve` and `import` record every on-chain publish, and a `--no-publish`
(SWM-only) run never touches the ledger, so it can't make a later real publish
skip those threats.

### Seeding in bulk

To load a whole catalog of threats at once (e.g. an advisory dump):

```bash
# Share to the free local tier only — review, then approve the ones worth publishing
hermes blackbox curate import --dir ./threats --no-publish

# Enrich dependency entries against OSV before publishing
hermes blackbox curate import --file ./deps.json --osv-enrich
```

The full step-by-step runbook — staging rehearsal through the production seed —
lives in **[seed.md](seed.md)** (the single seeding guide).

## Publishing to the public graph (VM)

`approve` (without `--no-publish`) writes on-chain, which means:

- Every approved threat is published as its own **complete, self-contained
  knowledge asset**. VM carries the threat name, description, severity,
  provenance, references, and category-specific match fields—not merely a
  batch proof or reduced copy.
- `import` follows the same rule for every entry. `--no-publish` is the only
  opt-out and leaves the complete asset in SWM for review or later publishing.

- It uses your DKG node and requires the curator wallet to be the authorized
  publisher — the network rejects anyone else.
- On-chain publishing needs a storage-ACK quorum from mainnet core nodes. If
  your node cannot reach them the publish will not finalize - use
  `--no-publish` to keep working locally and publish once the node is
  connected. Blackbox is mainnet only; there is no testnet fallback.

## Contributing

Curators (and only curators) commit here. Propose changes to detection logic,
the ontology, or curation policy via PR against this repo. Everything under
`plugins/blackbox/` is fair game; keep the [main README](README.md) accurate for
end users.
