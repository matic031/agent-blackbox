# Curator guide

Everything in the public threat graph is **curator-approved**. This guide is for
the people who do that approving. If you just want to protect your agents, the
[main README](README.md) is all you need — you never touch this.

## The trust model

There are two graphs:

- **Local graph (SWM)** — free, per-machine. Every Guardian writes here: findings
  it logs, and anonymized *candidate* threats its agent discovered. Anyone can
  write; nothing here is trusted by others automatically.
- **Public graph (VM)** — the shared, on-chain curated threat database every
  Guardian reads. Writing to it is **restricted to the Umanitek curator wallet**,
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
every Guardian syncs it and starts blocking/flagging it
```

A candidate that many independent agents report is a strong signal — `curate list`
groups by distinct reporters so you can see corroboration before approving.

## One-time setup

You need a curator wallet (the one authorized on-chain) configured on your DKG
node, then create the public graph:

```bash
hermes guardian setup-graph            # create + register the public threat graph (curator wallet only)
hermes guardian status                 # confirm node health + which graph you're pointed at
```

`context_graph_id` in your `config.yaml` must point at the public graph you
created (default `umanitek/guardian-threats`).

## Day-to-day curation

```bash
# See what agents have discovered, grouped by how many distinct reporters saw it
hermes guardian curate list --pending

# Inspect one candidate and who reported it
hermes guardian curate show <identifier>

# Approve → shares to SWM and publishes to the public on-chain graph (VM)
hermes guardian curate approve <identifier> --severity high --name "..." --description "..."

# Approve locally without the on-chain publish (useful while testing)
hermes guardian curate approve <identifier> --no-publish

# Reject a candidate; optionally publish a false-positive note so others down-rank it
hermes guardian curate reject <identifier> --dispute
```

### Seeding in bulk

To load a whole catalog of threats at once (e.g. an advisory dump):

```bash
# Share to the free local tier only — review, then approve the ones worth publishing
hermes guardian curate import --dir ./threats --no-publish

# Enrich dependency entries against OSV before publishing
hermes guardian curate import --file ./deps.json --osv-enrich
```

## Publishing to the public graph (VM)

`approve` (without `--no-publish`) writes on-chain, which means:

- It uses your DKG node and requires the curator wallet to be the authorized
  publisher — the network rejects anyone else.
- On-chain publishing needs a storage-ACK quorum from core nodes. On networks
  with no live cores (e.g. an empty testnet) the publish will not finalize —
  use `--no-publish` to keep working locally until cores are available or you
  publish on a network that has them.

## Contributing

Curators (and only curators) commit here. Propose changes to detection logic,
the ontology, or curation policy via PR against this repo. Everything under
`plugins/guardian/` is fair game; keep the [main README](README.md) accurate for
end users.
