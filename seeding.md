# Seeding the threat graph - step-by-step (staging run)

A follow-along checklist for seeding the public threat graph on mainnet. This
run is a **rehearsal under a throwaway graph name** so we prove the whole
pipeline end-to-end before the real production seed next week.

For the *why* - what belongs in the graph, catalog format, dedup theory, the
five golden rules - read [seed.md](seed.md) first. This file is just the ordered
steps to run.

---

## Naming - read this before anything else

Publishing to mainnet **registers the graph name on-chain**. Once we seed under a
name, that name is spent. So:

- **Production name: reserved. Do NOT use it in this run.** We finalize it next
  week. The code default `umanitek/guardian-threats` is presumably the reserved
  production name - **avoid it here.**
- **This staging run uses a deliberately non-production name:**

  ```
  umanitek/guardian-threats-staging
  ```

  Change it if you prefer, but keep it obviously-not-production (`-staging`,
  `-rehearsal`, `-rc1`, a date suffix, whatever). It is throwaway.

---

## Why we isolate the run (the one non-obvious gotcha)

The dedup ledger that stops you paying to publish the same threat twice
(`$GUARDIAN_HOME/seeded_identifiers.txt`) is a **single global file - it is not
keyed by graph name**. If we seed staging against the default home, next week's
production seed would look at that same ledger, think every identifier is
"already published", and skip them - leaving the production graph empty.

Fix: run this whole staging seed under a **separate `GUARDIAN_HOME`**. The
staging ledger stays isolated; production next week starts with a clean ledger.

---

## 0. Preconditions

- [ ] Curator wallet funded: **ETH** (gas) + **TRAC** (publish). ✅ you have this.
- [ ] Local DKG node running on **mainnet** and reachable:
  ```
  dkg hermes setup --network mainnet        # if not already done
  curl -s http://127.0.0.1:9200/api/status  # should respond
  ```
- [ ] Guardian installed and working: `hermes guardian status` runs.
- [ ] A **small** first batch ready as `batch-01.json` (see [seed.md](seed.md)
  for the catalog format). Keep the rehearsal batch small - 20-50 known-bad
  packages is plenty to prove detection. Save the big 100k push for production.

---

## 1. Open an isolated staging shell

Run every command below in **one terminal** with these two env vars set. The
first points all `hermes guardian` commands at the staging graph; the second
isolates the ledger/audit logs so production stays clean.

```bash
export GUARDIAN_CONTEXT_GRAPH_ID="umanitek/guardian-threats-staging"
export GUARDIAN_HOME="$HOME/.guardian-staging"
```

Confirm it took:

```bash
hermes guardian status | grep "context graph"
#   context graph:     umanitek/guardian-threats-staging   ← must say -staging
```

> If that line shows `umanitek/guardian-threats` (no `-staging`), stop - the env
> var didn't apply and you'd seed the production name. Re-export and re-check.

---

## 2. Create + register the staging graph (one-time, on-chain)

```bash
hermes guardian setup-graph --network mainnet
```

This creates the context graph and registers it on-chain (spends a little
ETH/TRAC). The human-readable display name is cosmetic ("Umanitek Guardian
Threats"); the thing that matters - and gets reserved - is the identifier
`umanitek/guardian-threats-staging`.

---

## 3. Dry-run the first batch (spends nothing)

Always dry-run before paying. It applies all dedup and prints the exact number
of *new* publishes - your TRAC bill - without spending anything.

```bash
hermes guardian curate import --file batch-01.json --osv-enrich --dry-run
#   → "Dry run: 42 NEW threats would publish, 3 skipped as duplicates, 0 errors."
```

Fix any `errors` in the catalog before publishing. Zero errors, sane new-count → proceed.

---

## 4. Publish the first batch to mainnet

```bash
hermes guardian curate import --file batch-01.json --osv-enrich --epochs 1
```

- `--epochs 1` is the cheapest storage (one epoch). Fine for a rehearsal. For
  production you'll pick a longer horizon - epochs are the biggest cost lever at
  scale (see [seed.md](seed.md#storage-life-vs-cost---epochs)).
- Re-running the same batch is safe: the ledger skips anything already published,
  so you never double-pay.

---

## 5. Verify detection with a real agent

```bash
hermes guardian sync         # pull the freshly-seeded threats into the local ruleset
hermes guardian status       # ruleset counts should jump (dependency N, ...)
hermes guardian dashboard    # open http://127.0.0.1:9700 → Public tab shows your seeds
```

Then prove a real catch: in an agent, try to install one of the packages you
seeded, e.g.

```
npm install <one-of-your-seeded-bad-packages>@<seeded-version>
```

It should appear in the dashboard's live findings as a **Public graph match /
confirmed**. To see it actually blocked (not just flagged), set block mode for
the test:

```bash
GUARDIAN_MODE=block hermes    # or set plugins.entries.guardian.mode: block
```

---

## 6. Iterate through the remaining batches

Repeat steps 3-5 per batch:

```bash
hermes guardian curate import --file batch-02.json --osv-enrich --dry-run
hermes guardian curate import --file batch-02.json --osv-enrich --epochs 1
```

- Seeding from a second machine, or lost the ledger? Add `--check-graph` - it
  queries the on-chain graph once and skips anything already there (authoritative
  dedup).
- Published a false positive? Pull it immediately:
  ```bash
  hermes guardian curate reject dep:npm:some-legit-pkg@1.0.0 --dispute
  ```

---

## 7. Hand-off to the production seed (next week)

The staging graph and its TRAC spend are throwaway - you've proven the pipeline.
For the real run:

1. **Use the reserved production name** (decided this/next week), not `-staging`.
2. **Start from a clean ledger.** Either use the **default** `GUARDIAN_HOME` (do
   NOT set it to `~/.guardian-staging`), or delete the staging ledger. A clean
   ledger is what makes the production graph actually receive every threat:
   ```bash
   # production shell - note: default home, production graph name
   export GUARDIAN_CONTEXT_GRAPH_ID="umanitek/<final-production-name>"
   unset GUARDIAN_HOME        # back to the default ~/.hermes/guardian
   ```
3. Everything else is identical - same catalogs, same dry-run-first discipline,
   just a longer `--epochs` and the full batch set.

That's it: the only differences between this rehearsal and production are the
**graph name** and the **home/ledger**. Nail those two and the production seed is
the same steps at scale.

---

## Quick command reference

```bash
# staging isolation (per shell)
export GUARDIAN_CONTEXT_GRAPH_ID="umanitek/guardian-threats-staging"
export GUARDIAN_HOME="$HOME/.guardian-staging"

hermes guardian status                                   # confirm graph name
hermes guardian setup-graph --network mainnet            # 1x: create + register
hermes guardian curate import --file B.json --osv-enrich --dry-run   # preview cost
hermes guardian curate import --file B.json --osv-enrich --epochs 1  # publish
hermes guardian sync && hermes guardian dashboard        # verify
hermes guardian curate reject <id> --dispute             # pull a false positive
```
