# Positioning — "the one that proves"

apohara-sealchain's job is narrow and unfashionable: **prove what happened to an artifact,
and prove exactly how much that proof is worth.** Most provenance tooling asks you
to trust a vendor, a SaaS, or a green checkmark. apohara-sealchain asks you to trust
*math you can re-run offline* — and it is candid about where the math stops.

That candor is the product. It comes together in three connected pieces.

## 1. Trust profile — *what each combination proves*

[`packaging/trust-profile.json`](../packaging/trust-profile.json) is the canonical,
machine-readable statement of what every layer and layer-combination proves, what
it does **not** prove, and the trust anchor it depends on. It also defines the
named profiles (`offline-basic`, `transparency`, `legal-grade`, `full`) and the
qualified-TSA host allowlist. [`TRUST-PROFILE.md`](TRUST-PROFILE.md) is its
human-readable rendering; if the two ever disagree, the JSON wins.

This is the brand anchor: a seal is **evidence, not a verdict**, and the trust
profile is the precise, written ceiling on what that evidence means.

## 2. Attestation policies — *enforce the bar*

A profile is only useful if you can require it. `apohara-sealchain verify --profile <name>`
(or `--policy <file.toml>`) enforces a bar **after** cryptographic verification:

| Exit | Meaning |
|------|---------|
| `0`  | Crypto verified **and** the policy is satisfied |
| `1`  | The receipt failed verification (tamper/mismatch) — outranks policy |
| `5`  | Crypto verified, but the policy was **not** satisfied |

A layer counts toward a policy only if it is **present AND verified** — no asserted
pass. Policies are plain TOML (`require_layers`, `forbid_layers`, `min_layers`,
`require_qualified_tsa`, `max_age_days`, `require_tsa_authority_in`); a typo'd key
is a hard error, never silently ignored. See [`examples/policies/`](../examples/policies/).

## 3. Transparency dashboard — *see it at a glance*

`apohara-sealchain dashboard` renders a **self-contained, offline** HTML report from your
local receipts (or a `--from-dir` scan): one row per artifact with its layers, an
honest verify status, and an optional policy-compliance column. The report has
**no network references at all** — it is a static file you can open or hand to an
auditor.

```sh
apohara-sealchain dashboard --from-dir . --profile transparency -o report.html
```

Honesty carries through to the pixels: a row is `PASS` only when the artifact was
present and every present layer verified; a missing artifact is `receipt-only`
(no faked pass); a tampered artifact is `FAIL`. Policy compliance is shown only
for rows that verified — a failed verification is the headline, not the policy.

## The through-line

```
trust profile  ─►  attestation policy  ─►  transparency dashboard
(what it proves)   (enforce the bar)       (see it, offline)
```

One source of truth, enforced at the command line, surfaced in a shareable report —
all offline, all re-checkable, none of it asserted. That is what "the one that
proves" means.

## See also

- [`TRUST-PROFILE.md`](TRUST-PROFILE.md) — the proof matrix and named profiles
- [`../examples/policies/`](../examples/policies/) — policy field reference + examples
- [`../SPEC.md`](../SPEC.md) — the `apohara-seal-v1` wire format and verify semantics
- [`../README.md#honesty-read-this`](../README.md#honesty-read-this) — the candid limitations
