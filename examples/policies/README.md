# Attestation policies

A **policy** declares the bar a receipt must clear to be acceptable for a use.
Policies run **after** cryptographic verification and never replace it: a tampered
receipt fails verification (exit `1`) regardless of any policy.

Enforce one with `apohara-sealchain verify`:

```sh
# A named built-in profile (from the canonical packaging/trust-profile.json)
apohara-sealchain verify model.bin model.bin.seal.json --profile transparency

# Or a custom TOML policy file
apohara-sealchain verify model.bin model.bin.seal.json --policy examples/policies/transparency.toml
```

## Exit codes

| Exit | Meaning |
|------|---------|
| `0`  | Crypto verified **and** policy satisfied |
| `1`  | The receipt failed verification (tamper/mismatch) — outranks policy |
| `5`  | Crypto verified, but the policy was **not** satisfied |

## Policy fields (TOML)

| Field | Type | Meaning |
|-------|------|---------|
| `require_layers` | list | Layers that must be **present AND verified** (e.g. `["ed25519","rekor"]`) |
| `forbid_layers` | list | Layers that must be absent |
| `min_layers` | int | Minimum count of present-and-verified attestation layers (hmac counts) |
| `require_qualified_tsa` | bool | TSA authority host must be a known qualified eIDAS QTSP (host-allowlist match) |
| `require_tsa_authority_in` | list | Explicit TSA-host allowlist; overrides the canonical QTSP list |
| `max_age_days` | int | Max age (days) between `seal.sealedAt` and verify time |

A typo'd key is a hard error (`deny_unknown_fields`), never silently ignored.

## Honesty

`require_qualified_tsa` is a **host-allowlist match** against the recorded
`seal.tsa.authority`. It does **not** cryptographically prove the eIDAS
qualification of a timestamp token — that legal weight comes from using a real
QTSP you are authorised to use. The default apohara-sealchain TSA is **not** qualified.
See [`docs/TRUST-PROFILE.md`](../../docs/TRUST-PROFILE.md) and the canonical
[`packaging/trust-profile.json`](../../packaging/trust-profile.json).

## Built-in profiles

The named profiles (`--profile`) come from `packaging/trust-profile.json`:

| Profile | Requires |
|---------|----------|
| `offline-basic` | hmac + ed25519 + c2pa (the offline default) |
| `transparency` | ed25519 + rekor |
| `legal-grade` | ed25519 + tsa, qualified QTSP host |
| `full` | all five layers |
