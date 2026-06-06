# `huggingface-seal` — seal a model and attach the receipt to the Hub

A composite GitHub Action that seals a HuggingFace model file with
apohara-sealchain into a tamper-evident `<file>.seal.json` receipt, **verifies it
locally**, and — only when given a write token — uploads the receipt to the model
repo so a downloader can prove the weights are byte-for-byte yours.

> **Seal then prove, before publishing.** The action always seals *and* re-verifies
> the receipt locally first; the Hub upload runs only when `hf_token` is set.
> Without a token it is a **dry-run**: receipt produced and verified, nothing
> published. There is no faked upload and no faked pass.

## Usage

```yaml
- uses: SuarezPM/apohara-sealchain/.github/actions/huggingface-seal@v0.2.0
  with:
    model_path: ./out/model.safetensors
    repo_id: your-org/your-model        # required only when uploading
    hf_token: ${{ secrets.HF_TOKEN }}   # omit for a dry-run (no upload)
    # args: --ai-generated              # optional extra `seal` flags
```

Omit `hf_token` to run the seal + verify steps without touching the Hub (CI dry-run):

```yaml
- uses: SuarezPM/apohara-sealchain/.github/actions/huggingface-seal@v0.2.0
  with:
    model_path: ./out/model.safetensors  # seals + verifies; does not publish
```

## Inputs

| Input | Required | Default | Notes |
|-------|----------|---------|-------|
| `model_path` | yes | — | File to seal. |
| `repo_id` | no | `""` | HF repo to upload to (required only with a token). |
| `hf_token` | no | `""` | HF write token. **Omitted ⇒ dry-run (no upload).** |
| `path_in_repo` | no | receipt basename | Destination of the receipt inside the repo. |
| `args` | no | `""` | Extra `seal` flags (`--all`, `--ai-generated`, `--tsa`, `--rekor`, …). |
| `version` | no | `latest` | apohara-sealchain release to use. |

## Outputs

- `receipt` — path to the produced `.seal.json`.
- `uploaded` — `true` if uploaded to the Hub, `false` for a dry-run.

## How it works

1. **Acquire** the `apohara-sealchain` binary (reuses one already on `PATH`, else
   downloads the matching release asset).
2. **Seal** `model_path` → `<model_path>.seal.json` (offline by default).
3. **Verify** the receipt locally; a verification failure aborts the job **before**
   any upload.
4. **Upload** the receipt to `repo_id` via `huggingface-cli` — **only** when
   `hf_token` is provided. The upload is the user's action (their token, their repo)
   and never runs in a dry-run.

## Try the dry-run locally

[`examples/huggingface/hf-action-dryrun.sh`](../../../examples/huggingface/hf-action-dryrun.sh)
reproduces steps 1–4 offline (throwaway keystore, temp model, no upload) so you can
see the exact seal + verify contract the action enforces before it ever publishes.
