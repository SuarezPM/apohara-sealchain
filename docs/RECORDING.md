# Recording the demo (cast + GIF)

`docs/demo.cast` and `docs/demo.gif` are **real recordings** of `scripts/demo.sh`,
not hand-authored mock-ups. This note explains how to regenerate them.

## Tools

- [`asciinema`](https://asciinema.org/) — records the terminal session to an
  asciicast file (`docs/demo.cast`).
- [`agg`](https://github.com/asciinema/agg) — renders an asciicast to an animated
  GIF (`docs/demo.gif`).

On Arch / CachyOS:

```sh
paru -S asciinema asciinema-agg   # agg ships as the AUR package `asciinema-agg`
```

(`cargo install agg` does **not** work — the `agg` crate on crates.io is an
unrelated, binary-less library. Use the AUR package or build from the
asciinema/agg repo.)

## Regenerate

```sh
# 1. record the demo (asciinema v3 records headless when there is no TTY,
#    which is how the committed cast was produced in CI-like environments)
asciinema rec --command "bash scripts/demo.sh" --overwrite docs/demo.cast

# 2. render the GIF
agg --theme monokai --font-size 16 docs/demo.cast docs/demo.gif
```

The script pins `--sealed-at` and the HMAC key, so the *content* of every run is
identical; only the per-run Ed25519 public key and the temp paths differ (the
keys are generated fresh into a throwaway `XDG_CONFIG_HOME`).

## Interactive recording

To record a real interactive session instead of replaying the script, run
`asciinema rec docs/demo.cast`, type the commands by hand, then `exit` (or
`Ctrl-D`) to stop. Upload with `asciinema upload docs/demo.cast` if you want a
hosted player link for the README.
