# balrog

Ranks the call sites in a firmware ELF tree that are worth opening in a decompiler.

This tool is meant to be used with `moria` and `mithril`. Basically, you can
think of it as a triager for ELF files, once you've extracted a firmware and looked
for CVEs. What deserves your attention first ?

- https://github.com/nmatt0/moria
- https://github.com/nmatt0/mithril

```sh
moria -e firmware.bin              # unpack
mithril firmware.bin.extracted/    # secrets, SBOM, CVEs
balrog scan firmware.bin.extracted/
```

## Build

```sh
cargo build --release
CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc \
  cargo build --release --target x86_64-unknown-linux-musl   # static binary
```

## Use

```
balrog scan <path>...          rank risky calls, grouped by class
balrog scan -j <path>          JSON
balrog scan --class exec <p>   one class only
balrog scan --min 100 <p>      score floor
balrog scan --per-bin 2 <p>    cap findings per class per binary
balrog scan --top 30 <p>       cap findings shown per class (default 15)
balrog imports <file>          resolved imports and their stub addresses
```

