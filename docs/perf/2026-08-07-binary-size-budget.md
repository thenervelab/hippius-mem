# Binary size budget — default vs release features

Date: 2026-08-07  
Host: `aarch64-apple-darwin` (Apple Silicon)  
Toolchain: Rust **1.97.1** (`rust-toolchain.toml`)  
Profile: **`dist`** (`inherits = "release"`, `lto = "thin"`, `strip = "symbols"`)  
Command: `cargo build -p hippius-mem --profile dist --locked` (± `--features …`)

## Measured artifact sizes

| Build | Features | Size | MiB |
|-------|----------|-----:|----:|
| **Default** | _(none)_ | 13,138,592 B | **12.53** |
| Dashboard only | `dashboard` | 15,165,584 B | **14.46** |
| **Release (dist / installer)** | `embeddings,dashboard` | 35,950,592 B | **34.29** |

### Deltas vs default

| Comparison | Δ |
|------------|--:|
| `dashboard` only | **+1.93 MiB** |
| `embeddings,dashboard` (full release) | **+21.76 MiB** (**2.74×** default) |
| Approximate **embeddings** share (`emb+dash` − `dash`) | **+19.82 MiB** |

## Sanity checks

- Default binary: no `onnxruntime` / `fastembed` strings of interest (lexical path only).
- Release binary: embeds ONNX Runtime symbols (e.g. `onnxruntime::IOBinding::…`) — static link via `ort` / fastembed.
- Extra `strip(1)` on the release binary did not shrink further; profile `strip = "symbols"` already applied.

## What this means for dependency work

1. **Shipped-size pain is almost entirely `embeddings` (ONNX Runtime), not “too many small crates.”**  
   Dashboard is cheap (~2 MiB). The release feature set is **~22 MiB** over a lean default, of which **~20 MiB** is embeddings.

2. **Default (~12.5 MiB) is already “AWS SDK + rustls/`aws-lc` + crypto + MCP”.**  
   Thinning or replacing `aws-sdk-s3` can only buy part of that 12.5 MiB base — it does **not** move the 34 MiB release artifact unless embeddings change.

3. **Product posture (keep for now):**  
   - Installer / cargo-dist: `embeddings,dashboard` (semantic recall + UI).  
   - Local day-to-day: default or `dashboard` only (see REFERENCE.md “Default vs release size”).  
   - Intel-mac lean artifact remains the documented embeddings exception.

4. **Go / no-go for a thin S3 client:**  
   - **Not justified as a release-size project** — ONNX dominates.  
   - **Only justified** if the goal is faster **default** compile times / smaller **lexical** binaries / smaller `target/` when developing without embeddings. Treat that as a separate CI/dev ergonomics design, not a “make the shipped binary small” fix.

## Runtime note (not in the binary)

First semantic `recall` still downloads the embedding model (~90 MB) into the fastembed cache. That cost is **on disk at runtime**, not in the 34 MiB binary.

## Reproduce

```sh
cargo build -p hippius-mem --profile dist --locked
ls -lh target/dist/hippius-mem

cargo build -p hippius-mem --profile dist --features dashboard --locked
ls -lh target/dist/hippius-mem

cargo build -p hippius-mem --profile dist --features embeddings,dashboard --locked
ls -lh target/dist/hippius-mem
```

(Feature flips share one output path; measure or copy after each build.)
