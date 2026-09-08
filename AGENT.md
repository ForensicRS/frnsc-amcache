# Agent notes: frnsc-amcache

A pure-Rust parser for Windows AmCache (`Amcache.hve`) registry data, part of the [ForensicRS](https://github.com/ForensicRS) ecosystem. It depends on `forensic-rs` for registry/pipeline abstractions and `frnsc-hive` for the actual hive-file backend. This file is for anyone (human or agent) extending or reviewing the crate; see [README.md](README.md) for user-facing usage.

## Module map

- [src/lib.rs](src/lib.rs) — re-exports `amcache`, `common`, `parser`. No re-exports at crate root; consumers reach through `frnsc_amcache::amcache::AmCacheReader`, `frnsc_amcache::parser::AmCacheParserFactory`, or `frnsc_amcache::common::*`.
- [src/amcache.rs](src/amcache.rs) — `AmCacheReader`, the backend-agnostic low-level reader. Owns an `Arc<dyn Registry>` + a pre-resolved hive-root `RawKey` (the caller resolves the root, e.g. via `HiveRegistryReader::other_hive_root`, since the generic `Registry` trait has no way to reach a named "other" hive itself). One method pair per inventory: `xxx()` returns the parsing iterator, `xxx_count()` returns a cheap subkey count without parsing any entry — used by the bridge integration for pagination without materializing records.
- [src/parser.rs](src/parser.rs) — `AmCacheParserFactory`, the forensic-rs pipeline adapter. Implements `ArtifactParserFactory`; stateless (`&self`) — per-run state (open hive, host, registered source, acquisition) lives in a local inside `open()`, so one `Arc<AmCacheParserFactory>` serves every parallel worker. Also holds the nine `map_<record>` functions that turn each parsed struct into a `ForensicData` with namespaced fields.
- [src/common/mod.rs](src/common/mod.rs) — shared value-reading helpers (`read_value_string_or_empty`, `read_value_u32_or_empty`, `read_value_u64_or_empty`) and `timestamp_to_bridge_value`.
- `src/common/{app,app_file,app_shortcut,dev_container,dev_interface,dev_pnp,dev_usb_hub,drv_binary,drv_package}.rs` — one record struct + iterator + `BridgeValue` conversion per inventory type.
- [src/tst.rs](src/tst.rs) — reader-level smoke tests, pulled into `amcache.rs` via `#[path = "./tst.rs"] #[cfg(test)] mod tst;`. Real assertion coverage (record counts, provenance confidence, record-type diversity) lives in `src/parser.rs`'s embedded `#[cfg(test)] mod tests`, not here.
- `examples/pipeline.rs` — minimal triage-pipeline usage of `AmCacheParserFactory`.
- `examples/bridge_amcache.rs` — a `ProviderHook` built on `AmCacheReader` directly, exposing AmCache categories as lazily-paginated virtual filesystem children through forensic-rs's Bridge/`VfsProvider` machinery. A materially different integration surface from the pipeline (interactive/UI exploration vs. batch triage ingestion) — treat it as a second reference implementation, not a variant of `pipeline.rs`.

## Adding a new inventory type

The roadmap ([ROADMAP.md](ROADMAP.md)) lists AmCache/Appraiser inventory categories not yet implemented (e.g. `DeviceCensus`). To add one, follow the existing nine as a template — but check the actual subkey/value shape against the fixture hive first (e.g. via a throwaway `#[cfg(test)]` snippet like the ones used to derive `InventoryDevicePnp`/`InventoryDeviceInterface`/`InventoryDeviceUsbHubClass`): some categories don't share this crate's fixed-field-per-record assumption (see `DeviceCensus`'s note in `ROADMAP.md`), and registry value types vary by category (e.g. flags stored as `REG_SZ` `"0"`/`"1"` rather than `REG_DWORD` — casting those through `read_value_u32_or_empty` silently yields `0` instead of erroring, since `RegValue`'s `TryFrom<RegValue> for u32` doesn't parse strings).

1. New `src/common/<name>.rs`: a `#[derive(Clone, Debug, Default)]` struct with one field per registry value (doc-comment each field with its raw registry value name, and link the relevant [Windows Diagnostic Events and Fields](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/privacy/basic-level-windows-diagnostic-events-and-fields-1803#inventory-events) page where one exists), plus `pub timestamp: Option<ForensicTimestamp>`; an `impl From<&T> for BridgeValue`; a `<Name>Iter { key: OwnedRegKey, entries: std::vec::IntoIter<KeyEntry> }` with `build()`/`Iterator::next()`, reading fields via the `read_value_*_or_empty` helpers in `common/mod.rs`.
2. Register the submodule in `src/common/mod.rs`.
3. Add a subkey-opening method pair to `AmCacheReader` in `src/amcache.rs` (`xxx()` / `xxx_count()`), pointing at the new `Root\Inventory<Name>` subkey.
4. Add a `map_<name>` function and a `.chain(...)` arm to `AmCacheParserFactory::open` in `src/parser.rs`, namespacing fields as `"amcache.<record_snake_case>.<field_snake_case>"`.
5. If the type should be browsable interactively, add it to `CATEGORIES` and the category-dispatch `match` arms in `examples/bridge_amcache.rs`.
6. Move the item from "Planned" to "Shipped" in `ROADMAP.md` and add an entry to `CHANGELOG.md`.

## Conventions

- **Missing/wrong-type registry values default rather than error.** `read_value_string_or_empty`/`_u32_or_empty`/`_u64_or_empty` (`src/common/mod.rs`) fall back to empty string / `0` instead of propagating an error, because which values are present legitimately varies by Windows version. Only real structural failures (e.g. `key.info()?` for the timestamp) should propagate through `build()`.
- **`Iterator::next()` skips a per-entry error and continues** (logs via `info!`, including the offending entry name, and moves to the next entry) rather than stopping the whole iteration — this is long-standing, uniform behavior across every iterator, not specific to one type. Keep this loop-past-errors shape when adding a new type: a single malformed/edge-case subkey must never silently truncate every record after it.
- **Open an enumerated child with `OwnedRegKey::open_child`, not `.open()`.** `.open(name)` (from `forensic-rs`) treats `name` as a possibly multi-segment path and splits on `/`/`\` — correct when a caller builds a path by hand, but wrong for a name that came back from `.keys()`/`entry.name`: some AmCache categories (e.g. `InventoryDriverBinary`, keyed by full lowercase driver file paths like `c:/windows/system32/drivers/1394ohci.sys`) have flat child names that legitimately contain `/`/`\` as literal characters, not a hierarchy to descend. `.open_child(name)` opens by exact literal match instead — every `build()` in `src/common/*.rs` uses it for this reason; use it for any new type too, even if today's fixture data for that type happens not to contain separator characters.
- **`ForensicData` field naming**: `"amcache.<record>.<field>"` per record (e.g. `"amcache.application.program_id"`, note the shortcut type uses `"amcache.shortcut.*"` rather than `"amcache.application_shortcut.*"`), plus two shared keys across all record types: `"amcache.record_type"` (the discriminator, e.g. `"InventoryApplication"`) and `"amcache.timestamp"` (set only when `Some`, via `parser.rs`'s `set_timestamp` helper).
- **`AmCacheParserFactory::open` uses `.into_iter().flatten()`, not `?`, per category** so one inventory failing to open (e.g. an older `Amcache.hve` missing a subkey) doesn't abort the rest — keep this pattern when adding a new category.
- Keep `forensic-rs`/`frnsc-hive` versions in `Cargo.toml` aligned (currently both `"0.14"`). A local `.cargo/config.toml` (gitignored) may patch them to sibling source paths for development against unpublished versions.

## Testing

```bash
cargo test                          # src/tst.rs + src/parser.rs's embedded pipeline test
cargo run --example pipeline
cargo run --example bridge_amcache
```

All of the above depend on the fixture hive at `artifacts/C/Windows/AppCompat/Programs/Amcache.hve`. CI ([.github/workflows/rust.yml](.github/workflows/rust.yml)) runs `cargo test --verbose` on Linux, Windows, and macOS with the stable toolchain — there is currently no `clippy` or `cargo fmt --check` gate.
