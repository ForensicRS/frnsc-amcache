# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Three new inventory types, following the same `AmCacheReader` / `AmCacheParserFactory` / `BridgeValue` triple-integration pattern as the original six: `InventoryDevicePnp` (Plug and Play device + driver metadata, 70 entries in the reference fixture), `InventoryDeviceInterface` (per-machine sensor-interface availability flags), and `InventoryDeviceUsbHubClass` (USB hub port counts). `DeviceCensus`, `DriverPackageExtended`, and `InventoryDeviceMediaClass` remain unimplemented — see `ROADMAP.md` for why.

### Fixed
- Every `InventoryXIter::next()` now skips a per-entry parse failure and continues, instead of silently stopping the whole iteration on the first bad entry — a single malformed/edge-case subkey no longer truncates every record after it.
- `InventoryDriverBinary` entries now parse correctly. Root cause (in `forensic-rs`/`frnsc-hive`, not this crate): `OwnedRegKey::open()` splits its argument on `/`/`\` as a multi-segment path, but `InventoryDriverBinary`'s subkeys are named with full lowercase driver file paths (e.g. `c:/windows/system32/drivers/1394ohci.sys`) — a single literal name that happens to contain those characters, not a hierarchy to descend. Every enumerated-child open in `src/common/*.rs` now uses the new `OwnedRegKey::open_child()` (backed by `Registry::open_child_raw`), which opens by exact literal match instead. Previously every `InventoryDriverBinary` entry failed to parse and the category silently returned zero records.

## [0.14.0]

### Added
- Triage-pipeline integration: `frnsc_amcache::parser::AmCacheParserFactory`, implementing forensic-rs's `ArtifactParserFactory`. Self-discovers `Amcache.hve` from a `TriageSources` `FileSystem`, and emits one `ForensicData` per record across all six inventories, each with real minted provenance (`SourceHandle::mint`). Fields are namespaced `"amcache.<record>.<field>"`, with shared `"amcache.record_type"` and `"amcache.timestamp"` keys. See `examples/pipeline.rs`.
- Bridge / virtual-filesystem integration: every record struct in `frnsc_amcache::common` gained `impl From<&T> for BridgeValue`. See `examples/bridge_amcache.rs` for a `ProviderHook` that exposes AmCache inventories as lazily-paginated virtual children of `Amcache.hve`, backed by `AmCacheReader`.
- `AmCacheReader::<category>_count()` methods (`applications_count`, `application_files_count`, `application_shortcuts_count`, `device_containers_count`, `driver_binaries_count`, `driver_package_count`) — cheap subkey counts without parsing entries, used by the bridge integration for pagination.
- `examples/pipeline.rs` and `examples/bridge_amcache.rs`.

### Changed
- `AmCacheReader` (formerly a generic `AmCache<R: RegistryReader>` borrowing its backend by lifetime) is now non-generic, holding an `Arc<dyn Registry>` and a pre-resolved hive-root `RawKey`. It is `'static`, `Send + Sync`, and its iterators are backed by owned `OwnedRegKey`s that can outlive the reader.
- Every record struct's `timestamp` field changed from `Filetime` to `Option<ForensicTimestamp>`.
- `forensic-rs` and `frnsc-hive` bumped from `0.13` to `0.14`.
- `frnsc-hive` moved from `[dev-dependencies]` to `[dependencies]`, since `AmCacheParserFactory` now opens hives directly at runtime, not just in tests.

## [0.13.0] — 2025-02-18

### Added
- Initial release: `AmCache` reader with parsers for all six supported inventories — `InventoryApplication`, `InventoryApplicationFile`, `InventoryApplicationShortcut`, `InventoryDeviceContainer`, `InventoryDriverBinary`, `InventoryDriverPackage`.
- CI on Linux, Windows, and macOS (`cargo test`).
- MIT license.
