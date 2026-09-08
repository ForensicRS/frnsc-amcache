# Roadmap

Future work for `frnsc-amcache`, organized by category. See [CHANGELOG.md](CHANGELOG.md) for what's already shipped, and [AGENT.md](AGENT.md#adding-a-new-inventory-type) for the steps to add a new inventory type.

## Shipped inventory types

`InventoryApplication`, `InventoryApplicationFile`, `InventoryApplicationShortcut`, `InventoryDeviceContainer`, `InventoryDeviceInterface`, `InventoryDevicePnp`, `InventoryDeviceUsbHubClass`, `InventoryDriverBinary`, `InventoryDriverPackage` — each available through the direct `AmCacheReader` API, the `AmCacheParserFactory` triage-pipeline, and the `BridgeValue`/`ProviderHook` integration.

## Planned inventory types

AmCache/Appraiser inventory categories not yet implemented, from the same [Windows Diagnostic Events and Fields](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/privacy/basic-level-windows-diagnostic-events-and-fields-1803#inventory-events) taxonomy as the types above:

- [ ] `DeviceCensus` — deliberately deferred, not just unimplemented: unlike every other type in this crate, its subkeys (`App`, `Hardware`, `OS`, `Enterprise`, ...) each carry a completely different, unrelated set of value names rather than a shared per-instance schema, and some entries are unopenable/malformed in the reference fixture (deleted-cell artifacts). Needs either a generic `(category, name, value)` record shape instead of a fixed-field struct, or per-category structs — and `ForensicData`'s `Field` (`forensic-rs`) has no map/nested variant, so the pipeline mapping can't flatten one record straight into today's fixed `"amcache.<record>.<field>"` convention. Model this once a concrete consumer need picks one of those shapes.
- [ ] `DriverPackageExtended` — present but empty (0 entries) in the reference fixture; no ground truth to model its fields safely. Needs a hive where this category is actually populated.
- [ ] `InventoryApplicationAppV`
- [ ] `InventoryApplicationDriver`
- [ ] `InventoryApplicationFramework`
- [ ] `InventoryDeviceMediaClass` — present but empty (0 entries) in the reference fixture; same blocker as `DriverPackageExtended`.
- [ ] `InventoryMiscellaneousMemorySlotArrayInfo`
- [ ] `InventoryMiscellaneousOfficeAddIn`
- [ ] `InventoryMiscellaneousOfficeAddInUsage`
- [ ] `InventoryMiscellaneousOfficeIdentifiers`
- [ ] `InventoryMiscellaneousOfficeIESettings`
- [ ] `InventoryMiscellaneousOfficeInsights`
- [ ] `InventoryMiscellaneousOfficeProducts`
- [ ] `InventoryMiscellaneousOfficeSettings`
- [ ] `InventoryMiscellaneousOfficeVBA`
- [ ] `InventoryMiscellaneousOfficeVBARuleViolations`
- [ ] `InventoryMiscellaneousUUPInfo`

## Cross-cutting

- [ ] Take into account different Windows versions (subkey/value names and availability have drifted across Windows releases; parsing currently assumes one fixed layout).
