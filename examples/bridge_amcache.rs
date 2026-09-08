use std::collections::BTreeMap;
use std::sync::Arc;

use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;
use forensic_rs::prelude::*;
use frnsc_amcache::amcache::AmCacheReader;
use frnsc_hive::reader::{open_hive_with_logs, HiveRegistryReader};

const AMCACHE_PATH: &str = "Windows/AppCompat/Programs/Amcache.hve";

/// A `ProviderHook` that recognizes `Amcache.hve` by content (not just name)
/// inside a plain `VfsProvider`-served filesystem, and exposes its parsed
/// AmCache categories/records as that file's virtual children — the file
/// stays a normal, readable leaf, and is *also* a node you can list further,
/// entirely through forensic-rs's stock hook-dispatch machinery (no bespoke
/// provider needed).
///
/// Deliberately holds no parsed records: every `virtual_children`/
/// `read_virtual` call re-derives a fresh iterator from the registry and
/// only materializes the slice actually requested. A category could hold
/// millions of entries — caching a fully-parsed `Vec` per category the first
/// time it's touched would mean retaining all of it in memory forever after
/// just one page was ever requested.
struct AmcacheHook {
    // `AmCacheReader` owns an `Arc<dyn Registry>` + a resolved root `RawKey`
    // (see `frnsc_amcache::amcache`), so it's plain `Send + Sync` and lives
    // here as a normal field, resolved once at startup — no leaking, no
    // re-deriving the hive root on every access.
    amcache: AmCacheReader,
}

impl AmcacheHook {
    fn category_count(&self, category: &str) -> ForensicResult<Option<u64>> {
        let amcache = &self.amcache;
        Ok(Some(match category {
            "Applications" => amcache.applications_count()?,
            "ApplicationFiles" => amcache.application_files_count()?,
            "ApplicationShortcuts" => amcache.application_shortcuts_count()?,
            "DeviceContainers" => amcache.device_containers_count()?,
            "DriverBinaries" => amcache.driver_binaries_count()?,
            "DriverPackages" => amcache.driver_package_count()?,
            "DevicePnps" => amcache.device_pnps_count()?,
            "DeviceInterfaces" => amcache.device_interfaces_count()?,
            "DeviceUsbHubClasses" => amcache.device_usb_hub_classes_count()?,
            _ => return Ok(None),
        }))
    }

    /// Streams a page of a category straight off a fresh iterator — nothing
    /// beyond `offset + limit` records is ever parsed, and none of it is
    /// kept around after this call returns. `Iterator::skip`/`take` still
    /// parse (and discard) each skipped record, since these iterators have
    /// no way to jump straight to an offset — this fixes unbounded memory
    /// growth, not repeated-parse cost on very deep pagination.
    fn category_entries(&self, category: &str, offset: u64, limit: u64) -> ForensicResult<Option<(Vec<NodeEntry>, u64)>> {
        fn page<T>(
            items: impl Iterator<Item = T>,
            offset: u64,
            limit: u64,
            describe: impl Fn(&T) -> String,
        ) -> Vec<NodeEntry> {
            items
                .enumerate()
                .skip(offset as usize)
                .take(limit as usize)
                .map(|(idx, item)| NodeEntry {
                    name: Text::Owned(idx.to_string()),
                    node_type: NodeType::Leaf,
                    description: Some(Text::Owned(describe(&item))),
                })
                .collect()
        }

        let Some(total) = self.category_count(category)? else {
            return Ok(None);
        };
        let amcache = &self.amcache;
        let entries = match category {
            "Applications" => page(amcache.applications()?, offset, limit, |a| a.name.clone()),
            "ApplicationFiles" => page(amcache.application_files()?, offset, limit, |f| f.path.clone()),
            "ApplicationShortcuts" => page(amcache.application_shortcuts()?, offset, limit, |s| s.path.clone()),
            "DeviceContainers" => page(amcache.device_containers()?, offset, limit, |d| d.friendly_name.clone()),
            "DriverBinaries" => page(amcache.driver_binaries()?, offset, limit, |d| d.driver_name.clone()),
            "DriverPackages" => page(amcache.driver_package()?, offset, limit, |d| d.directory.clone()),
            "DevicePnps" => page(amcache.device_pnps()?, offset, limit, |d| d.description.clone()),
            "DeviceInterfaces" => page(amcache.device_interfaces()?, offset, limit, |d| {
                let enabled = [
                    &d.accelerometer_3d, &d.activity_detection, &d.ambient_light, &d.barometer, &d.custom,
                    &d.floor_elevation, &d.geomagnetic_orientation, &d.gravity_vector, &d.gyrometer_3d, &d.humidity,
                    &d.linear_accelerometer, &d.magnetometer_3d, &d.orientation, &d.pedometer, &d.proximity,
                    &d.relative_orientation, &d.simple_device_orientation, &d.temperature, &d.energy_meter,
                ]
                .into_iter()
                .filter(|flag| flag.as_str() == "1")
                .count();
                format!("{enabled} sensor interface(s) enabled")
            }),
            "DeviceUsbHubClasses" => page(amcache.device_usb_hub_classes()?, offset, limit, |d| d.inf.clone()),
            _ => return Ok(None),
        };
        Ok(Some((entries, total)))
    }

    /// Fetches exactly one record via `Iterator::nth`, without materializing
    /// or retaining anything beyond it.
    fn record_value(&self, category: &str, idx: usize) -> ForensicResult<Option<BridgeValue>> {
        let amcache = &self.amcache;
        Ok(match category {
            "Applications" => amcache.applications()?.nth(idx).map(|v| BridgeValue::from(&v)),
            "ApplicationFiles" => amcache.application_files()?.nth(idx).map(|v| BridgeValue::from(&v)),
            "ApplicationShortcuts" => amcache.application_shortcuts()?.nth(idx).map(|v| BridgeValue::from(&v)),
            "DeviceContainers" => amcache.device_containers()?.nth(idx).map(|v| BridgeValue::from(&v)),
            "DriverBinaries" => amcache.driver_binaries()?.nth(idx).map(|v| BridgeValue::from(&v)),
            "DriverPackages" => amcache.driver_package()?.nth(idx).map(|v| BridgeValue::from(&v)),
            "DevicePnps" => amcache.device_pnps()?.nth(idx).map(|v| BridgeValue::from(&v)),
            "DeviceInterfaces" => amcache.device_interfaces()?.nth(idx).map(|v| BridgeValue::from(&v)),
            "DeviceUsbHubClasses" => amcache.device_usb_hub_classes()?.nth(idx).map(|v| BridgeValue::from(&v)),
            _ => None,
        })
    }
}

const CATEGORIES: &[&str] = &[
    "Applications",
    "ApplicationFiles",
    "ApplicationShortcuts",
    "DeviceContainers",
    "DriverBinaries",
    "DriverPackages",
    "DevicePnps",
    "DeviceInterfaces",
    "DeviceUsbHubClasses",
];

impl ProviderHook for AmcacheHook {
    fn name(&self) -> &str {
        "amcache"
    }

    fn matches_path(&self, path: &str) -> bool {
        path.ends_with("Amcache.hve")
    }

    fn matches_value(&self, _path: &str, value: &BridgeValue) -> bool {
        // `value` is only a bounded content peek (see `VfsProvider::resolve_hook`
        // in forensic-rs) — enough to check the registry hive's magic bytes.
        matches!(value, BridgeValue::Binary(bytes) if bytes.starts_with(b"regf"))
    }

    fn virtual_children(
        &self,
        _parent_path: &str,
        _parent_value: &BridgeValue,
        virtual_path: &str,
        offset: u64,
        limit: u64,
    ) -> ForensicResult<(Vec<NodeEntry>, u64)> {
        if virtual_path.is_empty() {
            // The hook's own root: the 6 AmCache categories, free (no parsing).
            let total = CATEGORIES.len() as u64;
            let entries = CATEGORIES
                .iter()
                .skip(offset as usize)
                .take(limit as usize)
                .map(|name| NodeEntry {
                    name: Text::Borrowed(name),
                    node_type: NodeType::Container,
                    description: None,
                })
                .collect();
            return Ok((entries, total));
        }

        self.category_entries(virtual_path, offset, limit)?.ok_or_else(|| {
            ForensicError::other("AmcacheHook", format!("unknown AmCache category: {virtual_path}"))
        })
    }

    fn read_virtual(&self, _parent_path: &str, virtual_child: &str) -> ForensicResult<BridgeValue> {
        let (category, idx) = virtual_child.split_once('/').ok_or_else(|| {
            ForensicError::other("AmcacheHook", format!("cannot read AmCache category: {virtual_child}"))
        })?;
        let idx: usize = idx
            .parse()
            .map_err(|_| ForensicError::other("AmcacheHook", format!("invalid record index: {idx}")))?;
        self.record_value(category, idx)?.ok_or_else(|| {
            ForensicError::other("AmcacheHook", format!("record not found: {virtual_child}"))
        })
    }

    fn metadata_virtual(&self, _parent_path: &str, virtual_path: &str) -> ForensicResult<BTreeMap<Text, BridgeValue>> {
        let mut map = BTreeMap::new();
        if let Some(count) = self.category_count(virtual_path)? {
            map.insert(Text::Borrowed("count"), BridgeValue::U64(count));
        }
        Ok(map)
    }
}

/// Everything a UI would do on load: list providers, walk the dummy
/// filesystem down to the hive, read it as a raw file, then re-explore the
/// same path as a parsed AmCache tree.
fn simulate_ui(client: BridgeClient) -> ForensicResult<()> {
    println!("providers: {:?}", client.list_providers()?);

    for dir in ["", "Windows", "Windows/AppCompat", "Windows/AppCompat/Programs"] {
        match client.children("Filesystem", dir)? {
            BridgeResponse::Children { entries, total, .. } => {
                let names: Vec<&str> = entries.iter().map(|e| e.name.as_ref()).collect();
                println!("children(\"{dir}\") -> total={total} {names:?}");
            }
            other => println!("children(\"{dir}\") -> unexpected response: {other:?}"),
        }
    }

    // Leaf side: read the hive like any other file.
    match client.read("Filesystem", AMCACHE_PATH)? {
        BridgeResponse::Value { value: BridgeValue::Binary(bytes), .. } => {
            println!(
                "read(\"{AMCACHE_PATH}\") -> {} bytes, magic={:?}",
                bytes.len(),
                String::from_utf8_lossy(&bytes[..4.min(bytes.len())])
            );
        }
        other => println!("read(\"{AMCACHE_PATH}\") -> unexpected response: {other:?}"),
    }

    // Node side: the very same path also has children.
    match client.children("Filesystem", AMCACHE_PATH)? {
        BridgeResponse::Children { entries, total, .. } => {
            let names: Vec<&str> = entries.iter().map(|e| e.name.as_ref()).collect();
            println!("children(\"{AMCACHE_PATH}\") -> total={total} {names:?}");
        }
        other => println!("children(\"{AMCACHE_PATH}\") -> unexpected response: {other:?}"),
    }

    let applications_path = format!("{AMCACHE_PATH}/Applications");
    match client.children("Filesystem", &applications_path)? {
        BridgeResponse::Children { entries, total, .. } => {
            println!("children(\"{applications_path}\") -> total={total} first={:?}", entries.first().map(|e| e.name.as_ref()));
        }
        other => println!("children(\"{applications_path}\") -> unexpected response: {other:?}"),
    }

    let first_app_path = format!("{applications_path}/0");
    match client.read("Filesystem", &first_app_path)? {
        BridgeResponse::Value { value, .. } => println!("read(\"{first_app_path}\") -> {value:?}"),
        other => println!("read(\"{first_app_path}\") -> unexpected response: {other:?}"),
    }

    Ok(())
}

fn main() -> ForensicResult<()> {
    let mut in_memory_fs = InMemoryVirtualFileSystem::new();
    in_memory_fs.add_file("Users/alice/Desktop/notes.txt", b"todo: review amcache findings".to_vec());
    in_memory_fs.add_file("Users/alice/Downloads/setup.exe", b"MZ\x90\x00fake-installer".to_vec());
    in_memory_fs.add_file("Windows/System32/drivers/etc/hosts", b"127.0.0.1 localhost".to_vec());
    let hive_bytes = std::fs::read("./artifacts/C/Windows/AppCompat/Programs/Amcache.hve")
        .expect("Amcache.hve fixture not found under ./artifacts/C/Windows/AppCompat/Programs");
    in_memory_fs.add_file(AMCACHE_PATH, hive_bytes);

    let fs: Arc<dyn FileSystem> = Arc::new(in_memory_fs);

    let mut reader = HiveRegistryReader::new();
    let hive_file = open_hive_with_logs(&fs, FPath::new(r"Windows\AppCompat\Programs"), "Amcache.hve")
        .expect("failed to open Amcache.hve from the in-memory filesystem");
    reader.add_other("Amcache", hive_file);
    let root = reader.other_hive_root("Amcache").expect("Amcache hive was just mounted above");
    let registry: Arc<dyn Registry> = Arc::new(reader);
    let amcache = AmCacheReader::new(registry, root);

    // Nothing is parsed yet at this point — a category is only enumerated,
    // and only as many records as requested, when the bridge actually
    // receives a request that reaches into it (see `AmcacheHook` above).
    let mut vfs_provider = VfsProvider::new(fs); // defaults to name "Filesystem"
    vfs_provider.add_hook(Box::new(AmcacheHook { amcache }));

    let client = ForensicBridgeBuilder::new().add_provider(vfs_provider).spawn();

    // A dedicated thread stands in for a UI: it only ever talks to the
    // bridge through the cloneable `BridgeClient` handle, same as a real
    // frontend thread would.
    let ui_client = client.clone();
    let ui_thread = std::thread::spawn(move || simulate_ui(ui_client));
    ui_thread.join().expect("UI thread panicked")?;

    client.shutdown()?;
    Ok(())
}
