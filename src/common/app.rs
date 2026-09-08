use std::collections::BTreeMap;

use forensic_rs::prelude::*;

use super::{read_value_string_or_empty, read_value_u32_or_empty, timestamp_to_bridge_value};

/// This event sends basic metadata about an application on the system.
///
/// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/privacy/basic-level-windows-diagnostic-events-and-fields-1903#microsoftwindowsinventorycoreinventoryapplicationadd
#[derive(Clone, Debug, Default)]
pub struct InventoryApplication {
    /// ProgramId
    pub program_id: String,
    /// ProgramInstanceId
    pub program_instance_id: String,
    /// Name
    pub name: String,
    /// Version
    pub version: String,
    /// Publisher
    pub publisher: String,
    /// Language
    pub language: u32,
    /// Source
    pub source: String,
    /// Type
    pub r#type: String,
    /// StoreAppType
    pub store_app_type: String,
    /// MsiPackageCode
    pub msi_package_code: String,
    /// MsiProductCode
    pub msi_product_code: String,
    /// HiddenArp
    pub hidden_arp: u32,
    /// InboxModernApp
    pub inbox_modern_app: u32,
    /// OSVersionAtInstallTime
    pub os_version_at_install_time: String,
    /// InstallDate
    pub install_date: String,
    /// PackageFullName
    pub package_full_name: String,
    /// ManifestPath
    pub manifest_path: String,
    /// BundleManifestPath
    pub bundle_manifest_path: String,
    /// RootDirPath
    pub root_dir_path: String,
    /// UninstallString
    pub uninstall_string: String,
    /// RegistryKeyPath
    pub registry_key_path: String,
    /// Last write timestamp
    pub timestamp: Option<ForensicTimestamp>,
}

impl From<&InventoryApplication> for BridgeValue {
    fn from(app: &InventoryApplication) -> Self {
        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("program_id"), BridgeValue::Text(Text::Owned(app.program_id.clone())));
        map.insert(Text::Borrowed("program_instance_id"), BridgeValue::Text(Text::Owned(app.program_instance_id.clone())));
        map.insert(Text::Borrowed("name"), BridgeValue::Text(Text::Owned(app.name.clone())));
        map.insert(Text::Borrowed("version"), BridgeValue::Text(Text::Owned(app.version.clone())));
        map.insert(Text::Borrowed("publisher"), BridgeValue::Text(Text::Owned(app.publisher.clone())));
        map.insert(Text::Borrowed("language"), BridgeValue::U64(app.language as u64));
        map.insert(Text::Borrowed("source"), BridgeValue::Text(Text::Owned(app.source.clone())));
        map.insert(Text::Borrowed("type"), BridgeValue::Text(Text::Owned(app.r#type.clone())));
        map.insert(Text::Borrowed("store_app_type"), BridgeValue::Text(Text::Owned(app.store_app_type.clone())));
        map.insert(Text::Borrowed("msi_package_code"), BridgeValue::Text(Text::Owned(app.msi_package_code.clone())));
        map.insert(Text::Borrowed("msi_product_code"), BridgeValue::Text(Text::Owned(app.msi_product_code.clone())));
        map.insert(Text::Borrowed("hidden_arp"), BridgeValue::U64(app.hidden_arp as u64));
        map.insert(Text::Borrowed("inbox_modern_app"), BridgeValue::U64(app.inbox_modern_app as u64));
        map.insert(Text::Borrowed("os_version_at_install_time"), BridgeValue::Text(Text::Owned(app.os_version_at_install_time.clone())));
        map.insert(Text::Borrowed("install_date"), BridgeValue::Text(Text::Owned(app.install_date.clone())));
        map.insert(Text::Borrowed("package_full_name"), BridgeValue::Text(Text::Owned(app.package_full_name.clone())));
        map.insert(Text::Borrowed("manifest_path"), BridgeValue::Text(Text::Owned(app.manifest_path.clone())));
        map.insert(Text::Borrowed("bundle_manifest_path"), BridgeValue::Text(Text::Owned(app.bundle_manifest_path.clone())));
        map.insert(Text::Borrowed("root_dir_path"), BridgeValue::Text(Text::Owned(app.root_dir_path.clone())));
        map.insert(Text::Borrowed("uninstall_string"), BridgeValue::Text(Text::Owned(app.uninstall_string.clone())));
        map.insert(Text::Borrowed("registry_key_path"), BridgeValue::Text(Text::Owned(app.registry_key_path.clone())));
        map.insert(Text::Borrowed("timestamp"), timestamp_to_bridge_value(app.timestamp));
        BridgeValue::Map(map)
    }
}

pub struct InventoryApplicationIter {
    pub(crate) key: OwnedRegKey,
    pub(crate) entries: std::vec::IntoIter<KeyEntry>,
}

impl InventoryApplicationIter {
    fn build(&self, name: &str) -> ForensicResult<InventoryApplication> {
        let key = self.key.open_child(name)?;
        let program_id: String = read_value_string_or_empty(&key, "ProgramId");
        let program_instance_id: String =
            read_value_string_or_empty(&key, "ProgramInstanceId");

        let name: String = read_value_string_or_empty(&key, "Name");
        let version: String = read_value_string_or_empty(&key, "Version");
        let publisher: String = read_value_string_or_empty(&key, "Publisher");
        let language: u32 = read_value_u32_or_empty(&key, "Language");
        let source: String = read_value_string_or_empty(&key, "Source");
        let r#type: String = read_value_string_or_empty(&key, "Type");
        let store_app_type: String =
            read_value_string_or_empty(&key, "StoreAppType");

        let msi_package_code: String =
            read_value_string_or_empty(&key, "MsiPackageCode");
        let msi_product_code: String =
            read_value_string_or_empty(&key, "MsiProductCode");
        let hidden_arp = read_value_u32_or_empty(&key, "HiddenArp");
        let inbox_modern_app = read_value_u32_or_empty(&key, "InboxModernApp");
        let os_version_at_install_time: String =
            read_value_string_or_empty(&key, "OSVersionAtInstallTime");
        let install_date: String = read_value_string_or_empty(&key, "InstallDate");
        let package_full_name: String =
            read_value_string_or_empty(&key, "PackageFullName");
        let manifest_path: String =
            read_value_string_or_empty(&key, "ManifestPath");
        let bundle_manifest_path =
            read_value_string_or_empty(&key, "BundleManifestPath");
        let root_dir_path = read_value_string_or_empty(&key, "RootDirPath");
        let uninstall_string = read_value_string_or_empty(&key, "UninstallString");
        let registry_key_path = read_value_string_or_empty(&key, "RegistryKeyPath");

        let key_info = key.info()?;
        Ok(InventoryApplication {
            program_id,
            program_instance_id,
            name,
            version,
            publisher,
            language,
            source,
            r#type,
            store_app_type,
            msi_package_code,
            msi_product_code,
            hidden_arp,
            inbox_modern_app,
            os_version_at_install_time,
            install_date,
            package_full_name,
            manifest_path,
            bundle_manifest_path,
            root_dir_path,
            uninstall_string,
            registry_key_path,

            timestamp: key_info.last_write_time,
        })
    }
}

impl Iterator for InventoryApplicationIter {
    type Item = InventoryApplication;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.next()?;
            match self.build(&entry.name) {
                Ok(v) => return Some(v),
                Err(e) => {
                    info!("Error parsing AmCache InventoryApplication entry {}: {}", entry.name, e);
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use frnsc_hive::reader::{open_hive_with_logs, HiveRegistryReader};

    use super::*;

    fn open_application_key() -> OwnedRegKey {
        let fs: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new("./artifacts/C", Arc::new(StdVirtualFS::new())));
        let mut reader = HiveRegistryReader::new();
        let hive_file = open_hive_with_logs(&fs, FPath::new(r"C:\Windows\AppCompat\Programs"), "Amcache.hve").unwrap();
        reader.add_other("Amcache", hive_file);
        let root = reader.other_hive_root("Amcache").unwrap();
        let registry: Arc<dyn Registry> = Arc::new(reader);
        let raw = registry.open_raw(&root, r"Root\InventoryApplication").unwrap();
        OwnedRegKey::new(registry, raw)
    }

    /// A single unreadable/nonexistent subkey used to previously stop the
    /// whole iterator (see the fix on `Iterator::next`, above) — it must now
    /// be skipped, still yielding every real entry around it.
    #[test]
    fn skips_bad_entry_instead_of_stopping() {
        let key = open_application_key();
        let good_entries = key.keys().unwrap();
        let good_count = good_entries.len();
        assert!(good_count > 0, "fixture hive should have application entries");

        let mut entries_with_bad = good_entries.clone();
        entries_with_bad.insert(
            good_count / 2,
            KeyEntry { name: "definitely-not-a-real-subkey".into(), last_write: None, allocated: true },
        );

        let iter = InventoryApplicationIter { key, entries: entries_with_bad.into_iter() };
        let results: Vec<_> = iter.collect();
        assert_eq!(results.len(), good_count, "iterator should skip the bad entry rather than stopping early");
    }
}
