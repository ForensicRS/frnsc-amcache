use std::collections::BTreeMap;

use forensic_rs::prelude::*;

use super::{read_value_string_or_empty, read_value_u32_or_empty, timestamp_to_bridge_value};

/// This event sends basic metadata about driver binaries running on the system.
///
/// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/privacy/basic-level-windows-diagnostic-events-and-fields-1803#microsoftwindowsinventorycoreinventorydriverbinaryadd
#[derive(Clone, Debug, Default)]
pub struct InventoryDriverBinary {
    /// DriverName
    pub driver_name: String,
    /// Inf
    pub inf: String,
    /// DriverVersion
    pub driver_version: String,
    /// Product
    pub product: String,
    /// ProductVersion
    pub product_version: String,
    /// WdfVersion: Windows Driver Framework
    pub wdf_version: String,
    pub driver_company : String,
    pub driver_package_strong_name : String,
    pub service : String,
    pub driver_in_box : u32,
    pub driver_signed : u32,
    pub driver_is_kernel_mode : u32,
    pub driver_id : String,
    pub driver_last_write_time : String,
    pub driver_type : u32,
    pub driver_timestamp : u32,
    pub driver_check_sum : u32,
    pub image_size : u32,
    /// Last write timestamp
    pub timestamp : Option<ForensicTimestamp>,
}
impl From<&InventoryDriverBinary> for BridgeValue {
    fn from(drv: &InventoryDriverBinary) -> Self {
        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("driver_name"), BridgeValue::Text(Text::Owned(drv.driver_name.clone())));
        map.insert(Text::Borrowed("inf"), BridgeValue::Text(Text::Owned(drv.inf.clone())));
        map.insert(Text::Borrowed("driver_version"), BridgeValue::Text(Text::Owned(drv.driver_version.clone())));
        map.insert(Text::Borrowed("product"), BridgeValue::Text(Text::Owned(drv.product.clone())));
        map.insert(Text::Borrowed("product_version"), BridgeValue::Text(Text::Owned(drv.product_version.clone())));
        map.insert(Text::Borrowed("wdf_version"), BridgeValue::Text(Text::Owned(drv.wdf_version.clone())));
        map.insert(Text::Borrowed("driver_company"), BridgeValue::Text(Text::Owned(drv.driver_company.clone())));
        map.insert(Text::Borrowed("driver_package_strong_name"), BridgeValue::Text(Text::Owned(drv.driver_package_strong_name.clone())));
        map.insert(Text::Borrowed("service"), BridgeValue::Text(Text::Owned(drv.service.clone())));
        map.insert(Text::Borrowed("driver_in_box"), BridgeValue::U64(drv.driver_in_box as u64));
        map.insert(Text::Borrowed("driver_signed"), BridgeValue::U64(drv.driver_signed as u64));
        map.insert(Text::Borrowed("driver_is_kernel_mode"), BridgeValue::U64(drv.driver_is_kernel_mode as u64));
        map.insert(Text::Borrowed("driver_id"), BridgeValue::Text(Text::Owned(drv.driver_id.clone())));
        map.insert(Text::Borrowed("driver_last_write_time"), BridgeValue::Text(Text::Owned(drv.driver_last_write_time.clone())));
        map.insert(Text::Borrowed("driver_type"), BridgeValue::U64(drv.driver_type as u64));
        map.insert(Text::Borrowed("driver_timestamp"), BridgeValue::U64(drv.driver_timestamp as u64));
        map.insert(Text::Borrowed("driver_check_sum"), BridgeValue::U64(drv.driver_check_sum as u64));
        map.insert(Text::Borrowed("image_size"), BridgeValue::U64(drv.image_size as u64));
        map.insert(Text::Borrowed("timestamp"), timestamp_to_bridge_value(drv.timestamp));
        BridgeValue::Map(map)
    }
}

pub struct InventoryDriverBinaryIter {
    pub(crate) key : OwnedRegKey,
    pub(crate) entries : std::vec::IntoIter<KeyEntry>,
}

impl InventoryDriverBinaryIter {
    fn build(&self, name: &str) -> ForensicResult<InventoryDriverBinary> {
        let key = self.key.open_child(name)?;
        let driver_name : String = read_value_string_or_empty(&key, "DriverName");
        let inf: String = read_value_string_or_empty(&key, "Inf");
        let driver_version : String = read_value_string_or_empty(&key, "DriverVersion");
        let product : String = read_value_string_or_empty(&key, "Product");
        let product_version : String = read_value_string_or_empty(&key, "ProductVersion");
        let wdf_version : String = read_value_string_or_empty(&key, "WdfVersion");
        let driver_company : String = read_value_string_or_empty(&key, "DriverCompany");
        let driver_package_strong_name = read_value_string_or_empty(&key, "DriverPackageStrongName");
        let service = read_value_string_or_empty(&key, "Service");
        let driver_in_box : u32 = read_value_u32_or_empty(&key, "DriverInBox");
        let driver_signed : u32 = read_value_u32_or_empty(&key, "DriverSigned");
        let driver_is_kernel_mode : u32 = read_value_u32_or_empty(&key, "DriverIsKernelMode");

        let driver_id = read_value_string_or_empty(&key, "DriverId");
        let driver_last_write_time = read_value_string_or_empty(&key, "DriverLastWriteTime");
        let driver_type : u32 = read_value_u32_or_empty(&key, "DriverType");
        let driver_timestamp : u32 = read_value_u32_or_empty(&key, "DriverTimeStamp");
        let driver_check_sum : u32 = read_value_u32_or_empty(&key, "DriverCheckSum");
        let image_size : u32 = read_value_u32_or_empty(&key, "ImageSize");

        let key_info = key.info()?;
        Ok(InventoryDriverBinary {
            driver_name,
            inf,
            driver_version,
            product,
            product_version,
            wdf_version,
            driver_company,
            driver_package_strong_name,
            service,
            driver_in_box,
            driver_signed,
            driver_is_kernel_mode,
            driver_id,
            driver_last_write_time,
            driver_type,
            driver_timestamp,
            driver_check_sum,
            image_size,
            timestamp : key_info.last_write_time
        })
    }
}

impl Iterator for InventoryDriverBinaryIter {
    type Item = InventoryDriverBinary;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.next()?;
            match self.build(&entry.name) {
                Ok(v) => return Some(v),
                Err(e) => {
                    info!("Error parsing AmCache InventoryDriverBinary entry {}: {}", entry.name, e);
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

    fn open_driver_binary_key() -> OwnedRegKey {
        let fs: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new("./artifacts/C", Arc::new(StdVirtualFS::new())));
        let mut reader = HiveRegistryReader::new();
        let hive_file = open_hive_with_logs(&fs, FPath::new(r"C:\Windows\AppCompat\Programs"), "Amcache.hve").unwrap();
        reader.add_other("Amcache", hive_file);
        let root = reader.other_hive_root("Amcache").unwrap();
        let registry: Arc<dyn Registry> = Arc::new(reader);
        let raw = registry.open_raw(&root, r"Root\InventoryDriverBinary").unwrap();
        OwnedRegKey::new(registry, raw)
    }

    /// A single unreadable/nonexistent subkey used to previously stop the
    /// whole iterator (see the fix on `Iterator::next`, above) — it must now
    /// be skipped, still yielding every real entry around it.
    #[test]
    fn skips_bad_entry_instead_of_stopping() {
        let key = open_driver_binary_key();
        let good_entries = key.keys().unwrap();
        let good_count = good_entries.len();
        assert!(good_count > 0, "fixture hive should have driver binary entries");

        let mut entries_with_bad = good_entries.clone();
        entries_with_bad.insert(
            good_count / 2,
            KeyEntry { name: "definitely-not-a-real-subkey".into(), last_write: None, allocated: true },
        );

        let iter = InventoryDriverBinaryIter { key, entries: entries_with_bad.into_iter() };
        let results: Vec<_> = iter.collect();
        assert_eq!(results.len(), good_count, "iterator should skip the bad entry rather than stopping early");
    }
}
