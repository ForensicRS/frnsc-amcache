use std::collections::BTreeMap;

use forensic_rs::prelude::*;

use super::{empty_string, read_value_string_or_empty, read_value_u32_or_empty, read_value_u64_or_empty, timestamp_to_bridge_value};

/// This event represents the basic metadata about a file on the system. The file must be part of an app and either have a block in the compatibility database or be part of an antivirus program.
///
/// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/privacy/basic-level-windows-diagnostic-events-and-fields-1803#microsoftwindowsappraisergeneralinventoryapplicationfileadd
#[derive(Clone, Debug, Default)]
pub struct InventoryApplicationFile {
    /// LowerCaseLongPath
    pub path: String,
    /// ProductVersion
    pub product_version: String,
    /// ProductName
    pub product_name: String,
    /// ProgramId
    pub program_id: String,
    /// Last write timestamp
    pub timestamp: Option<ForensicTimestamp>,
    /// FileId
    pub hash: String,
    /// Publisher
    pub publisher: String,
    /// LinkDate
    pub link_date: String,
    /// Language
    pub language: u32,
    /// Size
    pub size: u64,
    /// BinaryType
    pub bin_type: String,
    /// Usn
    pub usn: u64,
}

impl From<&InventoryApplicationFile> for BridgeValue {
    fn from(file: &InventoryApplicationFile) -> Self {
        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("path"), BridgeValue::Text(Text::Owned(file.path.clone())));
        map.insert(Text::Borrowed("product_version"), BridgeValue::Text(Text::Owned(file.product_version.clone())));
        map.insert(Text::Borrowed("product_name"), BridgeValue::Text(Text::Owned(file.product_name.clone())));
        map.insert(Text::Borrowed("program_id"), BridgeValue::Text(Text::Owned(file.program_id.clone())));
        map.insert(Text::Borrowed("hash"), BridgeValue::Text(Text::Owned(file.hash.clone())));
        map.insert(Text::Borrowed("publisher"), BridgeValue::Text(Text::Owned(file.publisher.clone())));
        map.insert(Text::Borrowed("link_date"), BridgeValue::Text(Text::Owned(file.link_date.clone())));
        map.insert(Text::Borrowed("language"), BridgeValue::U64(file.language as u64));
        map.insert(Text::Borrowed("size"), BridgeValue::U64(file.size));
        map.insert(Text::Borrowed("bin_type"), BridgeValue::Text(Text::Owned(file.bin_type.clone())));
        map.insert(Text::Borrowed("usn"), BridgeValue::U64(file.usn));
        map.insert(Text::Borrowed("timestamp"), timestamp_to_bridge_value(file.timestamp));
        BridgeValue::Map(map)
    }
}

pub struct InventoryApplicationFileIter {
    pub(crate) key: OwnedRegKey,
    pub(crate) entries: std::vec::IntoIter<KeyEntry>,
}

impl InventoryApplicationFileIter {
    fn build(&self, name: &str) -> ForensicResult<InventoryApplicationFile> {
        let key = self.key.open_child(name)?;
        let path: String = read_value_string_or_empty(&key, "LowerCaseLongPath");
        let product_version: String = key
            .value("ProductVersion")
            .or_else(|_| key.value("BinProductVersion"))
            .unwrap_or_else(empty_string)
            .try_into()
            .unwrap_or_default();
        let product_name: String = read_value_string_or_empty(&key, "ProductName");
        let program_id: String = read_value_string_or_empty(&key, "ProgramId");
        let hash: String = read_value_string_or_empty(&key, "FileId");
        let publisher: String = read_value_string_or_empty(&key, "Publisher");

        let link_date: String = read_value_string_or_empty(&key, "LinkDate");
        let language: u32 = read_value_u32_or_empty(&key, "Language");
        let size: u64 = read_value_u64_or_empty(&key, "Size");
        let bin_type: String = read_value_string_or_empty(&key, "BinaryType");
        let usn: u64 = read_value_u64_or_empty(&key, "Usn");

        let key_info = key.info()?;
        Ok(InventoryApplicationFile {
            path,
            program_id,
            timestamp: key_info.last_write_time,
            product_version,
            product_name,
            hash,
            publisher,
            link_date,
            language,
            size,
            bin_type,
            usn,
        })
    }
}

impl Iterator for InventoryApplicationFileIter {
    type Item = InventoryApplicationFile;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.next()?;
            match self.build(&entry.name) {
                Ok(v) => return Some(v),
                Err(e) => {
                    info!("Error parsing AmCache InventoryApplicationFile entry {}: {}", entry.name, e);
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use forensic_rs::prelude::testing::TestingRegistry;

    use super::*;

    /// A file entry missing both `ProductVersion` and `BinProductVersion` used to propagate a
    /// hard error via `?`, dropping the whole entry from iteration instead of defaulting
    /// `product_version` to empty like every other field (see AGENT.md's "default rather than
    /// error" convention).
    #[test]
    fn missing_product_version_defaults_to_empty_instead_of_dropping_the_entry() {
        let mut reg = TestingRegistry::new();
        reg.add_value("HKLM\\SomeApp", "LowerCaseLongPath", RegValue::new_sz(r"c:\some\app.exe"));
        let root = reg.root(PredefinedHive::LocalMachine).unwrap();
        let registry: Arc<dyn Registry> = Arc::new(reg);
        let key = OwnedRegKey::new(registry, root);
        let entries = vec![KeyEntry { name: "SomeApp".into(), last_write: None, allocated: true }].into_iter();

        let iter = InventoryApplicationFileIter { key, entries };
        let results: Vec<_> = iter.collect();
        assert_eq!(results.len(), 1, "entry should still be yielded even without a product version");
        assert_eq!(results[0].product_version, "");
    }
}
