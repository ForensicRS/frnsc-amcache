use forensic_rs::{
    info,
    traits::registry::{auto_close_key, RegHiveKey, RegistryReader},
    utils::time::Filetime,
};

use super::{read_value_string_or_empty, read_value_u32_or_empty, read_value_u64_or_empty};

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
    pub timestamp: Filetime,
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

pub struct InventoryApplicationFileIter<'a, R: RegistryReader> {
    pub(crate) pos: u32,
    pub(crate) key: RegHiveKey,
    pub(crate) reader: &'a R,
}

impl<'a, R: RegistryReader> Iterator for InventoryApplicationFileIter<'a, R> {
    type Item = InventoryApplicationFile;

    fn next(&mut self) -> Option<Self::Item> {
        if self.key == RegHiveKey::Hkey(0) {
            return None;
        }
        let pos = self.pos;
        self.pos += 1;
        let next_subkey = self.reader.key_at(self.key, pos).ok()?;
        let key = self.reader.open_key(self.key, &next_subkey).ok()?;
        match auto_close_key(self.reader, key, || {
            let path: String = read_value_string_or_empty(self.reader, key, "LowerCaseLongPath");
            let product_version: String = match self.reader.read_value(key, "ProductVersion") {
                Ok(v) => v,
                Err(_) => self.reader.read_value(key, "BinProductVersion")?,
            }
            .try_into()?;
            let product_name: String = read_value_string_or_empty(self.reader, key, "ProductName");
            let program_id: String = read_value_string_or_empty(self.reader, key, "ProgramId");
            let hash: String = read_value_string_or_empty(self.reader, key, "FileId");
            let publisher: String = read_value_string_or_empty(self.reader, key, "Publisher");

            let link_date: String = read_value_string_or_empty(self.reader, key, "LinkDate");
            let language: u32 = read_value_u32_or_empty(self.reader, key, "Language");
            let size: u64 = read_value_u64_or_empty(self.reader, key, "Size");
            let bin_type: String = read_value_string_or_empty(self.reader, key, "BinaryType");
            let usn: u64 = read_value_u64_or_empty(self.reader, key, "Usn");

            let key_info = self.reader.key_info(key)?;
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
        }) {
            Ok(v) => Some(v),
            Err(e) => {
                info!("Error getting AmCache File {}", e);
                None
            }
        }
    }
}

impl<'a, R: RegistryReader> Drop for InventoryApplicationFileIter<'a, R> {
    fn drop(&mut self) {
        self.reader.close_key(self.key);
        self.key = RegHiveKey::Hkey(0);
    }
}
