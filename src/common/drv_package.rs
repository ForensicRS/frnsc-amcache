use forensic_rs::{
    info,
    traits::registry::{auto_close_key, RegHiveKey, RegistryReader},
    utils::time::Filetime,
};

use super::{read_value_string_or_empty, read_value_u32_or_empty};

/// This event sends basic metadata about drive packages installed on the system.
///
/// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/privacy/basic-level-windows-diagnostic-events-and-fields-1803#microsoftwindowsinventorycoreinventorydriverpackageadd
#[derive(Clone, Debug, Default)]
pub struct InventoryDriverPackage {
    pub class_guid: String,
    pub class: String,
    pub directory: String,
    pub date: String,
    pub version: String,
    pub provider: String,
    pub submission_id: String,
    pub driver_inbox: u32,
    pub inf: String,
    pub flight_ids: String,
    pub recovery_ids: String,
    pub is_active: u32,
    pub hwids: String,
    pub sysfile: String,
    /// Last write timestamp
    pub timestamp: Filetime,
}
pub struct InventoryDriverPackageIter<'a, R: RegistryReader> {
    pub(crate) pos: u32,
    pub(crate) key: RegHiveKey,
    pub(crate) reader: &'a R,
}

impl<'a, R: RegistryReader> Iterator for InventoryDriverPackageIter<'a, R> {
    type Item = InventoryDriverPackage;

    fn next(&mut self) -> Option<Self::Item> {
        if self.key == RegHiveKey::Hkey(0) {
            return None;
        }
        let pos = self.pos;
        self.pos += 1;
        let next_subkey = self.reader.key_at(self.key, pos).ok()?;
        let key = self.reader.open_key(self.key, &next_subkey).ok()?;
        match auto_close_key(self.reader, key, || {
            let class_guid = read_value_string_or_empty(self.reader, key, "ClassGuid");
            let class = read_value_string_or_empty(self.reader, key, "Class");
            let directory = read_value_string_or_empty(self.reader, key, "Directory");
            let date = read_value_string_or_empty(self.reader, key, "Date");
            let version = read_value_string_or_empty(self.reader, key, "Version");
            let provider = read_value_string_or_empty(self.reader, key, "Provider");
            let submission_id = read_value_string_or_empty(self.reader, key, "SubmissionId");
            let driver_inbox = read_value_u32_or_empty(self.reader, key, "DriverInBox");
            let inf = read_value_string_or_empty(self.reader, key, "Inf");
            let flight_ids = read_value_string_or_empty(self.reader, key, "FlightIds");
            let recovery_ids = read_value_string_or_empty(self.reader, key, "RecoveryIds");
            let is_active = read_value_u32_or_empty(self.reader, key, "IsActive");
            let hwids = read_value_string_or_empty(self.reader, key, "Hwids");
            let sysfile = read_value_string_or_empty(self.reader, key, "SYSFILE");

            let key_info = self.reader.key_info(key)?;
            Ok(InventoryDriverPackage {
                class_guid,
                class,
                directory,
                date,
                version,
                provider,
                submission_id,
                driver_inbox,
                inf,
                flight_ids,
                recovery_ids,
                is_active,
                hwids,
                sysfile,
                timestamp: key_info.last_write_time,
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

impl<'a, R: RegistryReader> Drop for InventoryDriverPackageIter<'a, R> {
    fn drop(&mut self) {
        self.reader.close_key(self.key);
        self.key = RegHiveKey::Hkey(0);
    }
}
