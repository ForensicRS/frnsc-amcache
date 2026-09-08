use std::collections::BTreeMap;

use forensic_rs::prelude::*;

use super::{read_value_string_or_empty, read_value_u32_or_empty, timestamp_to_bridge_value};

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
    pub timestamp: Option<ForensicTimestamp>,
}
impl From<&InventoryDriverPackage> for BridgeValue {
    fn from(pkg: &InventoryDriverPackage) -> Self {
        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("class_guid"), BridgeValue::Text(Text::Owned(pkg.class_guid.clone())));
        map.insert(Text::Borrowed("class"), BridgeValue::Text(Text::Owned(pkg.class.clone())));
        map.insert(Text::Borrowed("directory"), BridgeValue::Text(Text::Owned(pkg.directory.clone())));
        map.insert(Text::Borrowed("date"), BridgeValue::Text(Text::Owned(pkg.date.clone())));
        map.insert(Text::Borrowed("version"), BridgeValue::Text(Text::Owned(pkg.version.clone())));
        map.insert(Text::Borrowed("provider"), BridgeValue::Text(Text::Owned(pkg.provider.clone())));
        map.insert(Text::Borrowed("submission_id"), BridgeValue::Text(Text::Owned(pkg.submission_id.clone())));
        map.insert(Text::Borrowed("driver_inbox"), BridgeValue::U64(pkg.driver_inbox as u64));
        map.insert(Text::Borrowed("inf"), BridgeValue::Text(Text::Owned(pkg.inf.clone())));
        map.insert(Text::Borrowed("flight_ids"), BridgeValue::Text(Text::Owned(pkg.flight_ids.clone())));
        map.insert(Text::Borrowed("recovery_ids"), BridgeValue::Text(Text::Owned(pkg.recovery_ids.clone())));
        map.insert(Text::Borrowed("is_active"), BridgeValue::U64(pkg.is_active as u64));
        map.insert(Text::Borrowed("hwids"), BridgeValue::Text(Text::Owned(pkg.hwids.clone())));
        map.insert(Text::Borrowed("sysfile"), BridgeValue::Text(Text::Owned(pkg.sysfile.clone())));
        map.insert(Text::Borrowed("timestamp"), timestamp_to_bridge_value(pkg.timestamp));
        BridgeValue::Map(map)
    }
}

pub struct InventoryDriverPackageIter {
    pub(crate) key: OwnedRegKey,
    pub(crate) entries: std::vec::IntoIter<KeyEntry>,
}

impl InventoryDriverPackageIter {
    fn build(&self, name: &str) -> ForensicResult<InventoryDriverPackage> {
        let key = self.key.open_child(name)?;
        let class_guid = read_value_string_or_empty(&key, "ClassGuid");
        let class = read_value_string_or_empty(&key, "Class");
        let directory = read_value_string_or_empty(&key, "Directory");
        let date = read_value_string_or_empty(&key, "Date");
        let version = read_value_string_or_empty(&key, "Version");
        let provider = read_value_string_or_empty(&key, "Provider");
        let submission_id = read_value_string_or_empty(&key, "SubmissionId");
        let driver_inbox = read_value_u32_or_empty(&key, "DriverInBox");
        let inf = read_value_string_or_empty(&key, "Inf");
        let flight_ids = read_value_string_or_empty(&key, "FlightIds");
        let recovery_ids = read_value_string_or_empty(&key, "RecoveryIds");
        let is_active = read_value_u32_or_empty(&key, "IsActive");
        let hwids = read_value_string_or_empty(&key, "Hwids");
        let sysfile = read_value_string_or_empty(&key, "SYSFILE");

        let key_info = key.info()?;
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
    }
}

impl Iterator for InventoryDriverPackageIter {
    type Item = InventoryDriverPackage;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.next()?;
            match self.build(&entry.name) {
                Ok(v) => return Some(v),
                Err(e) => {
                    info!("Error parsing AmCache InventoryDriverPackage entry {}: {}", entry.name, e);
                    continue;
                }
            }
        }
    }
}
