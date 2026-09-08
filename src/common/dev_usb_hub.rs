use std::collections::BTreeMap;

use forensic_rs::prelude::*;

use super::{read_value_string_or_empty, read_value_u32_or_empty, timestamp_to_bridge_value};

/// This event sends basic metadata about the USB hubs present on the system. In the reference
/// fixture there is exactly one entry per hive, keyed `DeviceUsbHubClass`, but this iterates
/// whatever subkeys are present rather than assuming that name — same as every other inventory
/// in this crate.
///
/// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/privacy/basic-level-windows-diagnostic-events-and-fields-1803#microsoftwindowsinventorycoreinventorydeviceusbhubclassadd
#[derive(Clone, Debug, Default)]
pub struct InventoryDeviceUsbHubClass {
    /// TotalUserConnectablePorts
    pub total_user_connectable_ports: u32,
    /// TotalUserConnectableTypeCPorts
    pub total_user_connectable_type_c_ports: u32,
    /// Inf
    pub inf: String,
    /// Last write timestamp
    pub timestamp: Option<ForensicTimestamp>,
}

impl From<&InventoryDeviceUsbHubClass> for BridgeValue {
    fn from(hub: &InventoryDeviceUsbHubClass) -> Self {
        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("total_user_connectable_ports"), BridgeValue::U64(hub.total_user_connectable_ports as u64));
        map.insert(Text::Borrowed("total_user_connectable_type_c_ports"), BridgeValue::U64(hub.total_user_connectable_type_c_ports as u64));
        map.insert(Text::Borrowed("inf"), BridgeValue::Text(Text::Owned(hub.inf.clone())));
        map.insert(Text::Borrowed("timestamp"), timestamp_to_bridge_value(hub.timestamp));
        BridgeValue::Map(map)
    }
}

pub struct InventoryDeviceUsbHubClassIter {
    pub(crate) key: OwnedRegKey,
    pub(crate) entries: std::vec::IntoIter<KeyEntry>,
}

impl InventoryDeviceUsbHubClassIter {
    fn build(&self, name: &str) -> ForensicResult<InventoryDeviceUsbHubClass> {
        let key = self.key.open_child(name)?;
        let total_user_connectable_ports = read_value_u32_or_empty(&key, "TotalUserConnectablePorts");
        let total_user_connectable_type_c_ports = read_value_u32_or_empty(&key, "TotalUserConnectableTypeCPorts");
        let inf = read_value_string_or_empty(&key, "Inf");

        let key_info = key.info()?;
        Ok(InventoryDeviceUsbHubClass {
            total_user_connectable_ports,
            total_user_connectable_type_c_ports,
            inf,
            timestamp: key_info.last_write_time,
        })
    }
}

impl Iterator for InventoryDeviceUsbHubClassIter {
    type Item = InventoryDeviceUsbHubClass;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.next()?;
            match self.build(&entry.name) {
                Ok(v) => return Some(v),
                Err(e) => {
                    info!("Error parsing AmCache InventoryDeviceUsbHubClass entry {}: {}", entry.name, e);
                    continue;
                }
            }
        }
    }
}
