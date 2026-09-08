use std::collections::BTreeMap;

use forensic_rs::prelude::*;

use super::{read_value_string_or_empty, read_value_u32_or_empty, timestamp_to_bridge_value};

/// This event sends basic metadata about a device container (such as a monitor or printer as opposed to a Plug and Play device).
///
/// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/privacy/basic-level-windows-diagnostic-events-and-fields-1803#microsoftwindowsinventorycoreinventorydevicecontaineradd
#[derive(Clone, Debug, Default)]
pub struct InventoryDeviceContainer {
    /// ModelName
    pub model_name: String,
    /// FriendlyName
    pub friendly_name: String,
    /// ModelNumber
    pub model_number: String,
    /// Manufacturer
    pub manufacturer: String,
    /// ModelId
    pub model_id: String,
    /// PrimaryCategory
    pub primary_category: String,
    /// Categories
    pub categories: String,
    /// IsMachineContainer
    pub is_machine_container: u32,
    /// DiscoveryMethod
    pub discovery_method: u32,
    /// IsConnected
    pub is_connected: u32,
    /// IsActive
    pub is_active: u32,
    /// IsPaired
    pub is_paired: u32,
    /// IsNetworked
    pub is_networked: u32,
    /// State
    pub state: u32,
    /// Last write timestamp
    pub timestamp: Option<ForensicTimestamp>,
}
impl From<&InventoryDeviceContainer> for BridgeValue {
    fn from(dev: &InventoryDeviceContainer) -> Self {
        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("model_name"), BridgeValue::Text(Text::Owned(dev.model_name.clone())));
        map.insert(Text::Borrowed("friendly_name"), BridgeValue::Text(Text::Owned(dev.friendly_name.clone())));
        map.insert(Text::Borrowed("model_number"), BridgeValue::Text(Text::Owned(dev.model_number.clone())));
        map.insert(Text::Borrowed("manufacturer"), BridgeValue::Text(Text::Owned(dev.manufacturer.clone())));
        map.insert(Text::Borrowed("model_id"), BridgeValue::Text(Text::Owned(dev.model_id.clone())));
        map.insert(Text::Borrowed("primary_category"), BridgeValue::Text(Text::Owned(dev.primary_category.clone())));
        map.insert(Text::Borrowed("categories"), BridgeValue::Text(Text::Owned(dev.categories.clone())));
        map.insert(Text::Borrowed("is_machine_container"), BridgeValue::U64(dev.is_machine_container as u64));
        map.insert(Text::Borrowed("discovery_method"), BridgeValue::U64(dev.discovery_method as u64));
        map.insert(Text::Borrowed("is_connected"), BridgeValue::U64(dev.is_connected as u64));
        map.insert(Text::Borrowed("is_active"), BridgeValue::U64(dev.is_active as u64));
        map.insert(Text::Borrowed("is_paired"), BridgeValue::U64(dev.is_paired as u64));
        map.insert(Text::Borrowed("is_networked"), BridgeValue::U64(dev.is_networked as u64));
        map.insert(Text::Borrowed("state"), BridgeValue::U64(dev.state as u64));
        map.insert(Text::Borrowed("timestamp"), timestamp_to_bridge_value(dev.timestamp));
        BridgeValue::Map(map)
    }
}

pub struct InventoryDeviceContainerIter {
    pub(crate) key: OwnedRegKey,
    pub(crate) entries: std::vec::IntoIter<KeyEntry>,
}

impl InventoryDeviceContainerIter {
    fn build(&self, name: &str) -> ForensicResult<InventoryDeviceContainer> {
        let key = self.key.open_child(name)?;
        let model_name: String = read_value_string_or_empty(&key, "ModelName");
        let friendly_name: String =
            read_value_string_or_empty(&key, "FriendlyName");
        let model_number: String = read_value_string_or_empty(&key, "ModelNumber");
        let manufacturer: String = read_value_string_or_empty(&key, "Manufacturer");
        let model_id: String = read_value_string_or_empty(&key, "ModelId");
        let primary_category: String =
            read_value_string_or_empty(&key, "PrimaryCategory");
        let categories: String = read_value_string_or_empty(&key, "Categories");
        let is_machine_container: u32 =
            read_value_u32_or_empty(&key, "IsMachineContainer");
        let discovery_method: u32 =
            read_value_u32_or_empty(&key, "DiscoveryMethod");
        let is_connected: u32 = read_value_u32_or_empty(&key, "IsConnected");
        let is_active: u32 = read_value_u32_or_empty(&key, "IsActive");
        let is_paired: u32 = read_value_u32_or_empty(&key, "IsPaired");
        let is_networked: u32 = read_value_u32_or_empty(&key, "IsNetworked");
        let state: u32 = read_value_u32_or_empty(&key, "State");

        let key_info = key.info()?;
        Ok(InventoryDeviceContainer {
            model_name,
            friendly_name,
            model_number,
            manufacturer,
            model_id,
            primary_category,
            categories,
            is_machine_container,
            discovery_method,
            is_connected,
            is_active,
            is_networked,
            is_paired,
            state,
            timestamp: key_info.last_write_time,
        })
    }
}

impl Iterator for InventoryDeviceContainerIter {
    type Item = InventoryDeviceContainer;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.next()?;
            match self.build(&entry.name) {
                Ok(v) => return Some(v),
                Err(e) => {
                    info!("Error parsing AmCache InventoryDeviceContainer entry {}: {}", entry.name, e);
                    continue;
                }
            }
        }
    }
}
