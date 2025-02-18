use forensic_rs::{
    info,
    traits::registry::{auto_close_key, RegHiveKey, RegistryReader},
    utils::time::Filetime,
};

use super::{read_value_string_or_empty, read_value_u32_or_empty};

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
    pub timestamp: Filetime,
}
pub struct InventoryDeviceContainerIter<'a, R: RegistryReader> {
    pub(crate) pos: u32,
    pub(crate) key: RegHiveKey,
    pub(crate) reader: &'a R,
}

impl<'a, R: RegistryReader> Iterator for InventoryDeviceContainerIter<'a, R> {
    type Item = InventoryDeviceContainer;

    fn next(&mut self) -> Option<Self::Item> {
        if self.key == RegHiveKey::Hkey(0) {
            return None;
        }
        let pos = self.pos;
        self.pos += 1;
        let next_subkey = self.reader.key_at(self.key, pos).ok()?;
        let key = self.reader.open_key(self.key, &next_subkey).ok()?;
        match auto_close_key(self.reader, key, || {
            let model_name: String = read_value_string_or_empty(self.reader, key, "ModelName");
            let friendly_name: String =
                read_value_string_or_empty(self.reader, key, "FriendlyName");
            let model_number: String = read_value_string_or_empty(self.reader, key, "ModelNumber");
            let manufacturer: String = read_value_string_or_empty(self.reader, key, "Manufacturer");
            let model_id: String = read_value_string_or_empty(self.reader, key, "ModelId");
            let primary_category: String =
                read_value_string_or_empty(self.reader, key, "PrimaryCategory");
            let categories: String = read_value_string_or_empty(self.reader, key, "Categories");
            let is_machine_container: u32 =
                read_value_u32_or_empty(self.reader, key, "IsMachineContainer");
            let discovery_method: u32 =
                read_value_u32_or_empty(self.reader, key, "DiscoveryMethod");
            let is_connected: u32 = read_value_u32_or_empty(self.reader, key, "IsConnected");
            let is_active: u32 = read_value_u32_or_empty(self.reader, key, "IsActive");
            let is_paired: u32 = read_value_u32_or_empty(self.reader, key, "IsPaired");
            let is_networked: u32 = read_value_u32_or_empty(self.reader, key, "IsNetworked");
            let state: u32 = read_value_u32_or_empty(self.reader, key, "State");

            let key_info = self.reader.key_info(key)?;
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
        }) {
            Ok(v) => Some(v),
            Err(e) => {
                info!("Error getting AmCache File {}", e);
                None
            }
        }
    }
}

impl<'a, R: RegistryReader> Drop for InventoryDeviceContainerIter<'a, R> {
    fn drop(&mut self) {
        self.reader.close_key(self.key);
        self.key = RegHiveKey::Hkey(0);
    }
}
