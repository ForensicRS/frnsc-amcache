use std::collections::BTreeMap;

use forensic_rs::prelude::*;

use super::{read_value_string_or_empty, timestamp_to_bridge_value};

/// This event sends basic metadata about a Plug and Play (PnP) device and its associated
/// driver. Every field observed in the reference fixture is a `REG_SZ` — including the
/// state/code-looking ones like `DeviceState`/`ProblemCode`/`InstallState` — not a `REG_DWORD`,
/// so every field here is modeled as `String` rather than a numeric type.
///
/// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/privacy/basic-level-windows-diagnostic-events-and-fields-1803#microsoftwindowsinventorycoreinventorydevicepnpadd
#[derive(Clone, Debug, Default)]
pub struct InventoryDevicePnp {
    /// Model
    pub model: String,
    /// Manufacturer
    pub manufacturer: String,
    /// DriverName
    pub driver_name: String,
    /// ParentId
    pub parent_id: String,
    /// MatchingID
    pub matching_id: String,
    /// Class
    pub class: String,
    /// ClassGuid
    pub class_guid: String,
    /// Description
    pub description: String,
    /// Enumerator
    pub enumerator: String,
    /// Service
    pub service: String,
    /// InstallState
    pub install_state: String,
    /// DeviceState
    pub device_state: String,
    /// Inf
    pub inf: String,
    /// DriverVerDate
    pub driver_ver_date: String,
    /// DriverVerVersion
    pub driver_ver_version: String,
    /// DriverPackageStrongName
    pub driver_package_strong_name: String,
    /// ContainerId
    pub container_id: String,
    /// ProblemCode
    pub problem_code: String,
    /// Provider
    pub provider: String,
    /// DriverId
    pub driver_id: String,
    /// BusReportedDescription
    pub bus_reported_description: String,
    /// HWID
    pub hwid: String,
    /// ExtendedInfs
    pub extended_infs: String,
    /// COMPID
    pub comp_id: String,
    /// STACKID
    pub stack_id: String,
    /// UpperClassFilters
    pub upper_class_filters: String,
    /// LowerClassFilters
    pub lower_class_filters: String,
    /// UpperFilters
    pub upper_filters: String,
    /// LowerFilters
    pub lower_filters: String,
    /// DeviceInterfaceClasses
    pub device_interface_classes: String,
    /// DeviceDriverFlightId
    pub device_driver_flight_id: String,
    /// DeviceExtDriversFlightIds
    pub device_ext_drivers_flight_ids: String,
    /// InstallDate
    pub install_date: String,
    /// FirstInstallDate
    pub first_install_date: String,
    /// IsMachineContainer — observed on only a small minority of entries in the reference
    /// fixture (most PnP devices aren't machine containers); empty when absent, same as every
    /// other field here.
    pub is_machine_container: String,
    /// Last write timestamp
    pub timestamp: Option<ForensicTimestamp>,
}

impl From<&InventoryDevicePnp> for BridgeValue {
    fn from(dev: &InventoryDevicePnp) -> Self {
        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("model"), BridgeValue::Text(Text::Owned(dev.model.clone())));
        map.insert(Text::Borrowed("manufacturer"), BridgeValue::Text(Text::Owned(dev.manufacturer.clone())));
        map.insert(Text::Borrowed("driver_name"), BridgeValue::Text(Text::Owned(dev.driver_name.clone())));
        map.insert(Text::Borrowed("parent_id"), BridgeValue::Text(Text::Owned(dev.parent_id.clone())));
        map.insert(Text::Borrowed("matching_id"), BridgeValue::Text(Text::Owned(dev.matching_id.clone())));
        map.insert(Text::Borrowed("class"), BridgeValue::Text(Text::Owned(dev.class.clone())));
        map.insert(Text::Borrowed("class_guid"), BridgeValue::Text(Text::Owned(dev.class_guid.clone())));
        map.insert(Text::Borrowed("description"), BridgeValue::Text(Text::Owned(dev.description.clone())));
        map.insert(Text::Borrowed("enumerator"), BridgeValue::Text(Text::Owned(dev.enumerator.clone())));
        map.insert(Text::Borrowed("service"), BridgeValue::Text(Text::Owned(dev.service.clone())));
        map.insert(Text::Borrowed("install_state"), BridgeValue::Text(Text::Owned(dev.install_state.clone())));
        map.insert(Text::Borrowed("device_state"), BridgeValue::Text(Text::Owned(dev.device_state.clone())));
        map.insert(Text::Borrowed("inf"), BridgeValue::Text(Text::Owned(dev.inf.clone())));
        map.insert(Text::Borrowed("driver_ver_date"), BridgeValue::Text(Text::Owned(dev.driver_ver_date.clone())));
        map.insert(Text::Borrowed("driver_ver_version"), BridgeValue::Text(Text::Owned(dev.driver_ver_version.clone())));
        map.insert(Text::Borrowed("driver_package_strong_name"), BridgeValue::Text(Text::Owned(dev.driver_package_strong_name.clone())));
        map.insert(Text::Borrowed("container_id"), BridgeValue::Text(Text::Owned(dev.container_id.clone())));
        map.insert(Text::Borrowed("problem_code"), BridgeValue::Text(Text::Owned(dev.problem_code.clone())));
        map.insert(Text::Borrowed("provider"), BridgeValue::Text(Text::Owned(dev.provider.clone())));
        map.insert(Text::Borrowed("driver_id"), BridgeValue::Text(Text::Owned(dev.driver_id.clone())));
        map.insert(Text::Borrowed("bus_reported_description"), BridgeValue::Text(Text::Owned(dev.bus_reported_description.clone())));
        map.insert(Text::Borrowed("hwid"), BridgeValue::Text(Text::Owned(dev.hwid.clone())));
        map.insert(Text::Borrowed("extended_infs"), BridgeValue::Text(Text::Owned(dev.extended_infs.clone())));
        map.insert(Text::Borrowed("comp_id"), BridgeValue::Text(Text::Owned(dev.comp_id.clone())));
        map.insert(Text::Borrowed("stack_id"), BridgeValue::Text(Text::Owned(dev.stack_id.clone())));
        map.insert(Text::Borrowed("upper_class_filters"), BridgeValue::Text(Text::Owned(dev.upper_class_filters.clone())));
        map.insert(Text::Borrowed("lower_class_filters"), BridgeValue::Text(Text::Owned(dev.lower_class_filters.clone())));
        map.insert(Text::Borrowed("upper_filters"), BridgeValue::Text(Text::Owned(dev.upper_filters.clone())));
        map.insert(Text::Borrowed("lower_filters"), BridgeValue::Text(Text::Owned(dev.lower_filters.clone())));
        map.insert(Text::Borrowed("device_interface_classes"), BridgeValue::Text(Text::Owned(dev.device_interface_classes.clone())));
        map.insert(Text::Borrowed("device_driver_flight_id"), BridgeValue::Text(Text::Owned(dev.device_driver_flight_id.clone())));
        map.insert(Text::Borrowed("device_ext_drivers_flight_ids"), BridgeValue::Text(Text::Owned(dev.device_ext_drivers_flight_ids.clone())));
        map.insert(Text::Borrowed("install_date"), BridgeValue::Text(Text::Owned(dev.install_date.clone())));
        map.insert(Text::Borrowed("first_install_date"), BridgeValue::Text(Text::Owned(dev.first_install_date.clone())));
        map.insert(Text::Borrowed("is_machine_container"), BridgeValue::Text(Text::Owned(dev.is_machine_container.clone())));
        map.insert(Text::Borrowed("timestamp"), timestamp_to_bridge_value(dev.timestamp));
        BridgeValue::Map(map)
    }
}

pub struct InventoryDevicePnpIter {
    pub(crate) key: OwnedRegKey,
    pub(crate) entries: std::vec::IntoIter<KeyEntry>,
}

impl InventoryDevicePnpIter {
    fn build(&self, name: &str) -> ForensicResult<InventoryDevicePnp> {
        let key = self.key.open_child(name)?;
        let model = read_value_string_or_empty(&key, "Model");
        let manufacturer = read_value_string_or_empty(&key, "Manufacturer");
        let driver_name = read_value_string_or_empty(&key, "DriverName");
        let parent_id = read_value_string_or_empty(&key, "ParentId");
        let matching_id = read_value_string_or_empty(&key, "MatchingID");
        let class = read_value_string_or_empty(&key, "Class");
        let class_guid = read_value_string_or_empty(&key, "ClassGuid");
        let description = read_value_string_or_empty(&key, "Description");
        let enumerator = read_value_string_or_empty(&key, "Enumerator");
        let service = read_value_string_or_empty(&key, "Service");
        let install_state = read_value_string_or_empty(&key, "InstallState");
        let device_state = read_value_string_or_empty(&key, "DeviceState");
        let inf = read_value_string_or_empty(&key, "Inf");
        let driver_ver_date = read_value_string_or_empty(&key, "DriverVerDate");
        let driver_ver_version = read_value_string_or_empty(&key, "DriverVerVersion");
        let driver_package_strong_name = read_value_string_or_empty(&key, "DriverPackageStrongName");
        let container_id = read_value_string_or_empty(&key, "ContainerId");
        let problem_code = read_value_string_or_empty(&key, "ProblemCode");
        let provider = read_value_string_or_empty(&key, "Provider");
        let driver_id = read_value_string_or_empty(&key, "DriverId");
        let bus_reported_description = read_value_string_or_empty(&key, "BusReportedDescription");
        let hwid = read_value_string_or_empty(&key, "HWID");
        let extended_infs = read_value_string_or_empty(&key, "ExtendedInfs");
        let comp_id = read_value_string_or_empty(&key, "COMPID");
        let stack_id = read_value_string_or_empty(&key, "STACKID");
        let upper_class_filters = read_value_string_or_empty(&key, "UpperClassFilters");
        let lower_class_filters = read_value_string_or_empty(&key, "LowerClassFilters");
        let upper_filters = read_value_string_or_empty(&key, "UpperFilters");
        let lower_filters = read_value_string_or_empty(&key, "LowerFilters");
        let device_interface_classes = read_value_string_or_empty(&key, "DeviceInterfaceClasses");
        let device_driver_flight_id = read_value_string_or_empty(&key, "DeviceDriverFlightId");
        let device_ext_drivers_flight_ids = read_value_string_or_empty(&key, "DeviceExtDriversFlightIds");
        let install_date = read_value_string_or_empty(&key, "InstallDate");
        let first_install_date = read_value_string_or_empty(&key, "FirstInstallDate");
        let is_machine_container = read_value_string_or_empty(&key, "IsMachineContainer");

        let key_info = key.info()?;
        Ok(InventoryDevicePnp {
            model,
            manufacturer,
            driver_name,
            parent_id,
            matching_id,
            class,
            class_guid,
            description,
            enumerator,
            service,
            install_state,
            device_state,
            inf,
            driver_ver_date,
            driver_ver_version,
            driver_package_strong_name,
            container_id,
            problem_code,
            provider,
            driver_id,
            bus_reported_description,
            hwid,
            extended_infs,
            comp_id,
            stack_id,
            upper_class_filters,
            lower_class_filters,
            upper_filters,
            lower_filters,
            device_interface_classes,
            device_driver_flight_id,
            device_ext_drivers_flight_ids,
            install_date,
            first_install_date,
            is_machine_container,
            timestamp: key_info.last_write_time,
        })
    }
}

impl Iterator for InventoryDevicePnpIter {
    type Item = InventoryDevicePnp;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.next()?;
            match self.build(&entry.name) {
                Ok(v) => return Some(v),
                Err(e) => {
                    info!("Error parsing AmCache InventoryDevicePnp entry {}: {}", entry.name, e);
                    continue;
                }
            }
        }
    }
}
