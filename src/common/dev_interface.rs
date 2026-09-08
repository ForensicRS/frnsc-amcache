use std::collections::BTreeMap;

use forensic_rs::prelude::*;

use super::{read_value_string_or_empty, timestamp_to_bridge_value};

/// This event sends availability data on a device's sensor interfaces (accelerometer,
/// barometer, gyrometer, and similar), one flag per sensor type. In the reference fixture
/// there is exactly one entry per hive, keyed `DeviceInterfaces`, but this iterates whatever
/// subkeys are present rather than assuming that name — same as every other inventory in this
/// crate. Every flag is a `REG_SZ` `"0"`/`"1"` in the observed data, not a `REG_DWORD`, so each
/// is modeled as `String` rather than a numeric type.
///
/// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/privacy/basic-level-windows-diagnostic-events-and-fields-1803#microsoftwindowsinventorycoreinventorydeviceinterfaceadd
#[derive(Clone, Debug, Default)]
pub struct InventoryDeviceInterface {
    /// Accelerometer3D
    pub accelerometer_3d: String,
    /// ActivityDetection
    pub activity_detection: String,
    /// AmbientLight
    pub ambient_light: String,
    /// Barometer
    pub barometer: String,
    /// Custom
    pub custom: String,
    /// FloorElevation
    pub floor_elevation: String,
    /// GeomagneticOrientation
    pub geomagnetic_orientation: String,
    /// GravityVector
    pub gravity_vector: String,
    /// Gyrometer3D
    pub gyrometer_3d: String,
    /// Humidity
    pub humidity: String,
    /// LinearAccelerometer
    pub linear_accelerometer: String,
    /// Magnetometer3D
    pub magnetometer_3d: String,
    /// Orientation
    pub orientation: String,
    /// Pedometer
    pub pedometer: String,
    /// Proximity
    pub proximity: String,
    /// RelativeOrientation
    pub relative_orientation: String,
    /// SimpleDeviceOrientation
    pub simple_device_orientation: String,
    /// Temperature
    pub temperature: String,
    /// EnergyMeter
    pub energy_meter: String,
    /// Last write timestamp
    pub timestamp: Option<ForensicTimestamp>,
}

impl From<&InventoryDeviceInterface> for BridgeValue {
    fn from(dev: &InventoryDeviceInterface) -> Self {
        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("accelerometer_3d"), BridgeValue::Text(Text::Owned(dev.accelerometer_3d.clone())));
        map.insert(Text::Borrowed("activity_detection"), BridgeValue::Text(Text::Owned(dev.activity_detection.clone())));
        map.insert(Text::Borrowed("ambient_light"), BridgeValue::Text(Text::Owned(dev.ambient_light.clone())));
        map.insert(Text::Borrowed("barometer"), BridgeValue::Text(Text::Owned(dev.barometer.clone())));
        map.insert(Text::Borrowed("custom"), BridgeValue::Text(Text::Owned(dev.custom.clone())));
        map.insert(Text::Borrowed("floor_elevation"), BridgeValue::Text(Text::Owned(dev.floor_elevation.clone())));
        map.insert(Text::Borrowed("geomagnetic_orientation"), BridgeValue::Text(Text::Owned(dev.geomagnetic_orientation.clone())));
        map.insert(Text::Borrowed("gravity_vector"), BridgeValue::Text(Text::Owned(dev.gravity_vector.clone())));
        map.insert(Text::Borrowed("gyrometer_3d"), BridgeValue::Text(Text::Owned(dev.gyrometer_3d.clone())));
        map.insert(Text::Borrowed("humidity"), BridgeValue::Text(Text::Owned(dev.humidity.clone())));
        map.insert(Text::Borrowed("linear_accelerometer"), BridgeValue::Text(Text::Owned(dev.linear_accelerometer.clone())));
        map.insert(Text::Borrowed("magnetometer_3d"), BridgeValue::Text(Text::Owned(dev.magnetometer_3d.clone())));
        map.insert(Text::Borrowed("orientation"), BridgeValue::Text(Text::Owned(dev.orientation.clone())));
        map.insert(Text::Borrowed("pedometer"), BridgeValue::Text(Text::Owned(dev.pedometer.clone())));
        map.insert(Text::Borrowed("proximity"), BridgeValue::Text(Text::Owned(dev.proximity.clone())));
        map.insert(Text::Borrowed("relative_orientation"), BridgeValue::Text(Text::Owned(dev.relative_orientation.clone())));
        map.insert(Text::Borrowed("simple_device_orientation"), BridgeValue::Text(Text::Owned(dev.simple_device_orientation.clone())));
        map.insert(Text::Borrowed("temperature"), BridgeValue::Text(Text::Owned(dev.temperature.clone())));
        map.insert(Text::Borrowed("energy_meter"), BridgeValue::Text(Text::Owned(dev.energy_meter.clone())));
        map.insert(Text::Borrowed("timestamp"), timestamp_to_bridge_value(dev.timestamp));
        BridgeValue::Map(map)
    }
}

pub struct InventoryDeviceInterfaceIter {
    pub(crate) key: OwnedRegKey,
    pub(crate) entries: std::vec::IntoIter<KeyEntry>,
}

impl InventoryDeviceInterfaceIter {
    fn build(&self, name: &str) -> ForensicResult<InventoryDeviceInterface> {
        let key = self.key.open_child(name)?;
        let accelerometer_3d = read_value_string_or_empty(&key, "Accelerometer3D");
        let activity_detection = read_value_string_or_empty(&key, "ActivityDetection");
        let ambient_light = read_value_string_or_empty(&key, "AmbientLight");
        let barometer = read_value_string_or_empty(&key, "Barometer");
        let custom = read_value_string_or_empty(&key, "Custom");
        let floor_elevation = read_value_string_or_empty(&key, "FloorElevation");
        let geomagnetic_orientation = read_value_string_or_empty(&key, "GeomagneticOrientation");
        let gravity_vector = read_value_string_or_empty(&key, "GravityVector");
        let gyrometer_3d = read_value_string_or_empty(&key, "Gyrometer3D");
        let humidity = read_value_string_or_empty(&key, "Humidity");
        let linear_accelerometer = read_value_string_or_empty(&key, "LinearAccelerometer");
        let magnetometer_3d = read_value_string_or_empty(&key, "Magnetometer3D");
        let orientation = read_value_string_or_empty(&key, "Orientation");
        let pedometer = read_value_string_or_empty(&key, "Pedometer");
        let proximity = read_value_string_or_empty(&key, "Proximity");
        let relative_orientation = read_value_string_or_empty(&key, "RelativeOrientation");
        let simple_device_orientation = read_value_string_or_empty(&key, "SimpleDeviceOrientation");
        let temperature = read_value_string_or_empty(&key, "Temperature");
        let energy_meter = read_value_string_or_empty(&key, "EnergyMeter");

        let key_info = key.info()?;
        Ok(InventoryDeviceInterface {
            accelerometer_3d,
            activity_detection,
            ambient_light,
            barometer,
            custom,
            floor_elevation,
            geomagnetic_orientation,
            gravity_vector,
            gyrometer_3d,
            humidity,
            linear_accelerometer,
            magnetometer_3d,
            orientation,
            pedometer,
            proximity,
            relative_orientation,
            simple_device_orientation,
            temperature,
            energy_meter,
            timestamp: key_info.last_write_time,
        })
    }
}

impl Iterator for InventoryDeviceInterfaceIter {
    type Item = InventoryDeviceInterface;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.next()?;
            match self.build(&entry.name) {
                Ok(v) => return Some(v),
                Err(e) => {
                    info!("Error parsing AmCache InventoryDeviceInterface entry {}: {}", entry.name, e);
                    continue;
                }
            }
        }
    }
}
