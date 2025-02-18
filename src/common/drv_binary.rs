use forensic_rs::{info, traits::registry::{auto_close_key, RegHiveKey, RegistryReader}, utils::time::Filetime};

use super::{read_value_string_or_empty, read_value_u32_or_empty};

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
    pub timestamp : Filetime,
}
pub struct InventoryDriverBinaryIter<'a, R : RegistryReader> {
    pub(crate) pos : u32,
    pub(crate) key : RegHiveKey,
    pub(crate) reader : &'a R
}

impl<'a, R: RegistryReader> Iterator for InventoryDriverBinaryIter<'a, R> {
    type Item = InventoryDriverBinary;

    fn next(&mut self) -> Option<Self::Item> {
        if self.key == RegHiveKey::Hkey(0) {
            return None
        }
        let pos = self.pos;
        self.pos += 1;
        let next_subkey = self.reader.key_at(self.key, pos).ok()?;
        let key = self.reader.open_key(self.key, &next_subkey).ok()?;
        match auto_close_key(self.reader, key, || {
            let driver_name : String = read_value_string_or_empty(self.reader, key, "DriverName");
            let inf: String = read_value_string_or_empty(self.reader, key, "Inf");
            let driver_version : String = read_value_string_or_empty(self.reader, key, "DriverVersion");
            let product : String = read_value_string_or_empty(self.reader, key, "Product");
            let product_version : String = read_value_string_or_empty(self.reader, key, "ProductVersion");
            let wdf_version : String = read_value_string_or_empty(self.reader, key, "WdfVersion");
            let driver_company : String = read_value_string_or_empty(self.reader, key, "DriverCompany");
            let driver_package_strong_name = read_value_string_or_empty(self.reader, key, "DriverPackageStrongName");
            let service = read_value_string_or_empty(self.reader, key, "Service");
            let driver_in_box : u32 = read_value_u32_or_empty(self.reader, key, "DriverInBox");
            let driver_signed : u32 = read_value_u32_or_empty(self.reader, key, "DriverSigned");
            let driver_is_kernel_mode : u32 = read_value_u32_or_empty(self.reader, key, "DriverIsKernelMode");

            let driver_id = read_value_string_or_empty(self.reader, key, "DriverId");
            let driver_last_write_time = read_value_string_or_empty(self.reader, key, "DriverLastWriteTime");
            let driver_type : u32 = read_value_u32_or_empty(self.reader, key, "DriverType");
            let driver_timestamp : u32 = read_value_u32_or_empty(self.reader, key, "DriverTimeStamp");
            let driver_check_sum : u32 = read_value_u32_or_empty(self.reader, key, "DriverCheckSum");
            let image_size : u32 = read_value_u32_or_empty(self.reader, key, "ImageSize");

            let key_info = self.reader.key_info(key)?;
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
        }) {
            Ok(v) => Some(v),
            Err(e) => {
                info!("Error getting AmCache File {}", e);
                None
            }
        }
    }
}

impl<'a, R: RegistryReader> Drop for InventoryDriverBinaryIter<'a, R> {
    fn drop(&mut self) {
        self.reader.close_key(self.key);
        self.key = RegHiveKey::Hkey(0);
    }
}
