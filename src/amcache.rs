use forensic_rs::{err::ForensicResult, traits::registry::{RegHiveKey, RegistryReader}};

use crate::common::{app::InventoryApplicationIter, app_file::InventoryApplicationFileIter, app_shortcut::InventoryApplicationShortcutIter, dev_container::InventoryDeviceContainerIter, drv_binary::InventoryDriverBinaryIter, drv_package::InventoryDriverPackageIter};

#[path ="./tst.rs"]
#[cfg(test)]
mod tst;

pub struct AmCache<R : RegistryReader> {
    reader : R
}

impl<R : RegistryReader> AmCache<R> {
    /// A count of application shortcut objects in cache. Subkey: InventoryApplicationShortcut
    pub fn application_shortcuts<'a>(&'a self) -> ForensicResult<InventoryApplicationShortcutIter<'a, R>> {
        let am_key = self.reader.open_key(RegHiveKey::Hkey(0), r"Amcache")?;
        let key = self.reader.open_key(am_key, r"Root\InventoryApplicationShortcut")?;
        self.reader.close_key(am_key);
        Ok(InventoryApplicationShortcutIter { pos : 0, reader : &self.reader, key})
    }
    /// A count of application file objects in cache. Subkey: InventoryApplicationFile
    pub fn application_files<'a>(&'a self) -> ForensicResult<InventoryApplicationFileIter<'a, R>> {
        let am_key = self.reader.open_key(RegHiveKey::Hkey(0), r"Amcache")?;
        let key = self.reader.open_key(am_key, r"Root\InventoryApplicationFile")?;
        self.reader.close_key(am_key);
        Ok(InventoryApplicationFileIter { pos : 0, reader : &self.reader, key})
    }
    /// A count of device container objects in cache. Subkey: InventoryDeviceContainer
    pub fn device_containers<'a>(&'a self) -> ForensicResult<InventoryDeviceContainerIter<'a, R>> {
        let am_key = self.reader.open_key(RegHiveKey::Hkey(0), r"Amcache")?;
        let key = self.reader.open_key(am_key, r"Root\InventoryDeviceContainer")?;
        self.reader.close_key(am_key);
        Ok(InventoryDeviceContainerIter { pos : 0, reader : &self.reader, key})
    }
    /// A count of driver binary objects in cache. Subkey: InventoryDriverBinary
    pub fn driver_binaries<'a>(&'a self) -> ForensicResult<InventoryDriverBinaryIter<'a, R>> {
        let am_key = self.reader.open_key(RegHiveKey::Hkey(0), r"Amcache")?;
        let key = self.reader.open_key(am_key, r"Root\InventoryDriverBinary")?;
        self.reader.close_key(am_key);
        Ok(InventoryDriverBinaryIter { pos : 0, reader : &self.reader, key})
    }
    /// A count of device objects in cache. Subkey: InventoryDriverPackage
    pub fn driver_package<'a>(&'a self) -> ForensicResult<InventoryDriverPackageIter<'a, R>> {
        let am_key = self.reader.open_key(RegHiveKey::Hkey(0), r"Amcache")?;
        let key = self.reader.open_key(am_key, r"Root\InventoryDriverPackage")?;
        self.reader.close_key(am_key);
        Ok(InventoryDriverPackageIter { pos : 0, reader : &self.reader, key})
    }
    /// A count of application objects in cache. Subkey: InventoryApplication
    pub fn applications<'a>(&'a self) -> ForensicResult<InventoryApplicationIter<'a, R>> {
        let am_key = self.reader.open_key(RegHiveKey::Hkey(0), r"Amcache")?;
        let key = self.reader.open_key(am_key, r"Root\InventoryApplication")?;
        self.reader.close_key(am_key);
        Ok(InventoryApplicationIter { pos : 0, reader : &self.reader, key})
    }
}