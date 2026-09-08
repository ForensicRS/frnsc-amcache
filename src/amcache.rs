use std::sync::Arc;

use forensic_rs::prelude::*;

use crate::common::{app::InventoryApplicationIter, app_file::InventoryApplicationFileIter, app_shortcut::InventoryApplicationShortcutIter, dev_container::InventoryDeviceContainerIter, dev_interface::InventoryDeviceInterfaceIter, dev_pnp::InventoryDevicePnpIter, dev_usb_hub::InventoryDeviceUsbHubClassIter, drv_binary::InventoryDriverBinaryIter, drv_package::InventoryDriverPackageIter};

#[path ="./tst.rs"]
#[cfg(test)]
mod tst;

/// Backend-agnostic reader over an already-resolved AmCache hive root key.
/// Owns an `Arc<dyn Registry>` (cheaply cloneable, `Send + Sync`, matching
/// `TriageSources`/`RegistryProvider`'s ownership pattern) rather than
/// borrowing the backend by lifetime, so `AmCacheReader` is `'static` and can
/// be stored as a plain field or moved across threads without leaking.
pub struct AmCacheReader {
    registry: Arc<dyn Registry>,
    root: RawKey,
}

impl AmCacheReader {
    /// `root` must already be resolved to the AmCache hive's root key against
    /// `registry` (e.g. via a backend-specific method like
    /// `HiveRegistryReader::other_hive_root` — the generic `Registry` trait
    /// has no way to reach a named "other" hive itself).
    pub fn new(registry: Arc<dyn Registry>, root: RawKey) -> Self {
        Self { registry, root }
    }

    /// Opens `subkey` relative to the AmCache hive's root as an owned,
    /// `Arc`-backed key rather than one borrowed from `&self` — so the
    /// returned `InventoryXIter` doesn't tie its lifetime to this reader and
    /// can outlive it (e.g. returned from a factory's `open()` after the
    /// local `AmCacheReader` used to build it goes out of scope).
    fn open(&self, subkey: &str) -> ForensicResult<OwnedRegKey> {
        let raw = self.registry.open_raw(&self.root, subkey)?;
        Ok(OwnedRegKey::new(Arc::clone(&self.registry), raw))
    }

    /// A count of application shortcut objects in cache. Subkey: InventoryApplicationShortcut
    pub fn application_shortcuts(&self) -> ForensicResult<InventoryApplicationShortcutIter> {
        let key = self.open(r"Root\InventoryApplicationShortcut")?;
        let entries = key.keys()?.into_iter();
        Ok(InventoryApplicationShortcutIter { key, entries })
    }
    /// A count of application file objects in cache. Subkey: InventoryApplicationFile
    pub fn application_files(&self) -> ForensicResult<InventoryApplicationFileIter> {
        let key = self.open(r"Root\InventoryApplicationFile")?;
        let entries = key.keys()?.into_iter();
        Ok(InventoryApplicationFileIter { key, entries })
    }
    /// A count of device container objects in cache. Subkey: InventoryDeviceContainer
    pub fn device_containers(&self) -> ForensicResult<InventoryDeviceContainerIter> {
        let key = self.open(r"Root\InventoryDeviceContainer")?;
        let entries = key.keys()?.into_iter();
        Ok(InventoryDeviceContainerIter { key, entries })
    }
    /// A count of driver binary objects in cache. Subkey: InventoryDriverBinary
    pub fn driver_binaries(&self) -> ForensicResult<InventoryDriverBinaryIter> {
        let key = self.open(r"Root\InventoryDriverBinary")?;
        let entries = key.keys()?.into_iter();
        Ok(InventoryDriverBinaryIter { key, entries })
    }
    /// A count of device objects in cache. Subkey: InventoryDriverPackage
    pub fn driver_package(&self) -> ForensicResult<InventoryDriverPackageIter> {
        let key = self.open(r"Root\InventoryDriverPackage")?;
        let entries = key.keys()?.into_iter();
        Ok(InventoryDriverPackageIter { key, entries })
    }
    /// A count of application objects in cache. Subkey: InventoryApplication
    pub fn applications(&self) -> ForensicResult<InventoryApplicationIter> {
        let key = self.open(r"Root\InventoryApplication")?;
        let entries = key.keys()?.into_iter();
        Ok(InventoryApplicationIter { key, entries })
    }
    /// A count of Plug and Play device objects in cache. Subkey: InventoryDevicePnp
    pub fn device_pnps(&self) -> ForensicResult<InventoryDevicePnpIter> {
        let key = self.open(r"Root\InventoryDevicePnp")?;
        let entries = key.keys()?.into_iter();
        Ok(InventoryDevicePnpIter { key, entries })
    }
    /// A count of device sensor-interface objects in cache. Subkey: InventoryDeviceInterface
    pub fn device_interfaces(&self) -> ForensicResult<InventoryDeviceInterfaceIter> {
        let key = self.open(r"Root\InventoryDeviceInterface")?;
        let entries = key.keys()?.into_iter();
        Ok(InventoryDeviceInterfaceIter { key, entries })
    }
    /// A count of USB hub class objects in cache. Subkey: InventoryDeviceUsbHubClass
    pub fn device_usb_hub_classes(&self) -> ForensicResult<InventoryDeviceUsbHubClassIter> {
        let key = self.open(r"Root\InventoryDeviceUsbHubClass")?;
        let entries = key.keys()?.into_iter();
        Ok(InventoryDeviceUsbHubClassIter { key, entries })
    }

    /// Number of subkeys under `subkey`, without parsing any of their values —
    /// cheap even when the corresponding iterator would need to open and read
    /// every entry to answer the same question.
    fn count(&self, subkey: &str) -> ForensicResult<u64> {
        Ok(self.open(subkey)?.keys()?.len() as u64)
    }

    /// Cheap count of application shortcut objects in cache, without parsing
    /// each entry's values. Subkey: InventoryApplicationShortcut
    pub fn application_shortcuts_count(&self) -> ForensicResult<u64> {
        self.count(r"Root\InventoryApplicationShortcut")
    }
    /// Cheap count of application file objects in cache, without parsing each
    /// entry's values. Subkey: InventoryApplicationFile
    pub fn application_files_count(&self) -> ForensicResult<u64> {
        self.count(r"Root\InventoryApplicationFile")
    }
    /// Cheap count of device container objects in cache, without parsing each
    /// entry's values. Subkey: InventoryDeviceContainer
    pub fn device_containers_count(&self) -> ForensicResult<u64> {
        self.count(r"Root\InventoryDeviceContainer")
    }
    /// Cheap count of driver binary objects in cache, without parsing each
    /// entry's values. Subkey: InventoryDriverBinary
    pub fn driver_binaries_count(&self) -> ForensicResult<u64> {
        self.count(r"Root\InventoryDriverBinary")
    }
    /// Cheap count of driver package objects in cache, without parsing each
    /// entry's values. Subkey: InventoryDriverPackage
    pub fn driver_package_count(&self) -> ForensicResult<u64> {
        self.count(r"Root\InventoryDriverPackage")
    }
    /// Cheap count of application objects in cache, without parsing each
    /// entry's values. Subkey: InventoryApplication
    pub fn applications_count(&self) -> ForensicResult<u64> {
        self.count(r"Root\InventoryApplication")
    }
    /// Cheap count of Plug and Play device objects in cache, without parsing
    /// each entry's values. Subkey: InventoryDevicePnp
    pub fn device_pnps_count(&self) -> ForensicResult<u64> {
        self.count(r"Root\InventoryDevicePnp")
    }
    /// Cheap count of device sensor-interface objects in cache, without
    /// parsing each entry's values. Subkey: InventoryDeviceInterface
    pub fn device_interfaces_count(&self) -> ForensicResult<u64> {
        self.count(r"Root\InventoryDeviceInterface")
    }
    /// Cheap count of USB hub class objects in cache, without parsing each
    /// entry's values. Subkey: InventoryDeviceUsbHubClass
    pub fn device_usb_hub_classes_count(&self) -> ForensicResult<u64> {
        self.count(r"Root\InventoryDeviceUsbHubClass")
    }
}