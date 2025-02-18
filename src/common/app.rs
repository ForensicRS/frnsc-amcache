use forensic_rs::{
    info,
    traits::registry::{auto_close_key, RegHiveKey, RegistryReader},
    utils::time::Filetime,
};

use super::{read_value_string_or_empty, read_value_u32_or_empty};

/// This event sends basic metadata about an application on the system.
/// 
/// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/privacy/basic-level-windows-diagnostic-events-and-fields-1903#microsoftwindowsinventorycoreinventoryapplicationadd
#[derive(Clone, Debug, Default)]
pub struct InventoryApplication {
    /// ProgramId
    pub program_id: String,
    /// ProgramInstanceId
    pub program_instance_id: String,
    /// Name
    pub name: String,
    /// Version
    pub version: String,
    /// Publisher
    pub publisher: String,
    /// Language
    pub language: u32,
    /// Source
    pub source: String,
    /// Type
    pub r#type: String,
    /// StoreAppType
    pub store_app_type: String,
    /// MsiPackageCode
    pub msi_package_code: String,
    /// MsiProductCode
    pub msi_product_code: String,
    /// HiddenArp
    pub hidden_arp: u32,
    /// InboxModernApp
    pub inbox_modern_app: u32,
    /// OSVersionAtInstallTime
    pub os_version_at_install_time: String,
    /// InstallDate
    pub install_date: String,
    /// PackageFullName
    pub package_full_name: String,
    /// ManifestPath
    pub manifest_path: String,
    /// BundleManifestPath
    pub bundle_manifest_path: String,
    /// RootDirPath
    pub root_dir_path: String,
    /// UninstallString
    pub uninstall_string: String,
    /// RegistryKeyPath
    pub registry_key_path: String,
    /// Last write timestamp
    pub timestamp: Filetime,
}

pub struct InventoryApplicationIter<'a, R: RegistryReader> {
    pub(crate) pos: u32,
    pub(crate) key: RegHiveKey,
    pub(crate) reader: &'a R,
}

impl<'a, R: RegistryReader> Iterator for InventoryApplicationIter<'a, R> {
    type Item = InventoryApplication;

    fn next(&mut self) -> Option<Self::Item> {
        if self.key == RegHiveKey::Hkey(0) {
            return None;
        }
        let pos = self.pos;
        self.pos += 1;
        let next_subkey = self.reader.key_at(self.key, pos).ok()?;
        let key = self.reader.open_key(self.key, &next_subkey).ok()?;
        match auto_close_key(self.reader, key, || {
            let program_id: String = read_value_string_or_empty(self.reader, key, "ProgramId");
            let program_instance_id: String =
                read_value_string_or_empty(self.reader, key, "ProgramInstanceId");

            let name: String = read_value_string_or_empty(self.reader, key, "Name");
            let version: String = read_value_string_or_empty(self.reader, key, "Version");
            let publisher: String = read_value_string_or_empty(self.reader, key, "Publisher");
            let language: u32 = read_value_u32_or_empty(self.reader, key, "Language");
            let source: String = read_value_string_or_empty(self.reader, key, "Source");
            let r#type: String = read_value_string_or_empty(self.reader, key, "Type");
            let store_app_type: String =
                read_value_string_or_empty(self.reader, key, "StoreAppType");

            let msi_package_code: String =
                read_value_string_or_empty(self.reader, key, "MsiPackageCode");
            let msi_product_code: String =
                read_value_string_or_empty(self.reader, key, "MsiProductCode");
            let hidden_arp = read_value_u32_or_empty(self.reader, key, "HiddenArp");
            let inbox_modern_app = read_value_u32_or_empty(self.reader, key, "InboxModernApp");
            let os_version_at_install_time: String =
                read_value_string_or_empty(self.reader, key, "OSVersionAtInstallTime");
            let install_date: String = read_value_string_or_empty(self.reader, key, "InstallDate");
            let package_full_name: String =
                read_value_string_or_empty(self.reader, key, "PackageFullName");
            let manifest_path: String =
                read_value_string_or_empty(self.reader, key, "ManifestPath");
            let bundle_manifest_path =
                read_value_string_or_empty(self.reader, key, "BundleManifestPath");
            let root_dir_path = read_value_string_or_empty(self.reader, key, "RootDirPath");
            let uninstall_string = read_value_string_or_empty(self.reader, key, "UninstallString");
            let registry_key_path = read_value_string_or_empty(self.reader, key, "RegistryKeyPath");

            let key_info = self.reader.key_info(key)?;
            Ok(InventoryApplication {
                program_id,
                program_instance_id,
                name,
                version,
                publisher,
                language,
                source,
                r#type,
                store_app_type,
                msi_package_code,
                msi_product_code,
                hidden_arp,
                inbox_modern_app,
                os_version_at_install_time,
                install_date,
                package_full_name,
                manifest_path,
                bundle_manifest_path,
                root_dir_path,
                uninstall_string,
                registry_key_path,

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

impl<'a, R: RegistryReader> Drop for InventoryApplicationIter<'a, R> {
    fn drop(&mut self) {
        self.reader.close_key(self.key);
        self.key = RegHiveKey::Hkey(0);
    }
}
