use forensic_rs::{info, traits::registry::{auto_close_key, RegHiveKey, RegistryReader}, utils::time::Filetime};

use super::read_value_string_or_empty;

#[derive(Clone, Debug, Default)]
pub struct InventoryApplicationShortcut {
    pub path : String,
    pub target_path : String,
    pub aum_id : String,
    pub program_id : String,
    pub timestamp : Filetime
}

pub struct InventoryApplicationShortcutIter<'a, R : RegistryReader> {
    pub(crate) pos : u32,
    pub(crate) key : RegHiveKey,
    pub(crate) reader : &'a R
}

impl<'a, R: RegistryReader> Iterator for InventoryApplicationShortcutIter<'a, R> {
    type Item = InventoryApplicationShortcut;

    fn next(&mut self) -> Option<Self::Item> {
        if self.key == RegHiveKey::Hkey(0) {
            return None
        }
        let pos = self.pos;
        self.pos += 1;
        let next_subkey = self.reader.key_at(self.key, pos).ok()?;
        let key = self.reader.open_key(self.key, &next_subkey).ok()?;
        match auto_close_key(self.reader, key, || {
            let path : String = read_value_string_or_empty(self.reader, key, "ShortcutPath");
            let target_path : String = read_value_string_or_empty(self.reader, key, "ShortcutTargetPath");
            let aum_id: String = read_value_string_or_empty(self.reader, key, "ShortcutAumid");
            let program_id : String = read_value_string_or_empty(self.reader, key, "ShortcutProgramId");
            let key_info = self.reader.key_info(key)?;
            Ok(InventoryApplicationShortcut {
                path,
                target_path,
                aum_id,
                program_id,
                timestamp : key_info.last_write_time
            })
        }) {
            Ok(v) => Some(v),
            Err(e) => {
                info!("Error getting AmCache shortcut {}", e);
                None
            }
        }
    }
}

impl<'a, R: RegistryReader> Drop for InventoryApplicationShortcutIter<'a, R> {
    fn drop(&mut self) {
        self.reader.close_key(self.key);
        self.key = RegHiveKey::Hkey(0);
    }
}