use std::collections::BTreeMap;

use forensic_rs::prelude::*;

use super::{read_value_string_or_empty, timestamp_to_bridge_value};

#[derive(Clone, Debug, Default)]
pub struct InventoryApplicationShortcut {
    pub path : String,
    pub target_path : String,
    pub aum_id : String,
    pub program_id : String,
    pub timestamp : Option<ForensicTimestamp>
}

impl From<&InventoryApplicationShortcut> for BridgeValue {
    fn from(shortcut: &InventoryApplicationShortcut) -> Self {
        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("path"), BridgeValue::Text(Text::Owned(shortcut.path.clone())));
        map.insert(Text::Borrowed("target_path"), BridgeValue::Text(Text::Owned(shortcut.target_path.clone())));
        map.insert(Text::Borrowed("aum_id"), BridgeValue::Text(Text::Owned(shortcut.aum_id.clone())));
        map.insert(Text::Borrowed("program_id"), BridgeValue::Text(Text::Owned(shortcut.program_id.clone())));
        map.insert(Text::Borrowed("timestamp"), timestamp_to_bridge_value(shortcut.timestamp));
        BridgeValue::Map(map)
    }
}

pub struct InventoryApplicationShortcutIter {
    pub(crate) key : OwnedRegKey,
    pub(crate) entries : std::vec::IntoIter<KeyEntry>,
}

impl InventoryApplicationShortcutIter {
    fn build(&self, name: &str) -> ForensicResult<InventoryApplicationShortcut> {
        let key = self.key.open_child(name)?;
        let path : String = read_value_string_or_empty(&key, "ShortcutPath");
        let target_path : String = read_value_string_or_empty(&key, "ShortcutTargetPath");
        let aum_id: String = read_value_string_or_empty(&key, "ShortcutAumid");
        let program_id : String = read_value_string_or_empty(&key, "ShortcutProgramId");
        let key_info = key.info()?;
        Ok(InventoryApplicationShortcut {
            path,
            target_path,
            aum_id,
            program_id,
            timestamp : key_info.last_write_time
        })
    }
}

impl Iterator for InventoryApplicationShortcutIter {
    type Item = InventoryApplicationShortcut;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.next()?;
            match self.build(&entry.name) {
                Ok(v) => return Some(v),
                Err(e) => {
                    info!("Error parsing AmCache InventoryApplicationShortcut entry {}: {}", entry.name, e);
                    continue;
                }
            }
        }
    }
}
