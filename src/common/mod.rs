use forensic_rs::prelude::*;

pub mod app_shortcut;
pub mod app_file;
pub mod app;
pub mod dev_container;
pub mod dev_interface;
pub mod dev_pnp;
pub mod dev_usb_hub;
pub mod drv_binary;
pub mod drv_package;

pub(crate) fn empty_string<E>(_ : E) -> RegValue {
    RegValue::SZ(String::default())
}

pub(crate) fn empty_u32<E>(_ : E) -> RegValue {
    RegValue::DWord(0)
}
pub(crate) fn empty_u64<E>(_ : E) -> RegValue {
    RegValue::QWord(0)
}

pub(crate) fn read_value_string_or_empty(key : &OwnedRegKey, name : &str) -> String {
    key.value(name).unwrap_or_else(empty_string).try_into().unwrap_or_default()
}

pub(crate) fn read_value_u32_or_empty(key : &OwnedRegKey, name : &str) -> u32 {
    key.value(name).unwrap_or_else(empty_u32).try_into().unwrap_or_default()
}

pub(crate) fn read_value_u64_or_empty(key : &OwnedRegKey, name : &str) -> u64 {
    key.value(name).unwrap_or_else(empty_u64).try_into().unwrap_or_default()
}

/// Maps a record's last-write timestamp to a `BridgeValue`, used by every
/// `From<&T> for BridgeValue` impl in this module's submodules.
pub(crate) fn timestamp_to_bridge_value(ts: Option<ForensicTimestamp>) -> BridgeValue {
    ts.map(BridgeValue::Timestamp).unwrap_or(BridgeValue::Null)
}