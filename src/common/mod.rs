use forensic_rs::prelude::{RegHiveKey, RegValue, RegistryReader};

pub mod app_shortcut;
pub mod app_file;
pub mod app;
pub mod dev_container;
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

pub(crate) fn read_value_string_or_empty(reader : &dyn RegistryReader, key : RegHiveKey, name : &str) -> String {
    reader.read_value(key, name).unwrap_or_else(empty_string).try_into().unwrap_or_default()
}

pub(crate) fn read_value_u32_or_empty(reader : &dyn RegistryReader, key : RegHiveKey, name : &str) -> u32 {
    reader.read_value(key, name).unwrap_or_else(empty_u32).try_into().unwrap_or_default()
}

pub(crate) fn read_value_u64_or_empty(reader : &dyn RegistryReader, key : RegHiveKey, name : &str) -> u64 {
    reader.read_value(key, name).unwrap_or_else(empty_u64).try_into().unwrap_or_default()
}