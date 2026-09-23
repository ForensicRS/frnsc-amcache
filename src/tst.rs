use std::sync::Arc;

use forensic_rs::prelude::*;
use frnsc_hive::reader::{open_hive_with_logs, HiveRegistryReader};

use super::AmCacheReader;

fn load_reader() -> HiveRegistryReader {
    let fs: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new("./artifacts/C", Arc::new(StdVirtualFS::new())));
    let mut reader = HiveRegistryReader::new();
    let mut findings = Vec::new();
    let hive_file = open_hive_with_logs(&fs, FPath::new(r"C:\Windows\AppCompat\Programs"), "Amcache.hve", &mut findings).unwrap();
    reader.add_other("Amcache", hive_file);
    reader
}

fn obtain_am_cache(reader: HiveRegistryReader) -> AmCacheReader {
    let root = reader.other_hive_root("Amcache").unwrap();
    let registry: Arc<dyn Registry> = Arc::new(reader);
    AmCacheReader::new(registry, root)
}

#[test]
fn should_read_amcache() {
    let reader = load_reader();
    let _am_cache = obtain_am_cache(reader);
}

#[test]
fn should_iterate_over_shortcuts() {
    let reader = load_reader();
    let am_cache = obtain_am_cache(reader);
    for shortcut in am_cache.application_shortcuts().unwrap() {
        println!("{:?}", shortcut);
    }
    for app in am_cache.applications().unwrap() {
        println!("{:?}", app);
    }
    for app_file in am_cache.application_files().unwrap() {
        println!("{:?}", app_file);
    }
    for device in am_cache.device_containers().unwrap() {
        println!("{:?}", device);
    }
    for driver in am_cache.driver_binaries().unwrap() {
        println!("{:?}", driver);
    }
    for driver_pkg in am_cache.driver_package().unwrap() {
        println!("{:?}", driver_pkg);
    }
}
