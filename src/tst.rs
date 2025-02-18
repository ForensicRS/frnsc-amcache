use std::path::Path;

use forensic_rs::{core::fs::{ChRootFileSystem, StdVirtualFS}, err::ForensicResult, traits::vfs::VirtualFileSystem};
use frnsc_hive::reader::{open_hive_with_logs, HiveRegistryReader};

use super::AmCache;

fn obtain_am_cache() -> AmCache<HiveRegistryReader> {
    let fs = StdVirtualFS::new().duplicate();
    let mut fs = ChRootFileSystem::new("./artifacts", fs).duplicate();
    load_am_cache_from_fs(&mut fs).unwrap()
}

fn load_am_cache_from_fs(fs : &mut Box<dyn VirtualFileSystem>) -> ForensicResult<AmCache<HiveRegistryReader>>{
    let mut reader = HiveRegistryReader::new();
    let hive_file = open_hive_with_logs(fs, Path::new(r"C:\Windows\AppCompat\Programs"), "Amcache.hve").unwrap();
    reader.add_other("Amcache", hive_file);
    Ok(AmCache {
        reader
    })
}

#[test]
fn should_read_amcache() {
    let _am_cache = obtain_am_cache();
}

#[test]
fn should_iterate_over_shortcuts() {
    let am_cache = obtain_am_cache();
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