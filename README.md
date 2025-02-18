# AmCache Parser & Analyzer

[![crates.io](https://img.shields.io/crates/v/frnsc-amcache.svg?style=for-the-badge&logo=rust)](https://crates.io/crates/frnsc-amcache) [![documentation](https://img.shields.io/badge/read%20the-docs-9cf.svg?style=for-the-badge&logo=docs.rs)](https://docs.rs/frnsc-amcache) [![MIT License](https://img.shields.io/crates/l/frnsc-amcache?style=for-the-badge)](https://github.com/ForensicRS/frnsc-amcache/blob/main/LICENSE) [![Rust](https://img.shields.io/github/actions/workflow/status/ForensicRS/frnsc-amcache/rust.yml?style=for-the-badge)](https://github.com/ForensicRS/frnsc-amcache/workflows/Rust/badge.svg?branch=main)


This repository provides a Rust-based tool for parsing and analyzing the AmCache registry hive in Windows. The AmCache stores valuable forensic data about executed programs, installed applications, and connected devices, making it a crucial source of information for threat hunting, incident response, and forensic investigations.

### Features
* Extracts and parses data from the AmCache.hve file.
* Supports: InventoryApplicationShortcut, InventoryApplication, InventoryApplicationFile, InventoryDeviceContainer, InventoryDriverBinary and InventoryDriverPackage.
* Provides structured output for forensic analysis.
* Fast and efficient parsing using Rust.


### Documentation

[Windows Diagnostic Events and Fields](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/privacy/basic-level-windows-diagnostic-events-and-fields-1803#inventory-events)

### To-Do
- [ ] Take into account different Windows Versions
- [x] InventoryDriverBinary
- [x] InventoryApplicationShortcut
- [x] InventoryApplicationFile
- [x] InventoryDriverPackage
- [x] InventoryDeviceContainer
- [x] InventoryApplication
- [ ] DeviceCensus
- [ ] DriverPackageExtended
- [ ] InventoryApplicationAppV
- [ ] InventoryApplicationDriver
- [ ] InventoryApplicationFramework
- [ ] InventoryDeviceInterface
- [ ] InventoryDeviceMediaClass
- [ ] InventoryDevicePnp
- [ ] InventoryDeviceUsbHubClass
- [ ] InventoryMiscellaneousMemorySlotArrayInfo
- [ ] InventoryMiscellaneousOfficeAddIn
- [ ] InventoryMiscellaneousOfficeAddInUsage
- [ ] InventoryMiscellaneousOfficeIdentifiers
- [ ] InventoryMiscellaneousOfficeIESettings
- [ ] InventoryMiscellaneousOfficeInsights
- [ ] InventoryMiscellaneousOfficeProducts
- [ ] InventoryMiscellaneousOfficeSettings
- [ ] InventoryMiscellaneousOfficeVBA
- [ ] InventoryMiscellaneousOfficeVBARuleViolations
- [ ] InventoryMiscellaneousUUPInfo

### Usage

```rust
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

fn main() {
    let mut amcache = obtain_am_cache();
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
```

```bash
InventoryApplicationShortcut { path: "c:\\users\\administrador\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\System Tools\\Administrative Tools.lnk", target_path: "", aum_id: "", program_id: "", timestamp: 04-09-2019 21:19:08.710 }
InventoryApplicationShortcut { path: "c:\\users\\supersecretadmin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\System Tools\\Administrative Tools.lnk", target_path: "", aum_id: "", program_id: "", timestamp: 25-09-2019 20:25:26.440 }
InventoryApplicationShortcut { path: "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\Calculator.lnk", target_path: "", aum_id: "", program_id: "", timestamp: 04-09-2019 21:18:59.541 }
InventoryApplicationShortcut { path: "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\System Tools\\Character Map.lnk", target_path: "", aum_id: "", program_id: "", timestamp: 04-09-2019 21:19:00.177 }
InventoryApplicationShortcut { path: "c:\\users\\supersecretadmin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\System Tools\\Command Prompt.lnk", target_path: "", aum_id: "", program_id: "", timestamp: 25-09-2019 20:25:26.456 }
InventoryApplicationFile { path: "c:\\program files (x86)\\google\\update\\download\\{8a69d345-d564-463c-aff1-a69d9e530f96}\\76.0.3809.132\\76.0.3809.132_75.0.3770.100_chrome_updater.exe", product_version: "76.0.3809.132", product_name: "google chrome installer", program_id: "0006551c26770e1f9e806ad7d0ed8d5254cc00000904", timestamp: 04-09-2019 21:19:04.283, hash: "0000f65dd072877889a3ff2a18d76d9ad904264c0921", publisher: "google llc", link_date: "08/23/2019 05:00:00", language: 1033, size: 0, bin_type: "pe64_amd64", usn: 0 }
InventoryApplicationFile { path: "c:\\windows\\system32\\applicationframehost.exe", product_version: "10.0.14393.0", product_name: "microsoft® windows® operating system", program_id: "0000f519feec486de87ed73cb92d3cac802400000000", timestamp: 13-07-2019 06:59:08.849, hash: "00000c2fe933abb71c8d97082ae6d732d49b0b01be15", publisher: "microsoft corporation", link_date: "07/16/2016 02:28:01", language: 1033, size: 0, bin_type: "pe64_amd64", usn: 0 }
InventoryApplicationFile { path: "c:\\program files (x86)\\google\\chrome\\application\\76.0.3809.132\\installer\\chrmstp.exe", product_version: "76.0.3809.132", product_name: "google chrome installer", program_id: "0000abe5c281c9c3d87c0f211f601cf22e6d0000ffff", timestamp: 04-09-2019 21:18:54.571, hash: "000053f9daa9acfa482229f74bb7d108b1bd6fbf4778", publisher: "google llc", link_date: "08/23/2019 05:00:00", language: 1033, size: 0, bin_type: "pe64_amd64", usn: 0 }
InventoryApplicationFile { path: "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe", product_version: "76.0.3809.132", product_name: "google chrome", program_id: "0006abe5c281c9c3d87c0f211f601cf22e6d00000904", timestamp: 04-09-2019 21:19:11.652, hash: "0000f6af6cd298f660ff5bb4f89398d1d3edac020a7d", publisher: "google llc", link_date: "08/23/2019 05:00:00", language: 1033, size: 0, bin_type: "pe64_amd64", usn: 0 }
InventoryApplicationFile { path: "c:\\program files (x86)\\google\\chrome\\application\\chrome_proxy.exe", product_version: "76.0.3809.132", product_name: "google chrome", program_id: "0006abe5c281c9c3d87c0f211f601cf22e6d00000904", timestamp: 04-09-2019 21:19:12.296, hash: "0000a8042870337efc505361aa0e704288f2f3d33e12", publisher: "google llc", link_date: "08/23/2019 05:00:00", language: 1033, size: 0, bin_type: "pe64_amd64", usn: 0 }
InventoryDeviceContainer { model_name: "Standard PC (i440FX + PIIX, 1996)", friendly_name: "CHITONSRV\0IH3DT", model_number: "", manufacturer: "QEMU", model_id: "", primary_category: "computer", categories: "computer", is_machine_container: 0, discovery_method: 0, is_connected: 0, is_active: 0, is_paired: 0, is_networked: 0, state: 25, timestamp: 27-10-2019 10:07:05.069 }
InventoryDeviceContainer { model_name: "Microsoft XPS Document Writer v4", friendly_name: "Microsoft XPS Document Writer", model_number: "", manufacturer: "", model_id: "{63e262cd-de1a-0741-2baa-25f72900a032}\0耀", primary_category: "printfax.printer.file", categories: "printfax.printer.file", is_machine_container: 0, discovery_method: 0, is_connected: 0, is_active: 0, is_paired: 0, is_networked: 0, state: 9, timestamp: 27-10-2019 10:07:05.303 }
InventoryDeviceContainer { model_name: "Generic Non-PnP Monitor\00", friendly_name: "", model_number: "", manufacturer: "", model_id: "{00b0927b-ab73-c599-59d5-8b32708d77c3}\0偍䑉", primary_category: "display.monitor", categories: "display.monitor\0r", is_machine_container: 0, discovery_method: 0, is_connected: 0, is_active: 0, is_paired: 0, is_networked: 0, state: 9, timestamp: 27-10-2019 10:07:05.287 }
InventoryDeviceContainer { model_name: "QEMU USB Tablet", friendly_name: "", model_number: "", manufacturer: "", model_id: "{cc54afdc-9d30-faad-a5fa-555953b50f19}", primary_category: "input.mouse", categories: "input.mouse", is_machine_container: 0, discovery_method: 0, is_connected: 0, is_active: 0, is_paired: 0, is_networked: 0, state: 9, timestamp: 27-10-2019 10:07:05.256 }
InventoryDeviceContainer { model_name: "Microsoft Print To PDF", friendly_name: "Microsoft Print to PDF", model_number: "", manufacturer: "", model_id: "{85345646-6c16-4d25-1877-240718614f8d}", primary_category: "printfax.printer.file", categories: "printfax.printer.file", is_machine_container: 0, discovery_method: 0, is_connected: 0, is_active: 0, is_paired: 0, is_networked: 0, state: 9, timestamp: 27-10-2019 10:07:05.069 }
InventoryDeviceContainer { model_name: "vport0p1", friendly_name: "", model_number: "", manufacturer: "", model_id: "{1a7f403f-5745-af01-cbd4-d56500e48939}\0耀", primary_category: "unknown", categories: "unknown", is_machine_container: 0, discovery_method: 0, is_connected: 0, is_active: 0, is_paired: 0, is_networked: 0, state: 9, timestamp: 27-10-2019 10:07:05.225 }
InventoryDriverBinary { driver_name: "1394ohci.sys", inf: "", driver_version: "10.0.14393.0", product: "Microsoft® Windows® Operating System", product_version: "10.0.14393.0", wdf_version: "", driver_company: "Microsoft Corporation", driver_package_strong_name: "", service: "1394ohci", driver_in_box: 0, driver_signed: 0, driver_is_kernel_mode: 0, driver_id: "0000895407cb018368e62fc360b972a8b0da7e729662", driver_last_write_time: "07/16/2016 13:18:02", driver_type: 8650778, driver_timestamp: 1468635696, driver_check_sum: 285843, image_size: 262144, timestamp: 27-10-2019 10:07:06.928 }
InventoryDriverBinary { driver_name: "3ware.sys", inf: "", driver_version: "5.1.0.51", product: "LSI 3ware RAID Controller", product_version: "WindowsBlue", wdf_version: "", driver_company: "LSI", driver_package_strong_name: "", service: "3ware", driver_in_box: 0, driver_signed: 0, driver_is_kernel_mode: 0, driver_id: "00001d670e2c8594733506375d2da1c37452189d37d3", driver_last_write_time: "07/16/2016 13:18:02", driver_type: 8650778, driver_timestamp: 1431988083, driver_check_sum: 136876, image_size: 122880, timestamp: 27-10-2019 10:07:06.928 }
InventoryDriverBinary { driver_name: "acpi.sys", inf: "acpi.inf", driver_version: "10.0.14393.2339", product: "Sistema operativo Microsoft® Windows®", product_version: "10.0.14393.0", wdf_version: "", driver_company: "Microsoft Corporation", driver_package_strong_name: "acpi.inf_amd64_35b48a2849b447b5", service: "acpi", driver_in_box: 0, driver_signed: 0, driver_is_kernel_mode: 0, driver_id: "0000b8a2a9241169fe62b78de100a4c0468fe7459dbe", driver_last_write_time: "06/12/2018 01:35:22", driver_type: 8651034, driver_timestamp: 1528763928, driver_check_sum: 722416, image_size: 733184, timestamp: 27-10-2019 10:07:06.943 }
InventoryDriverBinary { driver_name: "acpidev.sys\0\u{e9e8}", inf: "", driver_version: "10.0.14393.0", product: "Microsoft® Windows® Operating System", product_version: "10.0.14393.0", wdf_version: "", driver_company: "Microsoft Corporation", driver_package_strong_name: "", service: "acpidev\0\u{e708}", driver_in_box: 0, driver_signed: 0, driver_is_kernel_mode: 0, driver_id: "00005af567a52a010553901abe347f191628e8785e6d", driver_last_write_time: "07/16/2016 13:18:02", driver_type: 8650778, driver_timestamp: 1468636150, driver_check_sum: 36804, image_size: 53248, timestamp: 27-10-2019 10:07:06.943 }
InventoryDriverBinary { driver_name: "acpiex.sys", inf: "", driver_version: "10.0.14393.0", product: "Microsoft® Windows® Operating System", product_version: "10.0.14393.0", wdf_version: "1.15", driver_company: "Microsoft Corporation", driver_package_strong_name: "", service: "acpiex", driver_in_box: 0, driver_signed: 0, driver_is_kernel_mode: 0, driver_id: "0000187b57e23dae09a62fccfb415859ed004f30e432", driver_last_write_time: "07/16/2016 13:19:13", driver_type: 8651034, driver_timestamp: 1468636103, driver_check_sum: 143506, image_size: 143360, timestamp: 27-10-2019 10:07:06.943 }
InventoryDriverBinary { driver_name: "acpipagr.sys", inf: "", driver_version: "10.0.14393.0", product: "Microsoft® Windows® Operating System", product_version: "10.0.14393.0", wdf_version: "", driver_company: "Microsoft Corporation", driver_package_strong_name: "", service: "acpipagr", driver_in_box: 0, driver_signed: 0, driver_is_kernel_mode: 0, driver_id: "0000b563efcb44ebc623c6c995fdd9b99a7a15bcf274", driver_last_write_time: "07/16/2016 13:18:03", driver_type: 8650778, driver_timestamp: 1468636140, driver_check_sum: 74069, image_size: 45056, timestamp: 27-10-2019 10:07:06.959 }
InventoryDriverBinary { driver_name: "acpipmi.sys", inf: "", driver_version: "10.0.14393.0", product: "Microsoft® Windows® Operating System", product_version: "10.0.14393.0", wdf_version: "", driver_company: "Microsoft Corporation", driver_package_strong_name: "", service: "acpipmi", driver_in_box: 0, driver_signed: 0, driver_is_kernel_mode: 0, driver_id: "0000fde1b95d7165db9a41d74c85087e998ddcc21bc2", driver_last_write_time: "07/16/2016 13:17:59", driver_type: 8650778, driver_timestamp: 1468635584, driver_check_sum: 28534, image_size: 49152, timestamp: 27-10-2019 10:07:06.959 }
InventoryDriverBinary { driver_name: "acpitime.sys", inf: "", driver_version: "10.0.14393.0", product: "Microsoft® Windows® Operating System", product_version: "10.0.14393.0", wdf_version: "", driver_company: "Microsoft Corporation", driver_package_strong_name: "", service: "acpitime", driver_in_box: 0, driver_signed: 0, driver_is_kernel_mode: 0, driver_id: "0000f386096754166b5fe85f2c5c25240610e3272d47", driver_last_write_time: "07/16/2016 13:18:03", driver_type: 8650778, driver_timestamp: 1468636160, driver_check_sum: 25636, image_size: 49152, timestamp: 27-10-2019 10:07:07.022 }
InventoryDriverBinary { driver_name: "adp80xx.sys", inf: "", driver_version: "1.3.0.10769", product: "PMC-Sierra HBA Controller", product_version: "1.3.0.10769", wdf_version: "", driver_company: "PMC-Sierra", driver_package_strong_name: "", service: "adp80xx", driver_in_box: 0, driver_signed: 0, driver_is_kernel_mode: 0, driver_id: "00006e08310a63bc538d49e196af07e52b50be438c24", driver_last_write_time: "07/16/2016 13:18:02", driver_type: 8650778, driver_timestamp: 1428612588, driver_check_sum: 1153210, image_size: 2473984, timestamp: 27-10-2019 10:07:07.037 }
InventoryDriverBinary { driver_name: "afd.sys", inf: "", driver_version: "10.0.14393.3115", product: "Sistema operativo Microsoft® Windows®", product_version: "10.0.14393.0", wdf_version: "", driver_company: "Microsoft Corporation", driver_package_strong_name: "", service: "afd", driver_in_box: 0, driver_signed: 0, driver_is_kernel_mode: 0, driver_id: "00004f8abe59d075a93064100200aa9b228402319f50", driver_last_write_time: "07/09/2019 03:59:05", driver_type: 8650778, driver_timestamp: 1562642127, driver_check_sum: 613346, image_size: 610304, timestamp: 27-10-2019 10:07:07.037 }
InventoryDriverPackage { class_guid: "{4d36e97d-e325-11ce-bfc1-08002be10318}", class: "system", directory: "c:\\windows\\system32\\driverstore\\filerepository\\balloon.inf_amd64_b42039c1c5afb07d", date: "2019-4-12", version: "100.77.104.17100", provider: "Red Hat, Inc.", submission_id: "", driver_inbox: 0, inf: "oem4.inf", flight_ids: "", recovery_ids: "", is_active: 0, hwids: "pci\\ven_1af4&dev_1002&subsys_00051af4&rev_00,pci\\ven_1af4&dev_1045&subsys_11001af4&rev_01", sysfile: "balloon.sys", timestamp: 04-09-2019 21:20:00.648 }
InventoryDriverPackage { class_guid: "{4d36e972-e325-11ce-bfc1-08002be10318}", class: "net", directory: "c:\\windows\\system32\\driverstore\\filerepository\\netkvm.inf_amd64_bfc7fe0145860ade", date: "2019-4-12", version: "100.77.104.17100", provider: "Red Hat, Inc.", submission_id: "", driver_inbox: 0, inf: "oem3.inf", flight_ids: "", recovery_ids: "", is_active: 0, hwids: "pci\\ven_1af4&dev_1000&subsys_00011af4&rev_00,pci\\ven_1af4&dev_1041&subsys_11001af4&rev_01", sysfile: "netkvm.sys", timestamp: 04-09-2019 21:20:02.093 }
InventoryDriverPackage { class_guid: "{4d36e97b-e325-11ce-bfc1-08002be10318}", class: "scsiadapter", directory: "c:\\windows\\system32\\driverstore\\filerepository\\vioscsi.inf_amd64_92c422d64c5b2776", date: "2019-4-12", version: "100.77.104.17100", provider: "Red Hat, Inc.", submission_id: "", driver_inbox: 0, inf: "oem5.inf", flight_ids: "", recovery_ids: "", is_active: 0, hwids: "pci\\ven_1af4&dev_1004&subsys_00081af4&rev_00,pci\\ven_1af4&dev_1048&subsys_11001af4&rev_01", sysfile: "vioscsi.sys", timestamp: 27-10-2019 10:07:22.601 }
InventoryDriverPackage { class_guid: "{4d36e97d-e325-11ce-bfc1-08002be10318}", class: "system", directory: "c:\\windows\\system32\\driverstore\\filerepository\\vioser.inf_amd64_80aed074603ea345", date: "2019-4-12", version: "100.77.104.17100", provider: "Red Hat, Inc.", submission_id: "", driver_inbox: 0, inf: "oem6.inf", flight_ids: "", recovery_ids: "", is_active: 0, hwids: "pci\\ven_1af4&dev_1003&subsys_00031af4&rev_00,pci\\ven_1af4&dev_1043&subsys_11001af4&rev_01", sysfile: "vioser.sys\0\0\u{1}", timestamp: 27-10-2019 10:07:21.429 }
InventoryDriverPackage { class_guid: "{4d36e97b-e325-11ce-bfc1-08002be10318}", class: "scsiadapter", directory: "c:\\windows\\system32\\driverstore\\filerepository\\viostor.inf_amd64_6214303affd5c7dd", date: "2019-4-12", version: "100.77.104.17100", provider: "Red Hat, Inc.", submission_id: "", driver_inbox: 0, inf: "oem0.inf", flight_ids: "", recovery_ids: "", is_active: 0, hwids: "pci\\ven_1af4&dev_1001&subsys_00021af4&rev_00,pci\\ven_1af4&dev_1042&subsys_11001af4&rev_01", sysfile: "viostor.sys", timestamp: 04-09-2019 21:20:03.437 }
```