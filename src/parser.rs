use forensic_rs::prelude::*;
use frnsc_hive::reader::{open_hive_with_logs, HiveRegistryReader};

use crate::amcache::AmCacheReader;
use crate::common::app::InventoryApplication;
use crate::common::app_file::InventoryApplicationFile;
use crate::common::app_shortcut::InventoryApplicationShortcut;
use crate::common::dev_container::InventoryDeviceContainer;
use crate::common::dev_interface::InventoryDeviceInterface;
use crate::common::dev_pnp::InventoryDevicePnp;
use crate::common::dev_usb_hub::InventoryDeviceUsbHubClass;
use crate::common::drv_binary::InventoryDriverBinary;
use crate::common::drv_package::InventoryDriverPackage;

/// Conventional directory an `Amcache.hve` lives under on a live/triage
/// filesystem — mirrors how `HiveRegistryReader::from_fs` hardcodes
/// `C:\Windows\System32\Config` for the standard hives.
const AMCACHE_HIVE_DIR: &str = r"C:\Windows\AppCompat\Programs";
const AMCACHE_HIVE_NAME: &str = "Amcache.hve";

/// Adapts [`AmCacheReader`] to forensic-rs's [`ArtifactParserFactory`] pipeline, emitting
/// one [`ForensicData`] per entry across all nine AmCache inventories, each carrying real
/// provenance minted from a source registered against the run's own [`ProvenanceStore`]
/// (via [`ParseContext::register_source`]).
///
/// Stateless (`&self`): all per-run state — the open hive, the host name, the registered
/// source, the acquisition method — lives in a local inside [`Self::open`], never in `self`,
/// so one instance behind an `Arc` can serve the serial pipeline, every parallel worker, and
/// every `AnalysisModule` that needs it.
///
/// Self-sufficient: unlike a caller that already owns an open `Registry`, this parser
/// discovers and opens `Amcache.hve` itself from the `FileSystem` inside `TriageSources`
/// (see [`AmCacheReader`] for the lower-level API when a caller already has a resolved
/// registry + root and wants to read AmCache data directly).
pub struct AmCacheParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for AmCacheParserFactory {
    fn default() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "windows.amcache",
                "AmCache",
                "Parses Windows Amcache.hve InventoryApplication* registry data",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![RegistryArtifacts::AmCache.into()]),
        }
    }
}

impl AmCacheParserFactory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens `Amcache.hve` from the `FileSystem` in `ctx`, mounts it as a named "other"
    /// hive (the generic `Registry` trait has no way to reach a non-standard hive itself — only
    /// `HiveRegistryReader::other_hive_root` can), and wraps the result in an owned
    /// [`AmCacheReader`].
    fn discover(ctx: &ParseContext<'_>) -> ForensicResult<AmCacheReader> {
        let fs = ctx
            .vfs()
            .ok_or_else(|| ForensicError::missing_data("FileSystem source required", CompactString::const_new("AmCacheParserFactory")))?;
        let hive_file = open_hive_with_logs(fs, FPath::new(AMCACHE_HIVE_DIR), AMCACHE_HIVE_NAME)
            .ok_or_else(|| ForensicError::missing_data("Amcache.hve not found", CompactString::const_new("AmCacheParserFactory")))?;

        let mut hive_reader = HiveRegistryReader::new();
        hive_reader.add_other("Amcache", hive_file);
        let root = hive_reader.other_hive_root("Amcache")?;
        let registry: std::sync::Arc<dyn Registry> = std::sync::Arc::new(hive_reader);
        Ok(AmCacheReader::new(registry, root))
    }
}

impl ArtifactParserFactory for AmCacheParserFactory {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn can_parse(&self, ctx: &ParseContext<'_>) -> bool {
        ctx.vfs()
            .is_some_and(|fs| fs.exists(&FPath::new(AMCACHE_HIVE_DIR).join(AMCACHE_HIVE_NAME)))
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let amcache = Self::discover(ctx)?;
        let host = ctx.host().to_string();
        let source = ctx.register_source(SourceKey::Path(format!(r"{AMCACHE_HIVE_DIR}\{AMCACHE_HIVE_NAME}")));
        let acquisition = ctx.acquisition();

        // Each `.xxx()` call below returns an owned iterator (its `OwnedRegKey` holds its
        // own `Arc::clone` of the registry) — `amcache` itself only needs to stay alive for
        // this expression, not for the lifetime of the returned `ParserRun::Pull` stream.
        // `.into_iter().flatten()` (rather than `?`) keeps one category's failure to open
        // from aborting every other category — e.g. an older Amcache.hve missing one subkey
        // still yields records for the rest.
        let (h, s) = (host.clone(), source.clone());
        let iter = amcache
            .applications()
            .into_iter()
            .flatten()
            .map(move |v| Ok(map_application(&h, &s, acquisition, v)))
            .chain({
                let (h, s) = (host.clone(), source.clone());
                amcache
                    .application_files()
                    .into_iter()
                    .flatten()
                    .map(move |v| Ok(map_application_file(&h, &s, acquisition, v)))
            })
            .chain({
                let (h, s) = (host.clone(), source.clone());
                amcache
                    .application_shortcuts()
                    .into_iter()
                    .flatten()
                    .map(move |v| Ok(map_application_shortcut(&h, &s, acquisition, v)))
            })
            .chain({
                let (h, s) = (host.clone(), source.clone());
                amcache
                    .device_containers()
                    .into_iter()
                    .flatten()
                    .map(move |v| Ok(map_device_container(&h, &s, acquisition, v)))
            })
            .chain({
                let (h, s) = (host.clone(), source.clone());
                amcache
                    .driver_binaries()
                    .into_iter()
                    .flatten()
                    .map(move |v| Ok(map_driver_binary(&h, &s, acquisition, v)))
            })
            .chain({
                let (h, s) = (host.clone(), source.clone());
                amcache
                    .driver_package()
                    .into_iter()
                    .flatten()
                    .map(move |v| Ok(map_driver_package(&h, &s, acquisition, v)))
            })
            .chain({
                let (h, s) = (host.clone(), source.clone());
                amcache
                    .device_pnps()
                    .into_iter()
                    .flatten()
                    .map(move |v| Ok(map_device_pnp(&h, &s, acquisition, v)))
            })
            .chain({
                let (h, s) = (host.clone(), source.clone());
                amcache
                    .device_interfaces()
                    .into_iter()
                    .flatten()
                    .map(move |v| Ok(map_device_interface(&h, &s, acquisition, v)))
            })
            .chain({
                let (h, s) = (host.clone(), source.clone());
                amcache
                    .device_usb_hub_classes()
                    .into_iter()
                    .flatten()
                    .map(move |v| Ok(map_device_usb_hub_class(&h, &s, acquisition, v)))
            });
        Ok(ParserRun::pull(iter))
    }
}

fn set_timestamp(data: &mut ForensicData, timestamp: Option<ForensicTimestamp>) {
    if let Some(ts) = timestamp {
        data.set("amcache.timestamp", ts);
    }
}

fn map_application(host: &str, source: &SourceHandle, acquisition: Acquisition, app: InventoryApplication) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, RegistryArtifacts::AmCache.into(), provenance);
    data.set("amcache.record_type", "InventoryApplication");
    set_timestamp(&mut data, app.timestamp);
    data.set("amcache.application.program_id", app.program_id);
    data.set("amcache.application.program_instance_id", app.program_instance_id);
    data.set("amcache.application.name", app.name);
    data.set("amcache.application.version", app.version);
    data.set("amcache.application.publisher", app.publisher);
    data.set("amcache.application.language", app.language as u64);
    data.set("amcache.application.source", app.source);
    data.set("amcache.application.type", app.r#type);
    data.set("amcache.application.store_app_type", app.store_app_type);
    data.set("amcache.application.msi_package_code", app.msi_package_code);
    data.set("amcache.application.msi_product_code", app.msi_product_code);
    data.set("amcache.application.hidden_arp", app.hidden_arp as u64);
    data.set("amcache.application.inbox_modern_app", app.inbox_modern_app as u64);
    data.set("amcache.application.os_version_at_install_time", app.os_version_at_install_time);
    data.set("amcache.application.install_date", app.install_date);
    data.set("amcache.application.package_full_name", app.package_full_name);
    data.set("amcache.application.manifest_path", app.manifest_path);
    data.set("amcache.application.bundle_manifest_path", app.bundle_manifest_path);
    data.set("amcache.application.root_dir_path", app.root_dir_path);
    data.set("amcache.application.uninstall_string", app.uninstall_string);
    data.set("amcache.application.registry_key_path", app.registry_key_path);
    data
}

fn map_application_file(host: &str, source: &SourceHandle, acquisition: Acquisition, file: InventoryApplicationFile) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, RegistryArtifacts::AmCache.into(), provenance);
    data.set("amcache.record_type", "InventoryApplicationFile");
    set_timestamp(&mut data, file.timestamp);
    data.set("amcache.application_file.path", file.path);
    data.set("amcache.application_file.product_version", file.product_version);
    data.set("amcache.application_file.product_name", file.product_name);
    data.set("amcache.application_file.program_id", file.program_id);
    data.set("amcache.application_file.hash", file.hash);
    data.set("amcache.application_file.publisher", file.publisher);
    data.set("amcache.application_file.link_date", file.link_date);
    data.set("amcache.application_file.language", file.language as u64);
    data.set("amcache.application_file.size", file.size);
    data.set("amcache.application_file.bin_type", file.bin_type);
    data.set("amcache.application_file.usn", file.usn);
    data
}

fn map_application_shortcut(host: &str, source: &SourceHandle, acquisition: Acquisition, shortcut: InventoryApplicationShortcut) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, RegistryArtifacts::AmCache.into(), provenance);
    data.set("amcache.record_type", "InventoryApplicationShortcut");
    set_timestamp(&mut data, shortcut.timestamp);
    data.set("amcache.shortcut.path", shortcut.path);
    data.set("amcache.shortcut.target_path", shortcut.target_path);
    data.set("amcache.shortcut.aum_id", shortcut.aum_id);
    data.set("amcache.shortcut.program_id", shortcut.program_id);
    data
}

fn map_device_container(host: &str, source: &SourceHandle, acquisition: Acquisition, device: InventoryDeviceContainer) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, RegistryArtifacts::AmCache.into(), provenance);
    data.set("amcache.record_type", "InventoryDeviceContainer");
    set_timestamp(&mut data, device.timestamp);
    data.set("amcache.device_container.model_name", device.model_name);
    data.set("amcache.device_container.friendly_name", device.friendly_name);
    data.set("amcache.device_container.model_number", device.model_number);
    data.set("amcache.device_container.manufacturer", device.manufacturer);
    data.set("amcache.device_container.model_id", device.model_id);
    data.set("amcache.device_container.primary_category", device.primary_category);
    data.set("amcache.device_container.categories", device.categories);
    data.set("amcache.device_container.is_machine_container", device.is_machine_container as u64);
    data.set("amcache.device_container.discovery_method", device.discovery_method as u64);
    data.set("amcache.device_container.is_connected", device.is_connected as u64);
    data.set("amcache.device_container.is_active", device.is_active as u64);
    data.set("amcache.device_container.is_paired", device.is_paired as u64);
    data.set("amcache.device_container.is_networked", device.is_networked as u64);
    data.set("amcache.device_container.state", device.state as u64);
    data
}

fn map_driver_binary(host: &str, source: &SourceHandle, acquisition: Acquisition, driver: InventoryDriverBinary) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, RegistryArtifacts::AmCache.into(), provenance);
    data.set("amcache.record_type", "InventoryDriverBinary");
    set_timestamp(&mut data, driver.timestamp);
    data.set("amcache.driver_binary.driver_name", driver.driver_name);
    data.set("amcache.driver_binary.inf", driver.inf);
    data.set("amcache.driver_binary.driver_version", driver.driver_version);
    data.set("amcache.driver_binary.product", driver.product);
    data.set("amcache.driver_binary.product_version", driver.product_version);
    data.set("amcache.driver_binary.wdf_version", driver.wdf_version);
    data.set("amcache.driver_binary.driver_company", driver.driver_company);
    data.set("amcache.driver_binary.driver_package_strong_name", driver.driver_package_strong_name);
    data.set("amcache.driver_binary.service", driver.service);
    data.set("amcache.driver_binary.driver_in_box", driver.driver_in_box as u64);
    data.set("amcache.driver_binary.driver_signed", driver.driver_signed as u64);
    data.set("amcache.driver_binary.driver_is_kernel_mode", driver.driver_is_kernel_mode as u64);
    data.set("amcache.driver_binary.driver_id", driver.driver_id);
    data.set("amcache.driver_binary.driver_last_write_time", driver.driver_last_write_time);
    data.set("amcache.driver_binary.driver_type", driver.driver_type as u64);
    data.set("amcache.driver_binary.driver_timestamp", driver.driver_timestamp as u64);
    data.set("amcache.driver_binary.driver_check_sum", driver.driver_check_sum as u64);
    data.set("amcache.driver_binary.image_size", driver.image_size as u64);
    data
}

fn map_driver_package(host: &str, source: &SourceHandle, acquisition: Acquisition, pkg: InventoryDriverPackage) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, RegistryArtifacts::AmCache.into(), provenance);
    data.set("amcache.record_type", "InventoryDriverPackage");
    set_timestamp(&mut data, pkg.timestamp);
    data.set("amcache.driver_package.class_guid", pkg.class_guid);
    data.set("amcache.driver_package.class", pkg.class);
    data.set("amcache.driver_package.directory", pkg.directory);
    data.set("amcache.driver_package.date", pkg.date);
    data.set("amcache.driver_package.version", pkg.version);
    data.set("amcache.driver_package.provider", pkg.provider);
    data.set("amcache.driver_package.submission_id", pkg.submission_id);
    data.set("amcache.driver_package.driver_inbox", pkg.driver_inbox as u64);
    data.set("amcache.driver_package.inf", pkg.inf);
    data.set("amcache.driver_package.flight_ids", pkg.flight_ids);
    data.set("amcache.driver_package.recovery_ids", pkg.recovery_ids);
    data.set("amcache.driver_package.is_active", pkg.is_active as u64);
    data.set("amcache.driver_package.hwids", pkg.hwids);
    data.set("amcache.driver_package.sysfile", pkg.sysfile);
    data
}

fn map_device_pnp(host: &str, source: &SourceHandle, acquisition: Acquisition, dev: InventoryDevicePnp) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, RegistryArtifacts::AmCache.into(), provenance);
    data.set("amcache.record_type", "InventoryDevicePnp");
    set_timestamp(&mut data, dev.timestamp);
    data.set("amcache.device_pnp.model", dev.model);
    data.set("amcache.device_pnp.manufacturer", dev.manufacturer);
    data.set("amcache.device_pnp.driver_name", dev.driver_name);
    data.set("amcache.device_pnp.parent_id", dev.parent_id);
    data.set("amcache.device_pnp.matching_id", dev.matching_id);
    data.set("amcache.device_pnp.class", dev.class);
    data.set("amcache.device_pnp.class_guid", dev.class_guid);
    data.set("amcache.device_pnp.description", dev.description);
    data.set("amcache.device_pnp.enumerator", dev.enumerator);
    data.set("amcache.device_pnp.service", dev.service);
    data.set("amcache.device_pnp.install_state", dev.install_state);
    data.set("amcache.device_pnp.device_state", dev.device_state);
    data.set("amcache.device_pnp.inf", dev.inf);
    data.set("amcache.device_pnp.driver_ver_date", dev.driver_ver_date);
    data.set("amcache.device_pnp.driver_ver_version", dev.driver_ver_version);
    data.set("amcache.device_pnp.driver_package_strong_name", dev.driver_package_strong_name);
    data.set("amcache.device_pnp.container_id", dev.container_id);
    data.set("amcache.device_pnp.problem_code", dev.problem_code);
    data.set("amcache.device_pnp.provider", dev.provider);
    data.set("amcache.device_pnp.driver_id", dev.driver_id);
    data.set("amcache.device_pnp.bus_reported_description", dev.bus_reported_description);
    data.set("amcache.device_pnp.hwid", dev.hwid);
    data.set("amcache.device_pnp.extended_infs", dev.extended_infs);
    data.set("amcache.device_pnp.comp_id", dev.comp_id);
    data.set("amcache.device_pnp.stack_id", dev.stack_id);
    data.set("amcache.device_pnp.upper_class_filters", dev.upper_class_filters);
    data.set("amcache.device_pnp.lower_class_filters", dev.lower_class_filters);
    data.set("amcache.device_pnp.upper_filters", dev.upper_filters);
    data.set("amcache.device_pnp.lower_filters", dev.lower_filters);
    data.set("amcache.device_pnp.device_interface_classes", dev.device_interface_classes);
    data.set("amcache.device_pnp.device_driver_flight_id", dev.device_driver_flight_id);
    data.set("amcache.device_pnp.device_ext_drivers_flight_ids", dev.device_ext_drivers_flight_ids);
    data.set("amcache.device_pnp.install_date", dev.install_date);
    data.set("amcache.device_pnp.first_install_date", dev.first_install_date);
    data.set("amcache.device_pnp.is_machine_container", dev.is_machine_container);
    data
}

fn map_device_interface(host: &str, source: &SourceHandle, acquisition: Acquisition, dev: InventoryDeviceInterface) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, RegistryArtifacts::AmCache.into(), provenance);
    data.set("amcache.record_type", "InventoryDeviceInterface");
    set_timestamp(&mut data, dev.timestamp);
    data.set("amcache.device_interface.accelerometer_3d", dev.accelerometer_3d);
    data.set("amcache.device_interface.activity_detection", dev.activity_detection);
    data.set("amcache.device_interface.ambient_light", dev.ambient_light);
    data.set("amcache.device_interface.barometer", dev.barometer);
    data.set("amcache.device_interface.custom", dev.custom);
    data.set("amcache.device_interface.floor_elevation", dev.floor_elevation);
    data.set("amcache.device_interface.geomagnetic_orientation", dev.geomagnetic_orientation);
    data.set("amcache.device_interface.gravity_vector", dev.gravity_vector);
    data.set("amcache.device_interface.gyrometer_3d", dev.gyrometer_3d);
    data.set("amcache.device_interface.humidity", dev.humidity);
    data.set("amcache.device_interface.linear_accelerometer", dev.linear_accelerometer);
    data.set("amcache.device_interface.magnetometer_3d", dev.magnetometer_3d);
    data.set("amcache.device_interface.orientation", dev.orientation);
    data.set("amcache.device_interface.pedometer", dev.pedometer);
    data.set("amcache.device_interface.proximity", dev.proximity);
    data.set("amcache.device_interface.relative_orientation", dev.relative_orientation);
    data.set("amcache.device_interface.simple_device_orientation", dev.simple_device_orientation);
    data.set("amcache.device_interface.temperature", dev.temperature);
    data.set("amcache.device_interface.energy_meter", dev.energy_meter);
    data
}

fn map_device_usb_hub_class(host: &str, source: &SourceHandle, acquisition: Acquisition, hub: InventoryDeviceUsbHubClass) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, RegistryArtifacts::AmCache.into(), provenance);
    data.set("amcache.record_type", "InventoryDeviceUsbHubClass");
    set_timestamp(&mut data, hub.timestamp);
    data.set("amcache.device_usb_hub_class.total_user_connectable_ports", hub.total_user_connectable_ports as u64);
    data.set("amcache.device_usb_hub_class.total_user_connectable_type_c_ports", hub.total_user_connectable_type_c_ports as u64);
    data.set("amcache.device_usb_hub_class.inf", hub.inf);
    data
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use forensic_rs::prelude::*;

    use super::AmCacheParserFactory;

    fn load_vfs() -> Arc<dyn FileSystem> {
        Arc::new(ChRootFileSystem::new("./artifacts/C", Arc::new(StdVirtualFS::new())))
    }

    #[derive(Clone, Default)]
    struct RecordCollector(Arc<Mutex<Vec<ForensicData>>>);

    impl TriageSink for RecordCollector {
        fn name(&self) -> &str {
            "record_collector"
        }
        fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
            self.0.lock().unwrap().push(data.clone());
            Ok(())
        }
        fn on_finding(&mut self, _finding: &Finding) -> ForensicResult<()> {
            Ok(())
        }
    }

    #[test]
    fn should_yield_records_with_resolvable_confidence() {
        let fs = load_vfs();

        let context = TriageContext::new("TEST-HOST", "default");
        let store = context.provenance_store();
        let collector = RecordCollector::default();

        let mut pipeline = TriagePipeline::builder()
            .context(context)
            .parser(Arc::new(AmCacheParserFactory::new()))
            .sink(Box::new(collector.clone()))
            .build()
            .unwrap();

        let sources = TriageSources::builder().vfs(fs).acquisition(Acquisition::ImageRead).build();
        let result = pipeline.run(&sources).unwrap();

        assert!(result.items_processed > 0);
        assert!(result.errors.is_empty());

        let records = collector.0.lock().unwrap();
        assert!(!records.is_empty());

        let mut record_types = std::collections::BTreeSet::new();
        for data in records.iter() {
            let confidence = data.confidence(&store);
            assert_ne!(confidence, Confidence::Unknown);
            if let Some(record_type) = data.field_as_str("amcache.record_type") {
                record_types.insert(record_type.to_string());
            }
        }
        assert!(record_types.len() > 1, "expected multiple AmCache record types, got {record_types:?}");
    }
}
