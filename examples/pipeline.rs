use std::sync::Arc;

use forensic_rs::prelude::*;
use frnsc_amcache::parser::AmCacheParserFactory;

/// Prints each parsed AmCache record's type, host and resolved confidence.
struct ReportSink {
    store: ProvenanceStore,
}

impl TriageSink for ReportSink {
    fn name(&self) -> &str {
        "report"
    }

    fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
        let record_type = data.field_as_str("amcache.record_type").unwrap_or("?");
        let confidence = data.confidence(&self.store);
        println!("[{confidence:?}] {record_type} host={}", data.host());
        Ok(())
    }

    fn on_finding(&mut self, finding: &Finding) -> ForensicResult<()> {
        println!("finding: {finding:?}");
        Ok(())
    }
}

fn main() -> ForensicResult<()> {
    let fs: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new("./artifacts/C", Arc::new(StdVirtualFS::new())));

    let context = TriageContext::new("TEST-HOST", "default");
    let store = context.provenance_store();

    // `AmCacheParserFactory` is stateless — it registers its own source and reads host/
    // acquisition from the `ParseContext` the pipeline hands it inside `open()`, so it's
    // plain `Send + Sync + 'static` and shares one `Arc` across every consumer with no
    // per-run construction or lifetime workarounds required.
    let mut pipeline = TriagePipeline::builder()
        .context(context)
        .parser(Arc::new(AmCacheParserFactory::new()))
        .sink(Box::new(ReportSink { store: store.clone() }))
        .build()?;

    let sources = TriageSources::builder().vfs(fs).acquisition(Acquisition::ImageRead).build();
    let result = pipeline.run(&sources)?;

    println!(
        "parsers_run={:?} items_processed={} findings={}",
        result.parsers_run, result.items_processed, result.findings_count
    );
    Ok(())
}
