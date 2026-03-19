//! Prometheus metrics for monitoring.

use prometheus::{Histogram, HistogramOpts, IntCounterVec, Opts, Registry};
use std::sync::LazyLock;

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

static REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let counter = IntCounterVec::new(
        Opts::new("veil_requests_total", "Total requests processed"),
        &["status"],
    )
    .unwrap();
    REGISTRY.register(Box::new(counter.clone())).unwrap();
    counter
});

static DECRYPT_DURATION: LazyLock<Histogram> = LazyLock::new(|| {
    let hist = Histogram::with_opts(
        HistogramOpts::new("veil_decrypt_duration_seconds", "Time to decrypt request")
            .buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05]),
    )
    .unwrap();
    REGISTRY.register(Box::new(hist.clone())).unwrap();
    hist
});

static ENCRYPT_DURATION: LazyLock<Histogram> = LazyLock::new(|| {
    let hist = Histogram::with_opts(
        HistogramOpts::new("veil_encrypt_duration_seconds", "Time to encrypt response")
            .buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05]),
    )
    .unwrap();
    REGISTRY.register(Box::new(hist.clone())).unwrap();
    hist
});

static PAYLOAD_SIZE: LazyLock<Histogram> = LazyLock::new(|| {
    let hist = Histogram::with_opts(
        HistogramOpts::new("veil_payload_bytes", "Encrypted payload size in bytes")
            .buckets(vec![100.0, 1000.0, 10000.0, 100000.0, 1000000.0]),
    )
    .unwrap();
    REGISTRY.register(Box::new(hist.clone())).unwrap();
    hist
});

pub fn record_request(status: &str) {
    REQUESTS_TOTAL.with_label_values(&[status]).inc();
}

pub fn observe_decrypt(duration_secs: f64) {
    DECRYPT_DURATION.observe(duration_secs);
}

pub fn observe_encrypt(duration_secs: f64) {
    ENCRYPT_DURATION.observe(duration_secs);
}

pub fn observe_payload_size(size: usize) {
    PAYLOAD_SIZE.observe(size as f64);
}

/// Encode all metrics in Prometheus text format.
pub fn encode_metrics() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metrics = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metrics, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
