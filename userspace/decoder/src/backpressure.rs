use prometheus_client::metrics::counter::Counter;
use prometheus_client::registry::Registry;

#[allow(dead_code)]
pub struct Metrics {
    pub ringbuf_drops: Counter,
    pub channel_drops: Counter,
    pub parser_drops: Counter,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let ringbuf_drops = Counter::default();
        let channel_drops = Counter::default();
        let parser_drops = Counter::default();

        registry.register("ebpf_ringbuf_drops", "Total drops at kernel level", ringbuf_drops.clone());
        registry.register("ebpf_channel_drops", "Total drops at channel saturation", channel_drops.clone());
        registry.register("ebpf_parser_drops", "Total drops at parser pool overload", parser_drops.clone());

        Self {
            ringbuf_drops,
            channel_drops,
            parser_drops,
        }
    }
}

/*
 * Backpressure implementation:
 * 1. Tier 1 - Kernel drop: Handled by BPF incrementing drop_counters.
 * 2. Tier 2 - Channel saturation: MPSC bounded channel.
 * 3. Tier 3 - Parser pool overload: Bounded task queue.
 */
