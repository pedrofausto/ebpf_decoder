#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct filter_config_t {
    pub version: u32,
    pub max_rate_pps: u32,
    pub ip_allowlist_update: u32,
    pub sampling_numerator: u32,
    pub sampling_denominator: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct log_event_t {
    pub conn_id: u32,
    pub pid: u32,
    pub tid: u32,
    pub ts_ns: u64,
    pub data_len: u32,
    pub data: [u8; 1024],
}
