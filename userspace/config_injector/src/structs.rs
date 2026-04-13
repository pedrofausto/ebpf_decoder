#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct filter_config_t {
    pub version: u32,
    pub max_rate_pps: u32,
    pub ip_allowlist_update: u32,
    pub sampling_numerator: u32,
    pub sampling_denominator: u32,
}
