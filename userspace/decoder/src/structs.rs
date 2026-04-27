/// Format constants — must match FORMAT_* in kernel/common/structs.h
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventFormat {
    Json = 0,
    Syslog = 1,
    Html = 2,
    PlainText = 3,
}

impl EventFormat {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Syslog,
            2 => Self::Html,
            3 => Self::PlainText,
            _ => Self::Json,
        }
    }
}

/// Action constants — must match ACTION_* in kernel/common/structs.h
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventAction {
    Decode = 0,
    Drop = 1,
    Pass = 2,
    Check = 3,
}

impl EventAction {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Drop,
            2 => Self::Pass,
            3 => Self::Check,
            _ => Self::Decode,
        }
    }
}

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

/// MUST stay 1:1 with log_event_t in kernel/common/structs.h
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct log_event_t {
    pub conn_id: u32,
    pub pid: u32,
    pub tid: u32,
    pub ts_ns: u64,
    pub is_arena_ptr: u8,
    pub format: u8, // FORMAT_* from port_proto_config
    pub action: u8, // ACTION_* from port_proto_config
    pub protocol: u8,
    pub dst_port: u16,
    pub pad: u16,
    pub arena_offset: u32,
    pub data_len: u32,
    pub data: [u8; 1024],
}
