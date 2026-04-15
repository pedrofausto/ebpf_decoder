use anyhow::{Result, anyhow, Context};
use libbpf_rs::{ObjectBuilder, Xdp, XdpFlags, Object, MapCore, TcHookBuilder, TC_INGRESS};
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use nix::ifaddrs::getifaddrs;
use tracing::{warn, info};

static CONFIRMED: AtomicBool = AtomicBool::new(false);

pub struct BpfPipeline {
    /* Handle to keep links alive */
    #[allow(dead_code)]
    pub links: Vec<libbpf_rs::Link>,
    /* Handle to keep objects alive for map access */
    pub xdp_obj: Object,
    #[allow(dead_code)]
    pub tc_obj: Object,
    #[allow(dead_code)]
    pub sockops_obj: Object,
    #[allow(dead_code)]
    pub sk_msg_obj: Object,
}

impl BpfPipeline {
    /// Confirm deployment and disarm safety timer.
    pub fn confirm() {
        CONFIRMED.store(true, Ordering::SeqCst);
    }

    /// Check if there are active SSH sessions on the target interface.
    /// Look for local port 22 in established state in /proc/net/tcp.
    fn is_ssh_active(interface: &str) -> Result<bool> {
        let ifaddrs = getifaddrs()?;
        let mut interface_ips: Vec<Ipv4Addr> = Vec::new();
        for ifaddr in ifaddrs {
            if ifaddr.interface_name == interface {
                if let Some(address) = ifaddr.address {
                    if let Some(sockaddr) = address.as_sockaddr_in() {
                        interface_ips.push(Ipv4Addr::from(sockaddr.ip()));
                    }
                }
            }
        }

        if interface_ips.is_empty() {
            return Ok(false);
        }

        let file = fs::File::open("/proc/net/tcp")?;
        let reader = BufReader::new(file);

        for line in reader.lines().skip(1) {
            let line = line?;
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 { continue; }

            let local_addr_part = parts[1];
            let state = parts[3];

            if state != "01" { continue; } // 01 is ESTABLISHED

            let addr_port: Vec<&str> = local_addr_part.split(':').collect();
            if addr_port.len() != 2 { continue; }

            let port = u16::from_str_radix(addr_port[1], 16)?;
            if port != 22 { continue; }

            let ip_val = u32::from_str_radix(addr_port[0], 16)?;
            // /proc/net/tcp IP is hex representation of memory order.
            // On little-endian, 127.0.0.1 is 0100007F.
            let ip = Ipv4Addr::from(ip_val.to_ne_bytes());

            if interface_ips.contains(&ip) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Schedule an automatic detach if not confirmed within N minutes.
    fn schedule_safety_timer(interface: String, minutes: u64) {
        thread::spawn(move || {
            info!("SAFETY: Dead man's switch armed. XDP will detach in {} minutes unless confirmed.", minutes);
            // Wait for N minutes
            for _ in 0..(minutes * 60) {
                thread::sleep(Duration::from_secs(1));
                if CONFIRMED.load(Ordering::SeqCst) {
                    info!("SAFETY: Deployment confirmed. Safety timer disarmed.");
                    return;
                }
            }

            warn!("SAFETY: Safety timer expired! Detaching XDP from {}...", interface);
            let _ = std::process::Command::new("ip")
                .args(["link", "set", "dev", &interface, "xdp", "off"])
                .status();
            
            warn!("SAFETY: XDP detached to prevent operator lockout. Exiting.");
            std::process::exit(1);
        });
    }

    pub fn load_and_attach(interface: &str) -> Result<Self> {
        let mut links = Vec::new();
        let pin_dir = "/sys/fs/bpf/ebpf-json-pipeline";

        /* Clean up any old/stale state from previous runs */
        if Path::new(pin_dir).exists() {
            info!("Cleaning up stale BPF pins in {}...", pin_dir);
            let _ = fs::remove_dir_all(pin_dir);
        }
        fs::create_dir_all(pin_dir).context("Failed to create BPF pin directory")?;
        match Self::is_ssh_active(interface) {
            Ok(true) => warn!("WARNING: Active SSH session detected on interface {}. Possible risk of operator lockout!", interface),
            Ok(false) => info!("Pre-flight: No active SSH sessions detected on interface {}.", interface),
            Err(e) => warn!("Pre-flight check failed (non-critical): {}", e),
        }

        /* 2. Load all maps and objects first */
        let maps = ["log_ringbuf", "port_proto_filter", "ip_allowlist", "rate_limit_map", "drop_counters", "sockmap", "large_payload_array"];
        if !Path::new(pin_dir).exists() {
            fs::create_dir_all(pin_dir).context("Failed to create BPF pin directory")?;
        }

        /* Load XDP first to establish the maps if they don't exist */
        let mut xdp_obj_builder = ObjectBuilder::default();
        let xdp_open = xdp_obj_builder.open_file("kernel/layer1_xdp/xdp_edge.bpf.o")
            .context("Failed to open XDP BPF object")?;
        let mut xdp_loaded = xdp_open.load().context("Failed to load XDP BPF object")?;
        
        for map_name in maps {
            if let Some(mut map) = xdp_loaded.maps_mut().find(|m| m.name() == map_name) {
                let path = format!("{}/{}", pin_dir, map_name);
                if !Path::new(&path).exists() {
                    let _ = map.pin(&path);
                }
            }
        }

        /* Load TC */
        let mut tc_obj_builder = ObjectBuilder::default();
        let mut tc_open = tc_obj_builder.open_file("kernel/layer1_tc/tc_stateful.bpf.o")
            .context("Failed to open TC BPF object")?;
        for map_name in maps {
            let path = format!("{}/{}", pin_dir, map_name);
            if Path::new(&path).exists() {
                if let Some(mut map) = tc_open.maps_mut().find(|m| m.name() == map_name) {
                    map.reuse_pinned_map(&path)?;
                }
            }
        }
        let tc_loaded = tc_open.load().context("Failed to load TC BPF object")?;

        /* Load SockOps */
        let mut sockops_obj_builder = ObjectBuilder::default();
        let mut sockops_open = sockops_obj_builder.open_file("kernel/layer4_transport/cgroup_sockops.bpf.o")
            .context("Failed to open SockOps BPF object")?;
        for map_name in maps {
            let path = format!("{}/{}", pin_dir, map_name);
            if Path::new(&path).exists() {
                if let Some(mut map) = sockops_open.maps_mut().find(|m| m.name() == map_name) {
                    map.reuse_pinned_map(&path)?;
                }
            }
        }
        let mut sockops_loaded = sockops_open.load().context("Failed to load SockOps BPF object")?;
        // Pin sockmap if it wasn't in XDP
        if let Some(mut map) = sockops_loaded.maps_mut().find(|m| m.name() == "sockmap") {
             let path = format!("{}/{}", pin_dir, "sockmap");
             if !Path::new(&path).exists() {
                 let _ = map.pin(&path);
             }
        }

        /* Load SK_MSG */
        let mut sk_msg_obj_builder = ObjectBuilder::default();
        let mut sk_msg_open = sk_msg_obj_builder.open_file("kernel/layer4_transport/sk_msg_intercept.bpf.o")
            .context("Failed to open SK_MSG BPF object")?;
        for map_name in maps {
            let path = format!("{}/{}", pin_dir, map_name);
            if Path::new(&path).exists() {
                if let Some(mut map) = sk_msg_open.maps_mut().find(|m| m.name() == map_name) {
                    map.reuse_pinned_map(&path)?;
                }
            }
        }
        let mut sk_msg_loaded = sk_msg_open.load().context("Failed to load SK_MSG BPF object")?;
        // Pin large_payload_array if it wasn't in others
        if let Some(mut map) = sk_msg_loaded.maps_mut().find(|m| m.name() == "large_payload_array") {
             let path = format!("{}/{}", pin_dir, "large_payload_array");
             if !Path::new(&path).exists() {
                 let _ = map.pin(&path);
             }
        }

        let if_index = nix::net::if_::if_nametoindex(interface)? as i32;

        /* 3. Attach TC first */
        let tc_prog = tc_loaded.progs().find(|p| p.name() == "tc_unified_filter")
            .ok_or_else(|| anyhow!("TC program 'tc_unified_filter' not found"))?;
        
        let mut tc_builder = TcHookBuilder::new(tc_prog.as_fd());
        tc_builder
            .ifindex(if_index)
            .replace(true)
            .handle(1)
            .priority(1);
        
        let mut tc_hook = tc_builder.hook(TC_INGRESS);
        tc_hook.create().context("Failed to create TC hook")?;
        if let Err(e) = tc_hook.attach() {
            let _ = tc_hook.destroy();
            return Err(e).context("Failed to attach TC program");
        }

        /* 4. Attach SockOps and SK_MSG */
        let sockops_prog = sockops_loaded.progs_mut().find(|p| p.name() == "bpf_sockmap_ops")
            .ok_or_else(|| anyhow!("Sockops program 'bpf_sockmap_ops' not found"))?;
        let cgroup_path = "/sys/fs/cgroup";
        let cgroup_file = fs::File::open(cgroup_path)
            .with_context(|| format!("Failed to open cgroup root at {}", cgroup_path))?;
        let sockops_link = sockops_prog.attach_cgroup(cgroup_file.as_raw_fd())
            .context("Failed to attach SockOps program to cgroup")?;
        links.push(sockops_link);

        let sk_msg_prog = sk_msg_loaded.progs().find(|p| p.name() == "sk_msg_interceptor")
            .ok_or_else(|| anyhow!("SK_MSG program 'sk_msg_interceptor' not found"))?;
        let sockmap = sockops_loaded.maps().find(|m| m.name() == "sockmap")
            .ok_or_else(|| anyhow!("Map 'sockmap' not found in SockOps object"))?;
        
        unsafe {
            let ret = libbpf_sys::bpf_prog_attach(
                sk_msg_prog.as_fd().as_raw_fd(),
                sockmap.as_fd().as_raw_fd(),
                libbpf_sys::BPF_SK_MSG_VERDICT,
                0
            );
            if ret < 0 {
                return Err(anyhow!("Failed to attach SK_MSG program: {}", std::io::Error::last_os_error()));
            }
        }

        /* 5. Finally, attach XDP as the last step */
        let xdp_prog = xdp_loaded.progs().find(|p| p.name() == "xdp_edge_filter")
            .ok_or_else(|| anyhow!("XDP program 'xdp_edge_filter' not found"))?;
        
        let xdp = Xdp::new(xdp_prog.as_fd());
        if let Err(e) = xdp.attach(if_index, XdpFlags::UPDATE_IF_NOEXIST) {
            warn!("XDP attachment failed, cleaning up TC hook...");
            let _ = tc_hook.detach().context("Failed to detach TC hook during XDP attach failure")?;
            let _ = tc_hook.destroy();
            return Err(e).context("Failed to attach XDP program");
        }

        /* 6. Schedule dead man's switch (5 minute safety window) */
        Self::schedule_safety_timer(interface.to_string(), 5);

        Ok(Self { 
            links,
            xdp_obj: xdp_loaded,
            tc_obj: tc_loaded,
            sockops_obj: sockops_loaded,
            sk_msg_obj: sk_msg_loaded,
        })
    }
}
