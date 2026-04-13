use anyhow::{Result, anyhow, Context};
use libbpf_rs::{ObjectBuilder, Xdp, XdpFlags, Object, MapCore, TcHookBuilder, TC_INGRESS};
use std::os::fd::AsFd;
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
        let links = Vec::new();
        let pin_dir = "/sys/fs/bpf/ebpf-json-pipeline";

        /* 1. Pre-flight checks */
        match Self::is_ssh_active(interface) {
            Ok(true) => warn!("WARNING: Active SSH session detected on interface {}. Possible risk of operator lockout!", interface),
            Ok(false) => info!("Pre-flight: No active SSH sessions detected on interface {}.", interface),
            Err(e) => warn!("Pre-flight check failed (non-critical): {}", e),
        }

        /* 2. Load all maps and objects first */
        let mut xdp_obj_builder = ObjectBuilder::default();
        let xdp_open = xdp_obj_builder.open_file("kernel/layer1_xdp/xdp_edge.bpf.o")
            .context("Failed to open XDP BPF object")?;
        let mut xdp_loaded = xdp_open.load().context("Failed to load XDP BPF object")?;
        
        /* Pin maps for sharing if not already pinned (idempotent) */
        let maps = ["log_ringbuf", "port_proto_filter", "ip_allowlist", "rate_limit_map", "drop_counters"];
        if !Path::new(pin_dir).exists() {
            fs::create_dir_all(pin_dir).context("Failed to create BPF pin directory")?;
        }
        for map_name in maps {
            if let Some(mut map) = xdp_loaded.maps_mut().find(|m| m.name() == map_name) {
                let path = format!("{}/{}", pin_dir, map_name);
                if !Path::new(&path).exists() {
                    let _ = map.pin(&path);
                }
            }
        }

        let mut tc_obj_builder = ObjectBuilder::default();
        let mut tc_open = tc_obj_builder.open_file("kernel/layer1_tc/tc_stateful.bpf.o")
            .context("Failed to open TC BPF object")?;
        
        /* Tell libbpf to reuse the pinned maps from XDP layer */
        for map_name in maps {
            let path = format!("{}/{}", pin_dir, map_name);
            if Path::new(&path).exists() {
                tc_open.maps_mut().find(|m| m.name() == map_name)
                    .ok_or_else(|| anyhow!("Map {} not found in TC object", map_name))?
                    .reuse_pinned_map(&path)?;
            }
        }
        
        let tc_loaded = tc_open.load().context("Failed to load TC BPF object")?;

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

        /* 4. Finally, attach XDP as the last step */
        let xdp_prog = xdp_loaded.progs().find(|p| p.name() == "xdp_edge_filter")
            .ok_or_else(|| anyhow!("XDP program 'xdp_edge_filter' not found"))?;
        
        let xdp = Xdp::new(xdp_prog.as_fd());
        if let Err(e) = xdp.attach(if_index, XdpFlags::UPDATE_IF_NOEXIST) {
            warn!("XDP attachment failed, cleaning up TC hook...");
            let _ = tc_hook.detach().context("Failed to detach TC hook during XDP attach failure")?;
            let _ = tc_hook.destroy();
            return Err(e).context("Failed to attach XDP program");
        }

        /* 5. Schedule dead man's switch (5 minute safety window) */
        Self::schedule_safety_timer(interface.to_string(), 5);

        Ok(Self { 
            links,
            xdp_obj: xdp_loaded,
            tc_obj: tc_loaded,
        })
    }
}
