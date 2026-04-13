mod structs;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::{UserRingBuffer, MapCore};
use structs::filter_config_t;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    interface: String,

    #[arg(short, long, default_value_t = 1000)]
    rate_limit: u32,

    #[arg(short, long, default_value_t = 1)]
    sampling_numerator: u32,

    #[arg(short, long, default_value_t = 1)]
    sampling_denominator: u32,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Updating configuration for interface: {}", args.interface);

    /* 1. Open the user_ringbuf map */
    let obj = libbpf_rs::ObjectBuilder::default().open_file("kernel/layer4_transport/user_ringbuf_consumer.bpf.o")?;
    let loaded = obj.load()?;
    let urb_map = loaded.maps().find(|m| m.name() == "filter_config_urb").expect("filter_config_urb map not found");

    /* 2. Setup UserRingBuffer and sumbit config */
    let urb = UserRingBuffer::new(&urb_map)?;
    let mut reserve = urb.reserve(std::mem::size_of::<filter_config_t>())?;
    
    let config = filter_config_t {
        version: 1,
        max_rate_pps: args.rate_limit,
        ip_allowlist_update: 0,
        sampling_numerator: args.sampling_numerator,
        sampling_denominator: args.sampling_denominator,
    };

    /* Copy data into the reserved slot */
    unsafe {
        std::ptr::copy_nonoverlapping(
            &config as *const _ as *const u8,
            reserve.as_mut().as_mut_ptr(),
            std::mem::size_of::<filter_config_t>(),
        );
    }
    
    let _ = urb.submit(reserve);

    println!("Configuration injected successfully.");
    Ok(())
}
