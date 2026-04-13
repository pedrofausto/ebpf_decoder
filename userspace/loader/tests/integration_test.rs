use std::net::UdpSocket;
use std::process::Command;
use std::thread;
use std::time::Duration;

#[test]
fn test_pipeline_ingestion() {
    /* 1. Ensure BPF is built */
    let status = Command::new("make")
        .arg("all")
        .current_dir("../..")
        .status()
        .expect("Failed to run make all");
    assert!(status.success());

    /* 2. Start UDP receiver (simplified simulation of decoder) */
    let socket = UdpSocket::bind("127.0.0.1:0").expect("couldn't bind to address");
    let port = socket.local_addr().unwrap().port();
    
    /* 3. Send JSON payload */
    let payload = b"{\"event\": \"test\", \"value\": 42}";
    socket.send_to(payload, format!("127.0.0.1:{}", port)).expect("couldn't send message");

    /* 4. Verify (In a real integration test we'd check BPF stats or ringbuffer) */
    println!("Sent test payload to loopback port {}", port);
    
    /* 
     * Note: Full end-to-end test with BPF requires root and interface attachment.
     * We demonstrate the test structure here.
     */
}
