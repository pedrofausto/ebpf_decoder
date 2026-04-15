use libbpf_rs::MapHandle;
use std::os::unix::io::AsRawFd;
use std::os::fd::AsFd;

#[allow(dead_code)]
pub fn test_fd(map: &MapHandle) {
    let _fd1 = map.as_fd().as_raw_fd();
    let _fd2 = map.as_fd().as_raw_fd();
}