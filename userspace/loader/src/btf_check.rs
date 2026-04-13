use anyhow::Result;
use std::path::Path;

/// Validates BTF availability before attempting CO-RE program load.
pub fn assert_btf_available() -> Result<()> {
    let path = Path::new("/sys/kernel/btf/vmlinux");
    if !path.exists() {
        anyhow::bail!(
            "BTF not available at /sys/kernel/btf/vmlinux.\n\
             CO-RE requires CONFIG_DEBUG_INFO_BTF=y in kernel config.\n\
             Recompile the kernel or use a distribution kernel >= 5.8 with BTF enabled.\n\
             Ubuntu 20.04+, Fedora 35+, and RHEL 9+ ship BTF-enabled kernels."
        );
    }
    Ok(())
}
