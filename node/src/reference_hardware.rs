use sc_sysinfo::{Metric, Requirement, Requirements, Throughput};

/// The hardware requirements as measured on reference hardware.
pub const REFERENCE_HARDWARE: std::cell::LazyCell<Requirements, fn() -> Requirements> =
    std::cell::LazyCell::new(|| {
        Requirements(vec![
            Requirement {
                metric: Metric::Blake2256,
                minimum: Throughput::from_mibs(1000.00),
            },
            Requirement {
                metric: Metric::Sr25519Verify,
                minimum: Throughput::from_kibs(6225.00),
            },
            Requirement {
                metric: Metric::MemCopy,
                minimum: Throughput::from_mibs(11700.00),
            },
            Requirement {
                metric: Metric::DiskSeqWrite,
                minimum: Throughput::from_mibs(900.00),
            },
            Requirement {
                metric: Metric::DiskRndWrite,
                minimum: Throughput::from_mibs(400.00),
            },
        ])
    });
