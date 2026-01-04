#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    pub response_probability: u32, // 0-100
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Config {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub rx: u64,
    pub valid_syn: u64,
    pub tx: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stats {}
