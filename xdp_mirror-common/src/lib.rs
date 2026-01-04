#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    pub response_probability: u32, // 0-100
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Config {}
