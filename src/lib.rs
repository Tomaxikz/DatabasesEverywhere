#[cfg(not(target_os = "linux"))]
compile_error!(
    "DatabasesEverywhere supports Linux targets only; the daemon depends on Linux container and Unix-socket facilities"
);

#[cfg(target_os = "linux")]
pub mod api;
#[cfg(target_os = "linux")]
pub mod auth;
#[cfg(target_os = "linux")]
pub mod backups;
#[cfg(target_os = "linux")]
pub mod bench;
#[cfg(target_os = "linux")]
pub mod bins;
#[cfg(target_os = "linux")]
pub mod cli;
#[cfg(target_os = "linux")]
pub mod compatibility;
#[cfg(target_os = "linux")]
pub mod config;
#[cfg(target_os = "linux")]
pub mod constants;
#[cfg(target_os = "linux")]
pub mod databases;
#[cfg(target_os = "linux")]
pub mod disk;
#[cfg(target_os = "linux")]
pub mod gateway;
#[cfg(target_os = "linux")]
pub mod instances;
#[cfg(target_os = "linux")]
pub mod jobs;
#[cfg(target_os = "linux")]
pub mod monitoring;
#[cfg(target_os = "linux")]
pub mod panel;
#[cfg(target_os = "linux")]
pub mod protocols;
#[cfg(target_os = "linux")]
pub mod runtime;
#[cfg(target_os = "linux")]
pub mod shared;
#[cfg(target_os = "linux")]
pub mod storage;
