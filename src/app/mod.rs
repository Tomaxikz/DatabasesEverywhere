#![warn(unreachable_pub)]

#[cfg(not(target_os = "linux"))]
compile_error!(
    "DatabasesEverywhere supports Linux targets only; the daemon depends on Linux container and Unix-socket facilities"
);

#[cfg(target_os = "linux")]
pub mod auth;
#[cfg(target_os = "linux")]
pub mod bins;
#[cfg(target_os = "linux")]
pub mod commands;
#[cfg(target_os = "linux")]
pub mod config;
#[cfg(target_os = "linux")]
mod daemon;
#[cfg(target_os = "linux")]
pub mod databases;
#[cfg(target_os = "linux")]
pub mod gateway;
#[cfg(target_os = "linux")]
pub mod instance;
#[cfg(target_os = "linux")]
pub mod io;
#[cfg(target_os = "linux")]
pub mod routes;
#[cfg(target_os = "linux")]
pub mod runtime;
#[cfg(target_os = "linux")]
pub mod state;
#[cfg(target_os = "linux")]
pub mod storage;
#[cfg(target_os = "linux")]
pub mod subsystems;
#[cfg(target_os = "linux")]
pub mod utils;
