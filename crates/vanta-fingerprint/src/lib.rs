//! vanta-fingerprint: real-device personas, UA/UA-CH from the engine version (R5),
//! consistency rules C001–C031, Ed25519-signed launch config (F02, F12, F20).

pub mod config;
pub mod device;
pub mod persona;
pub mod rules;
pub mod ua;

pub use persona::{Geo, Persona, SurfaceMode};
