//! ProxyWiFi daemon library.
//!
//! The daemon is split into a library and a thin binary so that the
//! service logic and the D-Bus interface can be unit-tested without
//! spawning a privileged process.

pub mod dataplane;
pub mod dbus_server;
pub mod dns;
pub mod service;
