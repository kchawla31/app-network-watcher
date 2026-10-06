//! Table, filters, and Android connect planning for the desktop debugger.
//! The window itself lives in the binary.

mod adb;
mod model;

pub use adb::{
    check_approval, connect_android, install_system_ca, parse_devices, run_command, AdbDevice,
    ConnectRequest,
};
pub use model::{
    header_block, json_lines, move_id, parse_header_block, qr_blocks, request_text, response_text,
    traffic_rows, JsonLine, Tone, TrafficRow,
};
pub use watcher_core::*;
