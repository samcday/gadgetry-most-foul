//! No-timeout synchronous transfer test (read_exact / write_all).
//!
//! Uses completion-based exact transfers with borrowed buffers.
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use super::*;

const SYNC_ROUNDS: usize = 16;
const VID: u16 = 0x1234;
const PID: u16 = 0x0021;

/// Device side: blocking exact IO with read_exact / write_all (no timeout).
fn run_device_sync(
    mut custom: Custom, mut ep_rx: gadgetry_most_foul::function::custom::EndpointOut,
    mut ep_tx: gadgetry_most_foul::function::custom::EndpointIn,
) {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_rx = stop.clone();
    let stop_tx = stop.clone();

    thread::scope(|s| {
        s.spawn(move || {
            let size = PACKET_SIZE;
            let mut expected = 0u8;
            for i in 0..SYNC_ROUNDS {
                let mut data = vec![0; size];
                ep_rx.read_exact(&mut data).unwrap_or_else(|e| panic!("device read_exact round {i} failed: {e}"));
                assert!(
                    data.iter().all(|&x| x == expected),
                    "device read_exact round {i}: expected all 0x{expected:02x}, got {:02x?}",
                    &data[..data.len().min(16)]
                );
                expected = expected.wrapping_add(1);
            }
            println!("device: read_exact completed {SYNC_ROUNDS} rounds");
            stop_rx.store(true, Ordering::Relaxed);
        });

        s.spawn(move || {
            let size = PACKET_SIZE;
            let mut b = 0u8;
            for i in 0..SYNC_ROUNDS {
                let data = vec![b; size];
                ep_tx.write_all(&data).unwrap_or_else(|e| panic!("device write_all round {i} failed: {e}"));
                b = b.wrapping_add(1);
            }
            println!("device: write_all completed {SYNC_ROUNDS} rounds");
            stop_tx.store(true, Ordering::Relaxed);
        });

        run_device_events(&mut custom, &stop, false);
    });
}

/// Test read_exact and write_all with no timeout.
#[test]
#[serial]
fn transfer_sync_no_timeout() {
    init();

    if skip_host() {
        return;
    }

    let (vid, pid) = (VID, PID);
    let (reg, custom, ep_rx, ep_tx) =
        setup_gadget_with_id(vid, pid, "sync transfer test device", "sync-transfer-test-001");

    thread::scope(|s| {
        s.spawn(|| run_device_sync(custom, ep_rx, ep_tx));
        s.spawn(|| {
            let (_intf, ep_in, ep_out, _if_num) = open_host_device(vid, pid);
            run_host_bulk(ep_in, ep_out, SYNC_ROUNDS);
            println!("host: all transfers complete");
        });
    });

    thread::sleep(Duration::from_millis(500));
    reg.remove().unwrap();
}
