//! Pipelined synchronous transfer test (read_exact_timeout / write_all_timeout).
use nusb::transfer::{ControlIn, ControlOut, ControlType, Recipient};
use std::{
    io::ErrorKind,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use gadgetry_most_foul::function::custom::Custom;

use super::*;

const ROUNDS: usize = 64;
const VID: u16 = 0x1234;
const PID: u16 = 0x0020;

/// Device side: pipelined exact IO with read_exact_timeout / write_all_timeout.
fn run_device_pipelined(
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
            while !stop_rx.load(Ordering::Relaxed) {
                let mut data = vec![0; size];
                match ep_rx.read_exact_timeout(&mut data, Duration::from_secs(2)) {
                    Ok(()) => {
                        assert!(
                            data.iter().all(|&x| x == expected),
                            "device recv: expected all 0x{expected:02x}, got {:02x?}",
                            &data[..data.len().min(16)]
                        );
                        expected = expected.wrapping_add(1);
                    }
                    Err(e) if e.kind() == ErrorKind::TimedOut => {}
                    Err(e) if stop_rx.load(Ordering::Relaxed) => {
                        println!("device recv stopped: {e}");
                        break;
                    }
                    Err(e) => panic!("device recv error: {e}"),
                }
            }
        });

        s.spawn(move || {
            let size = PACKET_SIZE;
            let mut b = 0u8;
            while !stop_tx.load(Ordering::Relaxed) {
                let data = vec![b; size];
                match ep_tx.write_all_timeout(&data, Duration::from_secs(2)) {
                    Ok(()) => b = b.wrapping_add(1),
                    Err(e) if e.kind() == ErrorKind::TimedOut => {}
                    Err(e) if stop_tx.load(Ordering::Relaxed) => {
                        println!("device send stopped: {e}");
                        break;
                    }
                    Err(e) => panic!("device send error: {e}"),
                }
            }
        });

        run_device_events(&mut custom, &stop, true);
    });
}

/// Host side for the pipelined test: control echo + bulk transfers + STOP.
pub(super) fn run_host_pipelined() {
    let (vid, pid) = (VID, PID);
    let (intf, ep_in, ep_out, if_num) = open_host_device(vid, pid);

    // --- Control transfer test ---
    let test_data: Vec<u8> = (0..64).collect();
    intf.control_out(
        ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Interface,
            request: req::ECHO,
            value: 0,
            index: if_num.into(),
            data: &test_data,
        },
        Duration::from_secs(2),
    )
    .wait()
    .expect("host: control out failed");

    let reply = intf
        .control_in(
            ControlIn {
                control_type: ControlType::Vendor,
                recipient: Recipient::Interface,
                request: req::ECHO,
                value: 0,
                index: if_num.into(),
                length: test_data.len() as u16,
            },
            Duration::from_secs(2),
        )
        .wait()
        .expect("host: control in failed");
    assert_eq!(reply.as_slice(), test_data.as_slice(), "host: control echo mismatch");
    println!("host: control echo OK ({} bytes)", test_data.len());

    // --- Bulk transfers ---
    run_host_bulk(ep_in, ep_out, ROUNDS);

    // Signal device to stop.
    intf.control_out(
        ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Interface,
            request: req::STOP,
            value: 0,
            index: if_num.into(),
            data: &[],
        },
        Duration::from_secs(2),
    )
    .wait()
    .expect("host: stop control failed");

    println!("host: all transfers complete");
}

#[test]
#[serial]
fn transfer() {
    init();

    if skip_host() {
        return;
    }

    let (vid, pid) = (VID, PID);
    let (reg, custom, ep_rx, ep_tx) = setup_gadget_with_id(vid, pid, "transfer test device", "transfer-test-001");

    thread::scope(|s| {
        s.spawn(|| run_device_pipelined(custom, ep_rx, ep_tx));
        s.spawn(run_host_pipelined);
    });

    thread::sleep(Duration::from_millis(500));
    reg.remove().unwrap();
}
