//! ZLP (Zero-Length Packet) tests for issue #17.
//!
//! Each test sets up a gadget and runs both device and host sides
//! in separate threads within the same process.

use nusb::{
    transfer::{Buffer, Bulk, Direction, In, Out},
    MaybeFuture,
};
use std::{
    io::ErrorKind,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use gadgetry_most_foul::{
    default_udc,
    function::custom::{Custom, Endpoint, EndpointDirection, EndpointIn, EndpointOut, Interface},
    Class, Config, Gadget, Id, Strings,
};

use crate::common::*;
use serial_test::serial;

const TIMEOUT: Duration = Duration::from_secs(5);
const VID: u16 = 0x1234;
const PID: u16 = 0x0010;

/// Sets up a custom USB gadget with one bulk IN and one bulk OUT endpoint.
fn setup_gadget() -> (gadgetry_most_foul::RegGadget, Custom, EndpointOut, EndpointIn) {
    let (ep_rx, ep_rx_dir) = EndpointDirection::host_to_device();
    let (ep_tx, ep_tx_dir) = EndpointDirection::device_to_host();

    let (custom, handle) = Custom::builder()
        .with_interface(
            Interface::new(Class::vendor_specific(1, 2), "ZLP test interface")
                .with_endpoint(Endpoint::bulk(ep_rx_dir))
                .with_endpoint(Endpoint::bulk(ep_tx_dir)),
        )
        .build();

    let udc = default_udc().expect("cannot get UDC");
    let reg = Gadget::new(
        Class::vendor_specific(255, 0),
        Id::new(VID, PID),
        Strings::new("test", "ZLP test device", "zlp-test-001"),
    )
    .with_config(Config::new("config").with_function(handle))
    .bind(&udc)
    .expect("cannot bind to UDC");

    (reg, custom, ep_rx, ep_tx)
}

/// Opens the ZLP test device on the USB host and claims the interface.
fn open_device() -> (nusb::Interface, nusb::Endpoint<Bulk, In>, nusb::Endpoint<Bulk, Out>, usize, usize) {
    let dev_info = find_device_with_id(VID, PID);
    let device = dev_info.open().wait().expect("cannot open device");
    let cfg = device.active_configuration().expect("no active configuration");

    let mut if_num = None;
    let mut ep_in_addr = None;
    let mut ep_out_addr = None;
    let mut ep_in_mps = 0usize;
    let mut ep_out_mps = 0usize;

    for desc in cfg.interface_alt_settings() {
        for ep in desc.endpoints() {
            match ep.direction() {
                Direction::In => {
                    ep_in_addr = Some(ep.address());
                    ep_in_mps = ep.max_packet_size();
                }
                Direction::Out => {
                    ep_out_addr = Some(ep.address());
                    ep_out_mps = ep.max_packet_size();
                }
            }
            if_num = Some(desc.interface_number());
        }
    }

    let if_num = if_num.expect("no interface found");
    let ep_in_addr = ep_in_addr.expect("no IN endpoint found");
    let ep_out_addr = ep_out_addr.expect("no OUT endpoint found");

    let intf = device.claim_interface(if_num).wait().expect("cannot claim interface");
    let ep_in = intf.endpoint::<Bulk, In>(ep_in_addr).expect("cannot open IN endpoint");
    let ep_out = intf.endpoint::<Bulk, Out>(ep_out_addr).expect("cannot open OUT endpoint");

    (intf, ep_in, ep_out, ep_in_mps, ep_out_mps)
}

/// Runs a minimal device event loop until stop is signaled.
fn run_event_loop(mut custom: Custom, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        match custom.event_timeout(Duration::from_secs(1)) {
            Ok(_) => {}
            Err(_) if stop.load(Ordering::Relaxed) => break,
            Err(_) => {}
        }
    }
}

// ─── Test 1: Receive ZLP with MPS-sized buffer ──────────────────────
//
// Host sends MPS bytes of 0xAA followed by a ZLP.
// Device reads exactly MPS bytes, then verifies the ZLP is rejected as a short exact read.

#[test]
#[serial]
fn zlp_recv_mps_buffer() {
    init();

    if skip_host() {
        return;
    }

    let (reg, custom, mut ep_rx, _ep_tx) = setup_gadget();
    let stop = Arc::new(AtomicBool::new(false));

    thread::scope(|s| {
        let stop_ev = stop.clone();
        s.spawn(move || run_event_loop(custom, stop_ev));

        s.spawn(|| {
            let mps = ep_rx.max_packet_size().unwrap();
            println!("device: RX MPS={mps}, receiving with MPS-sized buffer");

            let mut data = vec![0; mps];
            ep_rx.read_exact_timeout(&mut data, TIMEOUT).expect("recv data failed");
            assert_eq!(data.len(), mps, "expected {mps} bytes, got {}", data.len());
            assert!(data.iter().all(|&b| b == 0xAA), "expected all 0xAA");
            println!("device: read {mps} bytes of 0xAA");

            let mut zlp = vec![0; mps];
            match ep_rx.read_exact_timeout(&mut zlp, TIMEOUT) {
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                    println!("device: ZLP rejected as exact-transfer protocol error");
                }
                Ok(()) => panic!("device: expected ZLP exact read to fail"),
                Err(e) => panic!("device: unexpected ZLP read error: {e}"),
            }
        });

        let stop_host = stop.clone();
        s.spawn(move || {
            let (_intf, _ep_in, mut ep_out, _, ep_out_mps) = open_device();

            let c = ep_out.transfer_blocking(vec![0xAA_u8; ep_out_mps].into(), TIMEOUT);
            c.status.expect("host: send data failed");
            println!("host: sent {ep_out_mps} bytes of 0xAA");

            let c = ep_out.transfer_blocking(Vec::<u8>::new().into(), TIMEOUT);
            c.status.expect("host: send ZLP failed");
            println!("host: sent ZLP");

            thread::sleep(Duration::from_millis(500));
            stop_host.store(true, Ordering::Relaxed);
        });
    });

    thread::sleep(Duration::from_millis(500));
    reg.remove().unwrap();
}

// ─── Test 2: Receive ZLP with oversized buffer (issue #17) ──────────
//
// Host sends MPS bytes of 0xBB followed by a ZLP.
// Device reads with 2×MPS buffer → the positive short completion is progress;
// the ZLP is consumed as a transfer terminator and the remaining exact read
// times out.

#[test]
#[serial]
fn zlp_recv_large_buffer() {
    init();

    if skip_host() {
        return;
    }

    let (reg, custom, mut ep_rx, _ep_tx) = setup_gadget();
    let stop = Arc::new(AtomicBool::new(false));

    thread::scope(|s| {
        let stop_ev = stop.clone();
        s.spawn(move || run_event_loop(custom, stop_ev));

        s.spawn(|| {
            let mps = ep_rx.max_packet_size().unwrap();
            let buf_size = mps * 2;
            println!("device: RX MPS={mps}, receiving with oversized buffer ({buf_size} bytes)");

            let mut data = vec![0; buf_size];
            match ep_rx.read_exact_timeout(&mut data, TIMEOUT) {
                Err(e) if e.kind() == ErrorKind::TimedOut => {
                    println!("device: short packet accepted as progress; remaining exact read timed out");
                }
                Ok(()) => panic!("device: expected oversized exact read to time out"),
                Err(e) => panic!("device: unexpected error: {e}"),
            }
        });

        let stop_host = stop.clone();
        s.spawn(move || {
            let (_intf, _ep_in, mut ep_out, _, ep_out_mps) = open_device();

            let c = ep_out.transfer_blocking(vec![0xBB_u8; ep_out_mps].into(), TIMEOUT);
            c.status.expect("host: send data failed");
            println!("host: sent {ep_out_mps} bytes of 0xBB");

            let c = ep_out.transfer_blocking(Vec::<u8>::new().into(), TIMEOUT);
            c.status.expect("host: send ZLP failed");
            println!("host: sent ZLP");

            // Wait extra time for the device's second recv to time out.
            thread::sleep(Duration::from_secs(3));
            stop_host.store(true, Ordering::Relaxed);
        });
    });

    thread::sleep(Duration::from_millis(500));
    reg.remove().unwrap();
}

// ─── Test 3: Send standalone ZLP ────────────────────────────────────
//
// Device sends a ZLP via write_all(&[]). Host reads and expects 0 bytes.

#[test]
#[serial]
fn zlp_send_empty() {
    init();

    if skip_host() {
        return;
    }

    let (reg, custom, _ep_rx, mut ep_tx) = setup_gadget();
    let stop = Arc::new(AtomicBool::new(false));

    thread::scope(|s| {
        let stop_ev = stop.clone();
        s.spawn(move || run_event_loop(custom, stop_ev));

        s.spawn(move || {
            ep_tx.write_all_timeout(&[], TIMEOUT).expect("device: send ZLP failed");
            println!("device: sent ZLP");
        });

        let stop_host = stop.clone();
        s.spawn(move || {
            let (_intf, mut ep_in, _ep_out, ep_in_mps, _) = open_device();

            let c = ep_in.transfer_blocking(Buffer::new(ep_in_mps), TIMEOUT);
            c.status.expect("host: read failed");
            assert_eq!(c.actual_len, 0, "host: expected ZLP (0 bytes), got {}", c.actual_len);
            println!("host: received ZLP");

            stop_host.store(true, Ordering::Relaxed);
        });
    });

    thread::sleep(Duration::from_millis(500));
    reg.remove().unwrap();
}

// ─── Test 4: Send MPS data followed by ZLP ──────────────────────────
//
// Device sends MPS bytes of 0xDD then a ZLP. Host reads data, then ZLP.

#[test]
#[serial]
fn zlp_send_data_then_zlp() {
    init();

    if skip_host() {
        return;
    }

    let (reg, custom, _ep_rx, mut ep_tx) = setup_gadget();
    let stop = Arc::new(AtomicBool::new(false));

    thread::scope(|s| {
        let stop_ev = stop.clone();
        s.spawn(move || run_event_loop(custom, stop_ev));

        s.spawn(move || {
            let mps = ep_tx.max_packet_size().unwrap();
            ep_tx.write_all_timeout(&vec![0xDD_u8; mps], TIMEOUT).expect("device: send data failed");
            println!("device: sent {mps} bytes of 0xDD");
            ep_tx.write_all_timeout(&[], TIMEOUT).expect("device: send ZLP failed");
            println!("device: sent ZLP");
        });

        let stop_host = stop.clone();
        s.spawn(move || {
            let (_intf, mut ep_in, _ep_out, ep_in_mps, _) = open_device();

            let c = ep_in.transfer_blocking(Buffer::new(ep_in_mps), TIMEOUT);
            c.status.expect("host: read 1 failed");
            assert_eq!(c.actual_len, ep_in_mps, "host: expected {ep_in_mps} bytes, got {}", c.actual_len);
            assert!(c.buffer[..c.actual_len].iter().all(|&b| b == 0xDD), "host: expected all 0xDD");
            println!("host: read {} bytes of 0xDD", c.actual_len);

            let c = ep_in.transfer_blocking(Buffer::new(ep_in_mps), TIMEOUT);
            c.status.expect("host: read 2 failed");
            assert_eq!(c.actual_len, 0, "host: expected ZLP (0 bytes), got {}", c.actual_len);
            println!("host: received ZLP");

            stop_host.store(true, Ordering::Relaxed);
        });
    });

    thread::sleep(Duration::from_millis(500));
    reg.remove().unwrap();
}

// ─── Test 5: Send ZLP via exact write_all_timeout ───────────────────
//
// This verifies that a single exact zero-length write delivers a ZLP.

#[test]
#[serial]
fn zlp_send_single_call() {
    init();

    if skip_host() {
        return;
    }

    let (reg, custom, _ep_rx, mut ep_tx) = setup_gadget();
    let stop = Arc::new(AtomicBool::new(false));

    thread::scope(|s| {
        let stop_ev = stop.clone();
        s.spawn(move || run_event_loop(custom, stop_ev));

        s.spawn(move || {
            let mps = ep_tx.max_packet_size().unwrap();
            ep_tx.write_all_timeout(&vec![0xEE_u8; mps], TIMEOUT).expect("device: write data failed");
            println!("device: sent {mps} bytes of 0xEE via write_all_timeout");

            ep_tx.write_all_timeout(&[], TIMEOUT).expect("device: write ZLP failed");
            println!("device: sent ZLP via single write_all_timeout");
        });

        let stop_host = stop.clone();
        s.spawn(move || {
            let (_intf, mut ep_in, _ep_out, ep_in_mps, _) = open_device();

            let c = ep_in.transfer_blocking(Buffer::new(ep_in_mps), TIMEOUT);
            c.status.expect("host: read 1 failed");
            assert_eq!(c.actual_len, ep_in_mps, "host: expected {ep_in_mps} bytes, got {}", c.actual_len);
            assert!(c.buffer[..c.actual_len].iter().all(|&b| b == 0xEE), "host: expected all 0xEE");
            println!("host: read {} bytes of 0xEE", c.actual_len);

            let c = ep_in.transfer_blocking(Buffer::new(ep_in_mps), TIMEOUT);
            c.status.expect("host: read 2 failed");
            assert_eq!(c.actual_len, 0, "host: expected ZLP (0 bytes), got {}", c.actual_len);
            println!("host: received ZLP from single write_all_timeout call");

            stop_host.store(true, Ordering::Relaxed);
        });
    });

    thread::sleep(Duration::from_millis(500));
    reg.remove().unwrap();
}
