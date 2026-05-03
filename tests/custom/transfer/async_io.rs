//! Async transfer test (read_exact_async / write_all_async with tokio).
use std::{sync::Arc, time::Duration};

use nusb::transfer::{Buffer, ControlIn, ControlOut, ControlType, Recipient};

use gadgetry_most_foul::function::custom::Event;

use super::*;

const VID: u16 = 0x1234;
const PID: u16 = 0x0020;
const ASYNC_TRANSFER_SIZE: usize = 32 * 1024;
const ASYNC_ROUNDS: usize = 8;

async fn run_device_async(
    mut custom: Custom, mut ep_rx: gadgetry_most_foul::function::custom::EndpointOut,
    mut ep_tx: gadgetry_most_foul::function::custom::EndpointIn,
) {
    use tokio::io::{unix::AsyncFd, Interest};
    use tokio::sync::Notify;

    let stop = Arc::new(Notify::new());

    let stop_rx = stop.clone();
    let rx_task = tokio::spawn(async move {
        let size = ASYNC_TRANSFER_SIZE;
        let mut expected = 0u8;
        loop {
            tokio::select! {
                result = async {
                    let mut data = vec![0; size];
                    ep_rx.read_exact_async(&mut data).await?;
                    Ok::<_, std::io::Error>(data)
                } => {
                    match result {
                        Ok(data) => {
                            assert!(
                                data.iter().all(|&x| x == expected),
                                "device async recv: expected all 0x{expected:02x}, got {:02x?}",
                                &data[..data.len().min(16)]
                            );
                            expected = expected.wrapping_add(1);
                        }
                        Err(e) => {
                            println!("device async recv stopped: {e}");
                            break;
                        }
                    }
                }
                _ = stop_rx.notified() => break,
            }
        }
    });

    let stop_tx = stop.clone();
    let tx_task = tokio::spawn(async move {
        let size = ASYNC_TRANSFER_SIZE;
        let mut b = 0u8;
        loop {
            let data = vec![b; size];
            tokio::select! {
                result = async { ep_tx.write_all_async(&data).await } => {
                    match result {
                        Ok(()) => b = b.wrapping_add(1),
                        Err(e) => {
                            println!("device async send stopped: {e}");
                            break;
                        }
                    }
                }
                _ = stop_tx.notified() => break,
            }
        }
    });

    // Event loop: handle control requests.
    let event_fd = AsyncFd::with_interest(custom.fd().expect("device event fd failed"), Interest::READABLE)
        .expect("device event fd registration failed");
    let mut ctrl_data = Vec::new();
    let mut stopped = false;
    while !stopped {
        let Ok(mut guard) = event_fd.readable().await else {
            break;
        };
        guard.clear_ready();
        drop(guard);

        match custom.try_event() {
            Ok(Some(event)) => match event {
                Event::SetupHostToDevice(req) => {
                    if req.ctrl_req().request == req::STOP {
                        stopped = true;
                    }
                    ctrl_data = req.recv_all().unwrap();
                }
                Event::SetupDeviceToHost(req) if req.ctrl_req().request == req::ECHO => {
                    req.send(&ctrl_data).unwrap();
                }
                _ => {}
            },
            Ok(None) => continue,
            Err(e) => {
                if !stopped {
                    panic!("device async event error: {e}");
                }
                break;
            }
        }
    }

    stop.notify_waiters();
    let _ = rx_task.await;
    let _ = tx_task.await;
}

fn run_host_async() {
    let (intf, mut ep_in, mut ep_out, if_num) = open_host_device(VID, PID);

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

    for i in 0..ASYNC_ROUNDS {
        let expected = i as u8;

        let c = ep_out.transfer_blocking(vec![expected; ASYNC_TRANSFER_SIZE].into(), Duration::from_secs(2));
        c.status.expect("host: async OUT transfer failed");

        let c = ep_in.transfer_blocking(Buffer::new(ASYNC_TRANSFER_SIZE), Duration::from_secs(2));
        c.status.expect("host: async IN transfer failed");
        assert_eq!(c.actual_len, ASYNC_TRANSFER_SIZE, "host: async IN transfer length mismatch");
        assert!(
            c.buffer[..c.actual_len].iter().all(|&x| x == expected),
            "host: async IN transfer {i}: expected all 0x{expected:02x}, got {:02x?}",
            &c.buffer[..c.actual_len.min(16)]
        );
    }

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
}

#[tokio::test]
#[serial]
async fn transfer_async() {
    init();

    if skip_host() {
        return;
    }

    let (vid, pid) = (VID, PID);
    let (reg, custom, ep_rx, ep_tx) = setup_gadget_with_id(vid, pid, "transfer test device", "transfer-test-001");

    let host = tokio::task::spawn_blocking(run_host_async);
    run_device_async(custom, ep_rx, ep_tx).await;
    host.await.unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;
    reg.remove().unwrap();
}
