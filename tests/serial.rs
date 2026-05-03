use std::os::unix::prelude::FileTypeExt;

use gadgetry_most_foul::function::serial::{Serial, SerialClass};
use serial_test::serial;

mod common;
use common::*;

fn serial(serial_class: SerialClass) {
    init();

    let mut builder = Serial::builder(serial_class);
    builder.console = Some(false);
    let (serial, func) = builder.build();

    let reg = reg(func);
    let tty = serial.tty().unwrap();

    println!("Serial device {} function at {}", tty.display(), serial.status().path().unwrap().display());

    assert!(tty.metadata().unwrap().file_type().is_char_device());

    check_host(|_device, cfg| {
        match serial_class {
            SerialClass::Acm => {
                // CDC ACM: class 2 (Communications), subclass 2 (ACM).
                let cdc_intf =
                    cfg.interface_alt_settings().find(|desc| desc.class() == 2 && desc.subclass() == 2);
                assert!(cdc_intf.is_some(), "no CDC ACM interface (class 2, subclass 2) found on host");
                let cdc_intf = cdc_intf.unwrap();
                println!(
                    "CDC ACM interface {}: class={}, subclass={}, protocol={}",
                    cdc_intf.interface_number(),
                    cdc_intf.class(),
                    cdc_intf.subclass(),
                    cdc_intf.protocol(),
                );

                // CDC Data interface: class 10.
                let data_intf = cfg.interface_alt_settings().find(|desc| desc.class() == 10);
                assert!(data_intf.is_some(), "no CDC Data interface (class 10) found on host");
            }
            SerialClass::Generic => {
                // Generic serial: vendor-specific class 255.
                let vendor_intf = cfg.interface_alt_settings().find(|desc| desc.class() == 255);
                assert!(vendor_intf.is_some(), "no vendor-specific interface (class 255) found on host");
                let vendor_intf = vendor_intf.unwrap();
                println!(
                    "generic serial interface {}: class={}, subclass={}, protocol={}",
                    vendor_intf.interface_number(),
                    vendor_intf.class(),
                    vendor_intf.subclass(),
                    vendor_intf.protocol(),
                );
            }
            _ => {}
        }
    });

    if unreg(reg).unwrap() {
        assert!(serial.status().path().is_none());
        assert!(serial.tty().is_err());
    }
}

#[test]
#[serial]
fn acm() {
    serial(SerialClass::Acm)
}

#[test]
#[serial]
fn generic_serial() {
    serial(SerialClass::Generic)
}
