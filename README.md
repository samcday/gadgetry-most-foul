gadgetry-most-foul
==========

[![crates.io page](https://img.shields.io/crates/v/gadgetry-most-foul)](https://crates.io/crates/gadgetry-most-foul)
[![docs.rs page](https://docs.rs/gadgetry-most-foul/badge.svg)](https://docs.rs/gadgetry-most-foul)
[![Apache 2.0 license](https://img.shields.io/crates/l/gadgetry-most-foul)](https://github.com/samcday/gadgetry-most-foul/blob/master/LICENSE)

This library allows implementation of USB peripherals, so called **USB gadgets**,
on Linux devices that have a USB device controller (UDC).
Both, pre-defined USB functions and fully custom implementations of the USB
interface are supported.

The following pre-defined USB functions, implemented by kernel drivers, are available:

* network interface
    * CDC ECM
    * CDC ECM (subset)
    * CDC EEM
    * CDC NCM
    * RNDIS
* serial port
    * CDC ACM
    * generic
* human interface device (HID)
* mass-storage device (MSD)
* printer device
* musical instrument digital interface (MIDI)
* audio device (UAC1 and UAC2)
* video device (UVC)

In addition fully custom USB functions can be implemented in user-mode Rust code.

Support for OS-specific descriptors and WebUSB is also provided.

Features
--------

This crate provides the following optional features:

* `tokio`: enables async support for custom USB functions on top of the Tokio runtime.

Requirements
------------

The minimum supported Rust version (MSRV) is 1.77.

A USB device controller (UDC) supported by Linux is required. Normally, standard
PCs *do not* include an UDC.
A Raspberry Pi 4 contains an UDC, which is connected to its USB-C port.

The following Linux kernel configuration options should be enabled for full functionality:

  * `CONFIG_USB_GADGET`
  * `CONFIG_USB_CONFIGFS`
  * `CONFIG_USB_CONFIGFS_SERIAL`
  * `CONFIG_USB_CONFIGFS_ACM`
  * `CONFIG_USB_CONFIGFS_NCM`
  * `CONFIG_USB_CONFIGFS_ECM`
  * `CONFIG_USB_CONFIGFS_ECM_SUBSET`
  * `CONFIG_USB_CONFIGFS_RNDIS`
  * `CONFIG_USB_CONFIGFS_EEM`
  * `CONFIG_USB_CONFIGFS_MASS_STORAGE`
  * `CONFIG_USB_CONFIGFS_F_FS`
  * `CONFIG_USB_CONFIGFS_F_HID`
  * `CONFIG_USB_CONFIGFS_F_PRINTER`
  * `CONFIG_USB_CONFIGFS_F_MIDI`
  * `CONFIG_USB_CONFIGFS_F_UAC1`
  * `CONFIG_USB_CONFIGFS_F_UAC2`
  * `CONFIG_USB_CONFIGFS_F_UVC`

root permissions are required to configure USB gadgets on Linux and
the `configfs` filesystem needs to be mounted.


License
-------

gadgetry-most-foul is licensed under the [Apache 2.0 license].

[Apache 2.0 license]: https://github.com/samcday/gadgetry-most-foul/blob/master/LICENSE

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in gadgetry-most-foul by you, shall be licensed as Apache 2.0, without any
additional terms or conditions.
