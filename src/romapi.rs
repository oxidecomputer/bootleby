// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use num_derive::FromPrimitive;

#[repr(C)]
#[derive(Default, Debug)]
struct StandardVersion {
    bugfix: u8,
    minor: u8,
    major: u8,
    name: u8,
}

// Both SkbootStatus and SecureBool are defined in the NXP manual

#[repr(u32)]
#[derive(Debug, FromPrimitive, PartialEq)]
pub enum SkbootStatus {
    Success = 0x5ac3c35a,
    Fail = 0xc35ac35a,
    InvalidArgument = 0xc35a5ac3,
    KeyStoreMarkerInvalid = 0xc3c35a5a,
}

#[repr(u32)]
#[derive(Debug, FromPrimitive, PartialEq)]
pub enum SecureBool {
    SecureFalse = 0x5aa55aa5,
    SecureTrue = 0xc33cc33c,
    TrackerVerified = 0x55aacc33,
}

#[repr(C)]
struct FlashDriverInterface {
    /// This is technically a union for the v0 vs v1 ROM but we only care
    /// about the v1 on the Expresso board
    version1_flash_driver: &'static [u8; 0], // stubbed
}

#[repr(C)]
pub struct SKBootFns {
    pub skboot_authenticate: unsafe extern "C" fn(
        start_addr: *const u32,
        is_verified: *mut u32,
    ) -> u32,
    pub skboot_hashcrypt_irq_handler: unsafe extern "C" fn() -> (),
}

#[repr(C)]
pub struct BootloaderTree {
    /// Function to start the bootloader executing
    bootloader_fn: unsafe extern "C" fn(*const u8),
    /// Bootloader version
    version: StandardVersion,
    /// Actually a C string but we don't have that in no-std
    pub copyright: u32,
    reserved: u32,
    /// Functions for reading/writing to flash
    flash_driver: FlashDriverInterface,
    /// Functions for working with signed capsule updates
    iap_driver: &'static [u8; 0], // stubbed
    reserved1: u32,
    reserved2: u32,
    /// Functions for low power settings, used in conjunction with a
    /// binary shared lib, (might add function prototypes later)
    low_power: u32,
    /// Functions for PRINCE encryption, currently not implemented
    crypto: u32,
    /// Functions for checking signatures on images
    pub skboot: &'static SKBootFns,
}

extern "C" {
    static BOOTLOADER_TREE: BootloaderTree;
}

pub fn bootloader_tree() -> &'static BootloaderTree {
    unsafe {
        &BOOTLOADER_TREE
    }
}
