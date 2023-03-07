// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Types and hooks for implementing Board Support Packages (BSPs) for stage0.
//!
//! The stage0 BSP requirements are very simple, since for the most part, stage0
//! doesn't care about the board. The exact properties that need to be described
//! are in the `Bsp` trait below.
//!
//! To implement a BSP:
//!
//! 1. Create a module within `stage0::bsp` named after your board.
//! 2. Define a type in the module called `Board`. This type will never be
//!    instantiated, so it can be arbitrary; an empty enum is easy.
//! 3. Implement `stage0::bsp::Bsp` for your `Board` type.
//! 4. Add a `target-board-*` feature to `Cargo.toml`.
//! 5. Add a branch to the `cfg_if` in `src/bin/stage0.rs` to detect your board
//!    and select the right `Board` type.

// Note that these modules are not conditionally included. We always compile
// every BSP because we can currently get away with that -- none are mutually
// exclusive or need different build settings -- and this helps to ensure that
// everything actually builds.
//
// We may have to stop doing this eventually but it's nice for now.
pub mod rot_carrier;
pub mod lpc55xpresso;
pub mod gimlet;

use crate::SlotId;

/// Requirements placed upon a BSP type.
pub trait Bsp {
    /// Set up any I/Os needed for the board.
    fn configure(iocon: &lpc55_pac::IOCON, gpio: &lpc55_pac::GPIO);

    /// Indicate a boot failure. No information is provided as to _what_
    /// failure, because generally speaking we only have one bit of output.
    fn indicate_fault(gpio: &lpc55_pac::gpio::RegisterBlock);
    /// Indicate that a particular slot has been chosen for boot.
    ///
    /// This is only useful on eval boards with extra LEDs; production
    /// configurations don't have outputs for this, so by default this method is
    /// stubbed out.
    fn indicate_boot_choice(_slot: SlotId, _gpio: &lpc55_pac::GPIO) {}
    /// Checks to see if a user image selection override is in force.
    ///
    /// This is an eval board feature; in production builds we expect to use the
    /// default impl of this, which returns `None` (meaning no override is
    /// possible).
    fn check_override(_gpio: &lpc55_pac::GPIO) -> Option<SlotId> { None }
}
