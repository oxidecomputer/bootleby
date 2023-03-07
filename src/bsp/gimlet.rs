// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// BSP for Gimlet (revs B, C, D, ...)
///
/// This is the simplest BSP since it has no useful affordances like LEDs.

use super::Bsp;

pub struct Board;

impl Bsp for Board {
    fn configure(_iocon: &lpc55_pac::IOCON, _gpio: &lpc55_pac::GPIO) {
        // Nothing to do here. Fault line has a pullup. We will drive it low
        // only on fault, and leave it unconfigured on normal boot.
    }

    fn indicate_fault(gpio: &lpc55_pac::gpio::RegisterBlock) {
        // Switch fault pin to output. It is already set to low by default.
        gpio.dirset[0].write(|w| unsafe { w.bits(1 << 17) });
    }
}

