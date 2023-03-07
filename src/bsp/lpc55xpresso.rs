// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{bsp::Bsp, SlotId};

pub struct Board;

impl Bsp for Board {
    fn configure(iocon: &lpc55_pac::IOCON, _gpio: &lpc55_pac::GPIO) {
        // Set the USER button to digital input for override.
        iocon.pio1_9.modify(|_, w| w.digimode().set_bit());
    }

    fn indicate_fault(gpio: &lpc55_pac::gpio::RegisterBlock) {
        // The red LED is active low and connected to PIO1_6. We can activate it
        // by flipping the pin direction, exploiting the fact that pins will
        // default to low if not overridden.
        gpio.dir[1].modify(|_, w| unsafe { w.bits(1 << 6) });
    }

    fn indicate_boot_choice(slot: SlotId, gpio: &lpc55_pac::GPIO) {
        // LEDs are active low. Blue is on PIO0_31, green is on PIO0_15. We will
        // use green for A and blue for B.
        let index = match slot {
            SlotId::A => 15,
            SlotId::B => 31,
        };
        gpio.dir[0].modify(|_, w| unsafe { w.bits(1 << index) });
    }

    fn check_override(gpio: &lpc55_pac::GPIO) -> Option<SlotId> {
        // There is a single useful button on this board. We implement it as a
        // "choose slot B" override. This means if slot B is the default choice,
        // the button does nothing. So it goes.
        if gpio.b[1].b_[9].read().bits() == 0 {
            // Button is active low, this means it is held down
            Some(SlotId::B)
        } else {
            None
        }
    }
}
