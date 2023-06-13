// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{bsp::Bsp, SlotId};

// Gimletlet adapter -> RoT and PMOD expansion board configuration
//
// J4 (USART)
// - Pin 4: FC0_RXD => PIO0_29
// - Pin 5: FC0_TXD => PIO0_30
//
// J5 (AUX) - PMOD 4x LED board
// - Pin 3: PIO0_4 - fault indicator
// - Pin 4: PIO0_25 - unused
// - Pin 5: PIO0_22 - slot A chosen
// - Pin 6: FC3_RTS_SCLX_SSEL1 => PIO0_21 - slot B chosen
//
// J6 (SPI) - PMOD 4x pushbutton board
// - Pin 3: FC3_SCK => PIO0_6 => Override: prefer slot A
// - Pin 4: FC3_TXD_SCL_MISO => PIO0_2 => Override: prefer slot B
// - Pin 5: FC3_RXD_SDA_MOSI => PIO0_3 => unused
// - Pin 6: FC3_CTX_SDAX_SSEL0 => PIO0_20 => unused

pub struct Board;

impl Bsp for Board {
    fn configure(iocon: &lpc55_pac::IOCON, _gpio: &lpc55_pac::GPIO) {
        // Make our override buttons digital inputs with pulldowns.
        iocon.pio0_2.modify(|_, w| {
            w.digimode().set_bit();
            w.mode().pull_down();
            w
        });
        iocon.pio0_6.modify(|_, w| {
            w.digimode().set_bit();
            w.mode().pull_down();
            w
        });
    }

    fn indicate_fault(gpio: &lpc55_pac::gpio::RegisterBlock) {
        // Switch fault pin to output and drive it high.
        gpio.dirset[0].write(|w| unsafe { w.bits(1 << 4) });
        gpio.set[0].write(|w| unsafe { w.bits(1 << 4) });
    }

    fn indicate_boot_choice(slot: SlotId, gpio: &lpc55_pac::GPIO) {
        // Both slot indicator pins are on PIO0 at different locations:
        let pin = match slot {
            SlotId::A => 22,
            SlotId::B => 21,
        };
        // Switch pin to output and drive high.
        gpio.dirset[0].write(|w| unsafe { w.bits(1 << pin) });
        gpio.set[0].write(|w| unsafe { w.bits(1 << pin) });
    }

    fn check_override(gpio: &lpc55_pac::GPIO) -> Option<SlotId> {
        if gpio.b[0].b_[6].read().bits() != 0 {
            Some(SlotId::A)
        } else if gpio.b[0].b_[2].read().bits() != 0 {
            Some(SlotId::B)
        } else {
            None
        }
    }
}
