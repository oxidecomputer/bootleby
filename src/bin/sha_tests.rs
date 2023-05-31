// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Tests for the SHA256 and HMAC-SHA256 implementations.
//!
//! This produces a binary that is intended to run on the LPC55-Gimletlet
//! Adapter for the RoT carrier board, though it mostly just assumes which pins
//! the LEDs are on (PIO0_15 and PIO0_31).
//!
//! The test suite completes in well under 100ms, leaving the LEDs/pins in one
//! of the following states:
//!
//! ```text
//! PIO0_15   PIO0_31   Interpretation
//! -------   -------   --------------
//! low       low       tests not starting or hung early
//! high      low       hung during test, stopped at a breakpoint?
//! high      high      TESTS PASSED
//! low       high      test failed (panic or fault)
//! ```

#![no_std]
#![no_main]

use bootleby::sha256;

use cortex_m_rt::{entry, exception, ExceptionFrame};
use hex_literal::hex;
use zerocopy::AsBytes;

#[entry]
fn main() -> ! {
    let p = lpc55_pac::Peripherals::take().unwrap();

    // Set up the two LEDs on the carrier board. These are on PIO0_15 and
    // PIO0_31. They are active HIGH so we'll leave them off for now.
    for pin in [15, 31] {
        p.GPIO.dirset[0].write(|w| unsafe { w.bits(1 << pin) });
    }
    // Go ahead and light one of them to signal that we've booted.
    p.GPIO.w[0].w_[15].write(|w| unsafe { w.pword().bits(!0) });

    do_sha256_tests(&p);
    do_hmac_tests(&p);

    // Light the _other_ LED to show success.
    p.GPIO.w[0].w_[31].write(|w| unsafe { w.pword().bits(!0) });

    loop {
        cortex_m::asm::nop(); // tests passed! spin forever
    }
}

fn do_sha256_tests(p: &lpc55_pac::Peripherals) {
    static FIXTURES: &[(&[u8], &[u8])] = &[
        (
            b"",
            &hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ),
        (
            b"abcd",
            &hex!("88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"),
        ),
        (
            b"the quick brown fox jumps over the lazy dog.",
            &hex!("18e8d559417db8a93707c11b11bb90b56638049a5994006ed4b2705e4d86587f"),
        ),
    ];

    for (input, expected) in FIXTURES {
        sha256_test(p, input, expected);
    }
}

fn sha256_test(p: &lpc55_pac::Peripherals, input: &[u8], expected: &[u8]) {
    let mut h = sha256::Hasher::begin(&p.SYSCON, &p.HASHCRYPT);
    for word in input.chunks_exact(4) {
        h.update(&[u32::from_le_bytes(word.try_into().unwrap())], 0);
    }
    let result = h.finish();
    let result = result.as_bytes();
    assert_eq!(result, expected);
}

#[repr(align(4))]
struct WordAligned<const N: usize>([u8; N]);

#[inline(never)] // for GDB's stack traces
fn do_hmac_tests(p: &lpc55_pac::Peripherals) {
    // RFC 4231 Test Case 1
    hmac_test(
        p,
        &hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        &WordAligned(*b"Hi There").0,
        &hex!("b0344c61d8db38535ca8afceaf0bf12b 881dc200c9833da726e9376c2e32cff7"),
    );
    // RFC 4231 Test Case 2
    hmac_test(
        p,
        b"Jefe",
        &WordAligned(*b"what do ya want for nothing?").0,
        &hex!("5bdcc146bf60754e6a042426089575c7 5a003f089d2739839dec58b964ec3843"),
    );
}

#[inline(never)] // for GDB's stack traces
fn hmac_test(p: &lpc55_pac::Peripherals, key: &[u8], input: &[u8], expected: &[u8]) {
    // Pack key into array. Left-pad with zeros if the test vector key is too
    // short.
    let mut key_words = [0; 32 / 4];
    for (dest, word) in key_words.iter_mut().zip(key.chunks_exact(4)) {
        *dest = u32::from_le_bytes(word.try_into().unwrap());
    }

    // Verify that input is word-aligned and a multiple of four.
    let input_words = zerocopy::LayoutVerified::<_, [u32]>::new_slice(input).unwrap();

    let result = sha256::hmac(&p.SYSCON, &p.HASHCRYPT, &key_words, &input_words);
    let result = result.as_bytes();
    assert_eq!(result, expected);
}

#[panic_handler]
fn panic_handler(_: &core::panic::PanicInfo) -> ! {
    // Trigger an explicit breakpoint. The effect of this depends on whether a
    // debugger is attached.
    // - If so, it will halt and wait for debugger intercession.
    // - If not, it will escalate to a HardFault and trigger the routine below.
    loop {
        cortex_m::asm::bkpt();
        // This is reachable only if you resume in a debugger.
    }
}

#[exception]
unsafe fn HardFault(_ef: &ExceptionFrame) -> ! {
    // Safety: the GPIO peripheral is static, and we're not racing anyone by
    // definition since we're in the process of panicking to a halt.
    let gpio = unsafe { &*lpc55_pac::GPIO::ptr() };

    // Switch which LED is lit to indicate failure.
    gpio.w[0].w_[15].write(|w| unsafe { w.pword().bits(0) });
    gpio.w[0].w_[31].write(|w| unsafe { w.pword().bits(!0) });

    // Spin
    loop {
        cortex_m::asm::bkpt();
    }
}
