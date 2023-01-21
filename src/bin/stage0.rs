#![no_std]
#![no_main]

use stage0::{romapi, sha256, SLOT_SIZE_WORDS};

use cortex_m_rt::entry;
use lpc55_pac::interrupt;

/// Bootloader entry point. These are not the first instructions executed, since
/// we rely on `cortex_m_rt::entry` to do the equivalent of crt0 before we get
/// control.
#[entry]
fn main() -> ! {
    // Safety: This is sound as long as (1) `steal` only happens once, and (2)
    // none of the correctness of the rest of the code relies on peripherals
    // being uniquely held. The first part we can ensure by putting this at the
    // top of `main`, which `entry` makes hard to reentrantly call in safe code.
    // The second one is architectural but holds due to our design.
    let p = unsafe { lpc55_pac::Peripherals::steal() };

    // Make the USER button a digital input.
    p.IOCON.pio1_9.modify(|_, w| w.digimode().set_bit());

    let a_ok = stage0::verify_image(&p.FLASH, image_a());
    let b_ok = stage0::verify_image(&p.FLASH, image_b());

    let choice = match (a_ok, b_ok) {
        (Some(img), None) => img,
        (None, Some(img)) => img,
        (Some(img_a), Some(img_b)) => {
            // Break ties based on the state of the USER button (0 means
            // depressed)
            if p.GPIO.b[1].b_[9].read().bits() == 0 {
                // button is held
                img_b
            } else {
                img_a
            }
        }
        _ => panic!(),
    };

    sha256::update_cdi(&p.SYSCON, &p.HASHCRYPT, choice);
    boot_into(choice)
}

#[panic_handler]
fn panic_handler(_: &core::panic::PanicInfo) -> ! {
    // Safety: the GPIO peripheral is static, and we're not racing anyone by
    // definition since we're in the process of panicking to a halt.
    let gpio = unsafe { &*lpc55_pac::GPIO::ptr() };
    // Turn on the RED LED on the xpresso board.
    gpio.dir[1].write(|w| unsafe { w.bits(1 << 6) });

    // Park!
    loop {
        cortex_m::asm::bkpt();
    }
}

fn boot_into(
    image: &'static [u32],
) -> ! {
    //todo!("turn off peripherals");

    // The NXP image header is _also_ a Cortex-M vector table, stuffing things
    // into reserved places. So we can derive the correct boot values for the
    // SP, PC, and VTOR in the normal way:
    let (reset, stack, vtor) = (image[1], image[0], image.as_ptr() as u32);

    // And away we go!
    //
    // This block is responsible for preparing the execution environment for the
    // next program, so, putting the processor state back to defaults and
    // interpreting the program's header and vector table to figure out what to
    // run.
    unsafe {
        core::arch::asm!(
            "
                @ From the perspective of this program, we're never leaving
                @ this asm block. This means we can trash Rust invariants.

                @ Scribble our memory. Note that this destroys our stack! We
                @ can't refer to any stack-allocated anything from here on.
                movw r3, #:lower16:__start_of_ram
                movt r3, #:upper16:__start_of_ram
                movw r4, #:lower16:__end_of_ram
                movt r4, #:upper16:__end_of_ram
                movs r5, #0

            1:  str r5, [r3], #4
                cmp r3, r4
                bne 1b

                @ Move the vector table location to the image's table.
                @ Note that this means we can't do anything that might
                @ fault (other than the jump into the image) from here
                @ on.
                movw r3, #:lower16:0xE000ED08
                movt r3, #:upper16:0xE000ED08

                str r2, [r3]

                @ Clear our registers except the ones containing data
                @ controlled by the image. Disclosing that data is fine.
                @
                @ We can move an immediate zero into any of r0-r7 using a
                @ simple MOV-immediate instruction (2 bytes), but accessing
                @ r8+ in this manner costs 4 bytes instead of 2. However,
                @ moving a value from a low register to high is still 2
                @ bytes. And so:
                movs r3, #0
                movs r4, #0
                movs r5, #0
                movs r6, #0
                movs r7, #0

                mov r8, r7
                mov r9, r7
                mov r10, r7
                mov r11, r7
                mov r12, r7
                @ r13 = stack pointer, handled below.
                mov r14, r7   @ LR

                @ Set the stack pointer to the location the image wants.
                msr MSP, r1

                @ Jump into the image. We're using a simple BX here so that
                @ we remain in secure mode.
                @
                @ We checked the reset vector as part of validation, so we
                @ know this isn't going to result in an _immediate_ bus
                @ fault or usage fault. The main remaining failure case is
                @ if the first instruction in the image isn't valid. An
                @ ARM disassembler seems out of scope for stage0, so this
                @ failure can happen.
                bx r0
            ",

            // NOTE: because this asm block destroys RAM early on,
            // every parameter fed in here must be a *value* in a
            // register. If you find yourself passing an *address*
            // things are going to get weird for you.
            in("r0") reset,
            in("r1") stack,
            in("r2") vtor,

            options(noreturn),
        )
    }
}

// Image regions, placed by the linker script.
extern "C" {
    static IMAGE_A: [u32; SLOT_SIZE_WORDS];
    static IMAGE_B: [u32; SLOT_SIZE_WORDS];
}

/// Produces a reference to the A-slot image.
fn image_a() -> &'static [u32; SLOT_SIZE_WORDS] {
    // Safety: In general accessing extern statics is unsafe because Rust can't
    // guarantee that the other code -- because extern implies the presence of
    // other code -- will refrain from e.g. mutating the data, which would break
    // the & rules.
    //
    // In this case, what other code exists is just going to verify this, and
    // isn't going to write it, so we can hand out references willy-nilly.
    unsafe {
        &IMAGE_A
    }
}

/// Produces a reference to the B-slot image.
fn image_b() -> &'static [u32; SLOT_SIZE_WORDS] {
    // Safety: see discussion in `image_a` above.
    unsafe {
        &IMAGE_B
    }
}

/// Interrupt handler for HASHCRYPT.
///
/// The ROM uses the hash/crypto peripherals when doing image authentication, to
/// speed things along. As a side effect, it requires the user to route this
/// interrupt into the ROM handler, whose address is available in the skboot
/// table.
#[interrupt]
fn HASHCRYPT() {
    // Safety: Yeah, this is hella unsafe, we're calling into the ROM. Since
    // this handler is basically being used as a callback while the ROM has
    // control, it's not any _more_ unsafe than calling into the ROM routine in
    // the first place.
    unsafe {
        (romapi::bootloader_tree().skboot.skboot_hashcrypt_irq_handler)();
    }
}