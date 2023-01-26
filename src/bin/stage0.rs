#![no_std]
#![no_main]

use core::sync::atomic::{compiler_fence, Ordering};

use stage0::{romapi, sha256, SlotId, NxpImageHeader};

use cortex_m_rt::{entry, exception, ExceptionFrame};
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
    //
    // You're probably wondering why this is `steal` and not `take`. It's
    // because `take` winds up needing an `unwrap` that is relatively expensive
    // in code size, to check a property that should not be able to fail.
    let p = unsafe { lpc55_pac::Peripherals::steal() };

    // Make the USER button a digital input.
    p.IOCON.pio1_9.modify(|_, w| w.digimode().set_bit());

    let a_ok = stage0::verify_image(&p.FLASH, SlotId::A);
    let b_ok = stage0::verify_image(&p.FLASH, SlotId::B);

    let (header, contents) = match (a_ok, b_ok) {
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

    sha256::update_cdi(&p.SYSCON, &p.HASHCRYPT, contents);
    boot_into(header)
}

#[panic_handler]
fn panic_handler(_: &core::panic::PanicInfo) -> ! {
    // We use a BKPT instruction to wake any attached debugger. If no debugger
    // is attached, BKPT escalates into a HardFault, falling to the handler
    // below. This way we can reuse its fault indication code.
    loop {
        cortex_m::asm::bkpt();
    }
}

#[exception]
unsafe fn HardFault(_ef: &ExceptionFrame) -> ! {
    // Safety: the GPIO peripheral is static, and we're not racing anyone by
    // definition since we're handling a HardFault. So we win.
    let gpio = unsafe { &*lpc55_pac::GPIO::ptr() };
    // Turn on the RED LED on the xpresso board.
    gpio.dir[1].write(|w| unsafe { w.bits(1 << 6) });

    // Spin -- don't use BKPT here because if no debugger is attached it'll
    // escalate to another HardFault and lock the processor.
    loop {
        // This is enough to force LLVM to compile the infinite loop as
        // something other than a UDF, but not enough to generate instructions;
        // using an explicit nop here costs two bytes more.
        compiler_fence(Ordering::SeqCst);
    }
}

fn boot_into(
    header: &'static NxpImageHeader,
) -> ! {
    //todo!("turn off peripherals");

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

                @ Usage of registers established by the parameters to asm!
                @ below:
                @ r0 = target program reset vector
                @ r1 = target program initial stack pointer
                @ r2 = target program vector table address
                @
                @ All other registers are available as temporaries, and we'll
                @ wind up trashing them all one way or another.

                @ Write zeros over our RAM. Note that this destroys our stack!
                @ We can't refer to any stack-allocated anything from here on.
                @ (...not that we were going to.)
                @
                @ r3 = current address
                @ r4 = end address
                @ r5 = zero
                movw r3, #:lower16:__start_of_ram
                movt r3, #:upper16:__start_of_ram
                movw r4, #:lower16:__end_of_ram
                movt r4, #:upper16:__end_of_ram
                movs r5, #0

            1:  str r5, [r3], #4
                cmp r3, r4
                bne 1b

                @ Update the VTOR register to place the vector table in the
                @ target program image.
                @
                @ Note that this means we can't do anything that might
                @ fault (other than the jump into the image) from here
                @ on.
                movw r3, #:lower16:0xE000ED08  @ Get VTOR address into r3
                movt r3, #:upper16:0xE000ED08

                str r2, [r3]

                @ The target program should not assume anything about the
                @ initial contents of its registers except for PC and SP.
                @ Just in case, we'll clear our registers except the ones
                @ that hold values controlled by the target program. Since
                @ it already knows where its reset vector and stack pointer
                @ are, disclosing them is not a problem.
                @
                @ (You may be wondering why we don't clear _all_ registers.
                @ The answer is space: we can save a few bytes by skipping
                @ the image-controlled registers r0-r2.)
                @
                @ We can move an immediate zero into any of r0-r7 using a
                @ simple MOV-immediate instruction (2 bytes), but accessing
                @ r8+ in this manner costs 4 bytes instead of 2. However,
                @ moving a value from a low register to high is still 2
                @ bytes. And so:
                movs r3, #0     @ note: the S in MOVS is required for the
                movs r4, #0     @ 2-byte encoding to be chosen.
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
                @ Strictly speaking we want to set the Main Stack Pointer or
                @ MSP. However, by default SP is an alias of MSP, and we
                @ haven't changed this. MOV SP is two bytes shorter than
                @ MSR MSP.
                mov SP, r1

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
            in("r0") header.reset_vector,
            in("r1") header.initial_stack_pointer,
            in("r2") &header as *const _ as u32,

            options(noreturn),
        )
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
