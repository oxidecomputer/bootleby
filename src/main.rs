#![no_std]
#![no_main]

mod romapi;

use core::sync::atomic::Ordering;

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

    let a_ok = verify_image(&p.FLASH, image_a());
    let b_ok = verify_image(&p.FLASH, image_b());

    #[derive(Copy, Clone, Debug)]
    enum ImageChoice { A, B }

    let choice = match (a_ok, b_ok) {
        (true, false) => ImageChoice::A,
        (false, true) => ImageChoice::B,
        (true, true) => {
            // Break ties based on the state of the USER button (0 means
            // depressed)
            if p.GPIO.b[1].b_[9].read().bits() == 0 {
                // button is held
                ImageChoice::B
            } else {
                ImageChoice::A
            }
        }
        _ => panic!(),
    };

    boot_into(match choice {
        ImageChoice::A => image_a(),
        ImageChoice::B => image_b(),
    })
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

#[inline(never)]
fn verify_image(
    flash: &lpc55_pac::FLASH,
    image: &'static [u32; SLOT_SIZE_WORDS],
) -> bool {
    // Convert the image address to a Flash word number.
    let start_fword = (image.as_ptr() as u32 / 16) & ((1 << 18) - 1);
    // Verify that the _first_ page of the image has been programmed. Without
    // this, we can't load the image size.
    if !is_programmed(flash, start_fword) {
        // Welp, we certainly can't boot an image that's missing its first page.
        return false;
    }

    // Do not permit the compiler to hoist any accesses through `image` above
    // that check.
    core::sync::atomic::compiler_fence(Ordering::SeqCst);

    // Read the image length from word 8. This is within the first page so we're
    // clear to read it.
    let image_length = image[8];

    let image_length_fwords = (image_length + 15) / 16;

    // Verify that every. single. page. of the image is readable, because the
    // ROM doesn't do this despite NXP suggesting it in their app notes.
    for w in start_fword + 1 .. start_fword + image_length_fwords {
        if !is_programmed(flash, w) {
            return false;
        }
    }

    // for good measure:
    core::sync::atomic::compiler_fence(Ordering::SeqCst);

    // Because of our past experience with the implementation quality of the
    // ROM, let's do some basic checks before handing it a blob to inspect,
    // shall we?
    let image_type = image[9];
    {
        // TODO: when we begin requiring secure stage1, we do it here.
        match image_type {
            4 => {
                // Validate that the secondary header offset is in bounds.
                // TODO: we can do better than this:
                let header_offset = image[10];
                if header_offset >= SLOT_SIZE_WORDS as u32 {
                    return false;
                }
            }
            5 => {
                // CRC checksum used by the ROM. It'd be great if the ROM would
                // check this for us, wouldn't it?
                //
                // It won't though.

                // We only CRC the range specified by the image length. We
                // require it to be a multiple of 4 to make our lives easier.
                // The image length is in word 8.
                if image_length > SLOT_SIZE_WORDS as u32 {
                    return false;
                }
                if image_length % 4 != 0 {
                    return false;
                }

                let mut crc = tinycrc::Crc32::new(&crc_catalog::CRC_32_MPEG_2);

                // We want to add in all the image words _except_ the CRC word,
                // which is word 10.
                for &word in image[..10].iter().chain(&image[11..image_length as usize / 4]) {
                    crc.update(&word.to_le_bytes());
                }
                let expected_crc = crc.finish();
                let actual_crc = image[10];

                if expected_crc != actual_crc {
                    return false;
                }
            }
            0 => {
                // No secondary header.
            }
            _ => {
                // Bogus image type. Note that this includes the non-XIP image
                // types.
                return false;
            }
        }
        // TODO do we need to check the execution address?
        // TODO do we care whether an image is XIP or not?
        let reset_vector = image[1];
        if reset_vector & 1 == 0 {
            // This'll cause an immediate usage fault. Reject it.
            return false;
        }
        let image_base = image.as_ptr() as u32;
        let image_addr_range = image_base..image_base + SLOT_SIZE_WORDS as u32 * 4;

        if !image_addr_range.contains(&(reset_vector & !1)) {
            // Reset vector points out of the image, which seems really darn
            // suspicious.
            return false;
        }

        if image_type != 0 {
            // Word 13 is the execution address. This must match the image base,
            // since we only support XIP images.
            if image[13] != image_base {
                return false;
            }
        }
    }

    if image_type == 5 {
        // Plain CRC XIP image. skboot_authenticate doesn't like these. We
        // checked the CRC above.
        return true;
    }

    let bt = romapi::bootloader_tree();
    let auth = bt.skboot.skboot_authenticate;

    // Safety: skboot_authenticate is written in C and is part of the NXP ROM,
    // home of CVEs a'plenty. This function _should_ only
    //
    // 1. Read through our pointer, with the bounds determined by header fields
    //    that we've verified.
    // 2. Write through the annoying out-parameter `is_verified`.
    // 3. Mess around with boot ROM scratch space, which isn't part of our RAM
    //    area so overwriting it has no effect on our program.
    //
    // If these properties hold, then calling this is safe. If they don't hold,
    // our entire secure boot apparatus is likely broken.
    //
    // Incidentally: another good reason why this call is unsafe is that the ROM
    // appears to unmask the HASHCRYPT interrupt. We've provided a HASHCRYPT
    // handler that redirects into the ROM (below) without doing any
    // potentially-racy things to our state, so that's ok. We'll disable it in
    // just a bit.
    let mut is_verified = 1234; // function doesn't always initialize this
    let result = unsafe {
        auth(image.as_ptr(), &mut is_verified)
    };
    // I have _no_ reason to believe the ROM re-masks this interrupt, so, let's
    // do it ourselves.
    cortex_m::peripheral::NVIC::mask(lpc55_pac::Interrupt::HASHCRYPT);

    // > ...the caller shall verify both return values and consider authentic
    // > image only when the function returns kStatus_SKBOOT_Success AND
    // > *isSignVerified == kSECURE_TRACKER_VERIFIED.
    //      - NXP UM11126 section 7.4.1
    result == romapi::SkbootStatus::Success as u32
        && is_verified == romapi::SecureBool::TrackerVerified as u32
}

/// Checks if the page containing `word_number` has been programmed since it was
/// last erased. Since reading from an erased page will fault, it's important to
/// do this before accessing any page that is possibly erased.
///
/// Words are 128 bits, or 16 bytes, or 4 u32 words in size, and are numbered
/// starting from the base of flash.
#[inline(never)]
fn is_programmed(
    flash: &lpc55_pac::FLASH,
    word_number: u32,
) -> bool {
    // Issue a blank-check command. There's a pseudocode example of this in UM
    // 5.7.11.
    //
    // Since the STOPA is _inclusive_ we can use the same address for both.
    flash.int_clr_status.write(|w| unsafe { w.bits(0xF) });
    flash.starta.write(|w| unsafe { w.starta().bits(word_number) });
    flash.stopa.write(|w| unsafe { w.stopa().bits(word_number) });
    flash.cmd.write(|w| unsafe { w.cmd().bits(5) });

    while !flash.int_status.read().done().bit() {
        // spin.
    }

    if flash.int_status.read().fail().bit() {
        // Counter-intuitively, FAIL here means we succeeded, in that the page
        // is _not_ blank.
        true
    } else {
        // The page is erased. Do not attempt to read from it.
        false
    }
}

fn boot_into(image: &'static [u32; SLOT_SIZE_WORDS]) -> ! {
    //todo!("turn off peripherals");

    // The NXP image header is _also_ a Cortex-M vector table, stuffing things
    // into reserved places. So we can derive the correct boot values for the
    // SP, PC, and VTOR in the normal way:
    let (stack, reset, vtor) = (image[0], image[1], image.as_ptr() as u32);

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

/// Size of each flash image slot in words (which are 32 bits each). The ROM
/// requires flash images to be 32-bit aligned, and it's easier for us if they
/// are, too, so we'll just deal in words.
const SLOT_SIZE_WORDS: usize = 299 * 1024 / 4;

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
