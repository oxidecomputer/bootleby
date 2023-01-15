#![no_std]
#![no_main]

mod romapi;

use core::mem::MaybeUninit;

// TODO: we will want our own custom panic handling
use panic_halt as _;
use cortex_m_rt::entry;
use lpc55_pac::interrupt;

#[entry]
fn main() -> ! {
    let a_ok = verify_image(image_a());
    let b_ok = verify_image(image_b());

    let choice = match (a_ok, b_ok) {
        (true, false) => ImageChoice::A,
        (false, true) => ImageChoice::B,
        (true, true) => {
            // TODO: technically this does break ties, but not in a useful way!
            ImageChoice::A
        }
        _ => panic!("no valid images"),
    };

    match choice {
        ImageChoice::A => boot_into(image_a()),
        ImageChoice::B => boot_into(image_b()),
    }
}

fn boot_into(image: &'static [u32; SLOT_SIZE_WORDS]) -> ! {
    //todo!("disable interrupts possibly enabled by ROM");
    //todo!("turn off peripherals");

    // The NXP image header is _also_ a Cortex-M vector table, stuffing things
    // into reserved places. So we can derive the correct boot values for the
    // SP, PC, and VTOR in the normal way:
    // image!
    let (stack, reset, vtor) = (image[0], image[1], image.as_ptr() as u32);

    // And away we go!
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

#[derive(Copy, Clone, Debug)]
enum ImageChoice { A, B }

fn verify_image(
    image: &'static [u32; SLOT_SIZE_WORDS],
) -> bool {
    // Because of our past experience with the implementation quality of the
    // ROM, let's do some basic checks before handing it a blob to inspect,
    // shall we?
    {
        // TODO: when we begin requiring secure stage1, we do it here.
        let image_type = image[4];
        match image_type {
            1 | 4 | 0x8001 => {
                // Validate that the secondary header offset is in bounds.
                // TODO: we can do better than this:
                let header_offset = image[5];
                if header_offset >= SLOT_SIZE_WORDS as u32 {
                    return false;
                }
            }
            2 | 5 => {
                // CRC checksum... we can probably trust the ROM to compute
                // this?
            }
            0 => {
                // No secondary header.
            }
            _ => {
                // Bogus image type.
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
    }

    let bt = romapi::bootloader_tree();
    let auth = bt.skboot.skboot_authenticate;
    let mut is_verified = 0;
    let result = unsafe {
        auth(image.as_ptr(), &mut is_verified)
    };

    // > ...the caller shall verify both return values and consider authentic
    // > image only when the function returns kStatus_SKBOOT_Success AND
    // > *isSignVerified == kSECURE_TRACKER_VERIFIED.
    //      - NXP UM11126 section 7.4.1
    result == romapi::SkbootStatus::Success as u32
        && is_verified == romapi::SecureBool::TrackerVerified as u32
}

const SLOT_SIZE_WORDS: usize = 299 * 1024 / 4;

extern "C" {
    #[no_mangle]
    static IMAGE_A: [u32; SLOT_SIZE_WORDS];
    #[no_mangle]
    static IMAGE_B: [u32; SLOT_SIZE_WORDS];
}

fn image_a() -> &'static [u32; SLOT_SIZE_WORDS] {
    unsafe {
        &IMAGE_A
    }
}

fn image_b() -> &'static [u32; SLOT_SIZE_WORDS] {
    unsafe {
        &IMAGE_B
    }
}

#[interrupt]
fn HASHCRYPT() {
    unsafe {
        (romapi::bootloader_tree().skboot.skboot_hashcrypt_irq_handler)();
    }
}
