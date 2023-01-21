#![no_std]

pub mod romapi;
pub mod sha256;

use core::sync::atomic::Ordering;

/// Size of each flash image slot in words (which are 32 bits each). The ROM
/// requires flash images to be 32-bit aligned, and it's easier for us if they
/// are, too, so we'll just deal in words.
pub const SLOT_SIZE_WORDS: usize = 299 * 1024 / 4;

/// Verifies an image and, if successful, returns the prefix of the `image`
/// slice that contains valid data per the image header.
#[inline(never)]
pub fn verify_image(
    flash: &lpc55_pac::FLASH,
    image: &'static [u32; SLOT_SIZE_WORDS],
) -> Option<&'static [u32]> {
    // Convert the image address to a Flash word number.
    let start_fword = (image.as_ptr() as u32 / 16) & ((1 << 18) - 1);
    // Verify that the _first_ page of the image has been programmed. Without
    // this, we can't load the image size.
    if !is_programmed(flash, start_fword) {
        // Welp, we certainly can't boot an image that's missing its first page.
        return None;
    }

    // Do not permit the compiler to hoist any accesses through `image` above
    // that check.
    core::sync::atomic::compiler_fence(Ordering::SeqCst);

    // Read the image length from word 8. This is within the first page so we're
    // clear to read it. (It's also below the static SLOT_SIZE_WORDS bound, so
    // it doesn't incur a bounds check.)
    let image_length = image[8];

    // Our validation below requires that the image contain at least 11
    // u32-sized values, for a total size of...
    if image_length < 11 * 4 {
        return None;
    }
    // Suggesting that the image is larger than the flash slot is hella sus.
    if image_length as usize / 4 >= image.len() {
        return None;
    }
    // For implementation convenience reasons below, we require that the image
    // size is a multiple of 4. The NXP ROM doesn't require this, so, we're
    // being slightly stricter than necessary.
    if image_length % 4 != 0 {
        return None;
    }

    // Round up to a whole number of flash words (128 bits / 16 bytes each).
    // The generation of an overflow check on the addition is prevented by
    // bounding image_length to under the image.len above.
    let image_length_fwords = (image_length + 15) / 16;

    // Verify that every. single. page. of the image is readable, because the
    // ROM doesn't do this despite NXP suggesting it in their app notes.
    for w in start_fword + 1 .. start_fword + image_length_fwords {
        if !is_programmed(flash, w) {
            return None;
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
                    return None;
                }
            }
            5 => {
                // CRC checksum used by the ROM. It'd be great if the ROM would
                // check this for us, wouldn't it?
                //
                // It won't though.

                // We have already verified that image_length seems plausible.

                let mut crc = tinycrc::Crc32::new(&crc_catalog::CRC_32_MPEG_2);

                // We want to add in all the image words _except_ the CRC word,
                // which is word 10. The [11..] doesn't generate a bounds check
                // because we've checked that image_length/4 > 11 above.
                for &word in image[..10].iter().chain(&image[11..image_length as usize / 4]) {
                    crc.update(&word.to_le_bytes());
                }
                let expected_crc = crc.finish();
                let actual_crc = image[10];

                if expected_crc != actual_crc {
                    return None;
                }
            }
            _ => {
                // Unsupported image type. Note that this includes the non-XIP
                // image types, and also simple Cortex-M images without CRC or
                // signature.
                return None;
            }
        }
        // TODO do we need to check the execution address?
        // TODO do we care whether an image is XIP or not?
        let reset_vector = image[1];
        if reset_vector & 1 == 0 {
            // This'll cause an immediate usage fault. Reject it.
            return None;
        }
        let image_addr_range = image.as_ptr_range();

        if !image_addr_range.contains(&((reset_vector & !1) as *const u32)) {
            // Reset vector points out of the image, which seems really darn
            // suspicious.
            return None;
        }

        if image_type != 0 {
            // Word 13 is the execution address. This must match the image base,
            // since we only support XIP images.
            if image[13] != image.as_ptr() as u32 {
                return None;
            }
        }
    }

    if image_type == 5 {
        // Plain CRC XIP image. skboot_authenticate doesn't like these. We
        // checked the CRC above.
        return Some(&image[..image_length as usize / 4]);
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
    if result == romapi::SkbootStatus::Success as u32
        && is_verified == romapi::SecureBool::TrackerVerified as u32
    {
        Some(&image[..image_length as usize / 4])
    } else {
        None
    }
}

/// Checks if the page containing `word_number` has been programmed since it was
/// last erased. Since reading from an erased page will fault, it's important to
/// do this before accessing any page that is possibly erased.
///
/// Words are 128 bits, or 16 bytes, or 4 u32 words in size, and are numbered
/// starting from the base of flash.
#[inline(never)]
pub fn is_programmed(
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
