#![no_std]

pub mod romapi;
pub mod sha256;
pub mod bsp;

use core::{sync::atomic::Ordering, mem::size_of};
use zerocopy::{AsBytes, FromBytes};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SlotId { A, B }

/// Size of each flash image slot in words (which are 32 bits each). The ROM
/// requires flash images to be 32-bit aligned, and it's easier for us if they
/// are, too, so we'll just deal in words.
pub const SLOT_SIZE_WORDS: usize = 299 * 1024 / 4;

/// Verifies an image and, if successful, returns two references that alias one
/// another:
///
/// - The first is a reference to the NXP image header at the start of the slot,
///   as a way of proving that there's enough data to contain a valid image
///   header.
/// - The second is the entire image, pruned to its recorded size, as u32s, to
///   prove that it's 4-byte-aligned and a whole number of words. The first 16
///   words of this slice are the header.
#[inline(never)]
pub fn verify_image(
    flash: &lpc55_pac::FLASH,
    which: SlotId,
) -> Option<(&'static NxpImageHeader, &'static [u32])> {
    // Get a reference to one slot or the other. Starting out, we know the
    // following properties of `image` hold:
    //
    // 1. Its base address is 32-bit aligned (required by type system, ensured
    //    by linker).
    // 2. It consists of a whole number of 32-bit words (implicit in its
    //    definition as a `[u32]`).
    // 3. It is in flash (ensured by linker script).
    // 4. It refers to one of the firmware slots (ensured by linker script).
    let image = match which {
        SlotId::A => unsafe { &IMAGE_A },
        SlotId::B => unsafe { &IMAGE_B },
    };

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

    // Okay, now we're willing to interact with the actual array.
    // Attempt to pun the first 32 bytes as an image header. This doesn't
    // dereference the reference yet, but we get the following checks for free
    // from this line:
    // - Image is 4-byte aligned (we get this from the use of u32 anyway)
    // - Image is large enough to contain the image header.
    let (header, _) = zerocopy::LayoutVerified::<_, NxpImageHeader>::new_from_prefix(image.as_bytes())
        .unwrap();
    let header = header.into_ref();

    // The LPC55 aliases flash at base addresses, 0 and `0x1000_0000`. These
    // locations differ in bit 28. The distinction is that the addresses with
    // bit 28 set are, by default, set secure by the IDAU. We link stage0 to run
    // from addresses with bit 28 set, but we will tolerate next-stage programs
    // linked at either location.
    //
    // This means we have to be a smidge careful in testing things like the
    // reset vector below, and that we should also be polite and set the VTOR
    // the way the program expects when we launch.
    //
    // Figure out which alias the program was linked in using bit 28 of the
    // reset vector.
    let bit_28_set = header.reset_vector & 1 << 28 != 0;

    // For implementation convenience reasons below, we require that the image
    // size is a multiple of 4. The NXP ROM doesn't require this, so, we're
    // being slightly stricter than necessary.
    if header.image_length % 4 != 0 {
        return None;
    }
    // The claimed length must be large enough to contain the header we're
    // already using.
    if (header.image_length as usize) < size_of::<NxpImageHeader>() {
        return None;
    }

    // Slice off the unused portion of the image while simultaneously checking
    // that the image length fits within the slot. This avoids a bunch of checks
    // below.
    let image = image.get(..header.image_length as usize / 4)?;

    // Round up to a whole number of flash words (128 bits / 16 bytes each).
    //
    // Rustc likes to insert an overflow check here. We know this isn't going to
    // overflow because `image_length / 4 < SLOT_LEN_WORDS`, and so
    // `image_length` is significantly smaller than `u32::MAX`. So, we override
    // the overflow check.
    let image_length_fwords = header.image_length.wrapping_add(15) / 16;

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
    {
        match header.image_type {
            4 => {
                // Validate that the secondary header offset is in bounds.
                // TODO: we can do better than this:
                let header_offset = header.type_specific_header;
                if header_offset >= SLOT_SIZE_WORDS as u32 {
                    return None;
                }
            }
            #[cfg(feature = "allow-unsigned-images")]
            5 => {
                // CRC checksum used by the ROM. It'd be great if the ROM would
                // check this for us, wouldn't it?
                //
                // It won't though.

                // We have already verified that image_length seems plausible.

                let mut crc = tinycrc::Crc32::new(&crc_catalog::CRC_32_MPEG_2);

                // The CRC calculation simply _skips_ the CRC word, as opposed
                // to (say) including it with an assumed value of 0. So to CRC
                // our header we have to jump through...a small hoop.
                {
                    let header_bytes = header.as_bytes();
                    crc.update(&header_bytes[..0x28]);
                    crc.update(&header_bytes[0x28 + 4..]);
                }
                // And now, the rest of the image.
                crc.update(image[size_of::<NxpImageHeader>() / 4..].as_bytes());

                let computed_crc = crc.finish();
                let stored_crc = header.type_specific_header;

                if computed_crc != stored_crc {
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
        // TODO do we care whether an image is XIP or not?
        if header.reset_vector & 1 == 0 {
            // This'll cause an immediate usage fault. Reject it.
            return None;
        }
        let image_addr_range = image.as_ptr_range();
        // Update that addr range to reflect the image's expected link address.
        // Since we start out with the bit set, we need to clear it if required.
        let image_addr_range = if bit_28_set {
            image_addr_range
        } else {
            let mask_without_28 = !(1 << 28);
            let start = image_addr_range.start as u32 & mask_without_28;
            let end = image_addr_range.end as u32 & mask_without_28;
            start as *const _ .. end as *const _
        };

        if !image_addr_range.contains(&((header.reset_vector & !1) as *const u32)) {
            // Reset vector points out of the image, which seems really darn
            // suspicious.
            return None;
        }
    }
    
    #[cfg(feature = "allow-unsigned-images")]
    if header.image_type == 5 {
        // Plain CRC XIP image. skboot_authenticate doesn't like these. We
        // checked the CRC above.
        return Some((header, image));
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
        Some((header, image))
    } else {
        None
    }
}

#[derive(Copy, Clone, Debug, AsBytes, FromBytes)]
#[repr(C)]
pub struct NxpImageHeader {
    pub initial_stack_pointer: u32,
    pub reset_vector: u32,
    _unrelated_vectors_0: [u32; 6],
    pub image_length: u32,
    pub image_type: u32,
    pub type_specific_header: u32,
    _unrelated_vectors_1: [u32; 2],
    pub image_execution_address: u32,
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

// Image regions, placed by the linker script.
extern "C" {
    static IMAGE_A: [u32; SLOT_SIZE_WORDS];
    static IMAGE_B: [u32; SLOT_SIZE_WORDS];
}
