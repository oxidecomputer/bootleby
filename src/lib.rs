// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! LPC55 multi-image verified bootloader: the crate
//!
//! This crate provides most of the implementation for the "bootleby" multi-image
//! bootloader, factored out of the binary itself so that it can be tested.
//!
//! In general, code should go here rather than into `bootleby` directly, except
//! for the specific bits responsible for activating / launching a new image --
//! those are hard to test separately from `bootleby`.

#![no_std]

pub mod romapi;
pub mod sha256;
pub mod bsp;

use core::{sync::atomic::Ordering, mem::size_of};
use hex_literal::hex;
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

/// Names for our two firmware slots. Used whenever we need to pass around a
/// token identifying one slot or the other.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SlotId { A, B }

/// Size of each flash image slot in 32-bit words. The ROM requires flash images
/// to be 32-bit aligned, and it's easier for us if they are, too, so we'll just
/// deal in words. (This is also why the "words" constant is the primary one
/// rather than bytes.)
///
/// (Note that the flash controller also uses the term "word" to refer to a
/// larger chunk of data; this code consistently uses "fword" for flash words.)
///
/// Changing this constant requires updates to the linker script for both bootleby
/// and any second-stage programs being launched.
pub const SLOT_SIZE_WORDS: usize = 256 * 1024 / size_of::<u32>();

/// Equivalent in bytes. Please do not change separately from `SLOT_SIZE_WORDS`
/// because that would be confusing and rude.
pub const SLOT_SIZE_BYTES: usize = SLOT_SIZE_WORDS * size_of::<u32>();

/// Number of bytes per fword (flash word). Specified by hardware, do not
/// change.
const BYTES_PER_FWORD: usize = 16;

/// Sometimes, just _sometimes,_ Rust's insistence on distinguishing usize from
/// u32 on a 32-bit platform is annoying.
const BYTES_PER_FWORD_U32: u32 = BYTES_PER_FWORD as u32;

/// Number of fwords per programmable flash page (512 bytes).
const FWORDS_PER_PAGE: usize = 512 / BYTES_PER_FWORD;

/// Mask of bits that are actually decoded by the flash controller. The flash
/// controller receives 27-bit addresses from the bus, but only decodes the
/// bottom 18 bits, with the result that flash content is repeated many times.
const FLASH_DECODE_MASK: u32 = (1 << 18) - 1;

/// Verifies an image and, if successful, returns two references that alias one
/// another:
///
/// - The first is a reference to the NXP image header at the start of the slot,
///   as a way of proving that there's enough data to contain a valid image
///   header. Any further verification, or access to the reset vector etc.,
///   should use this reference to avoid extra bounds checks.
///
/// - The second is the entire image, pruned to its recorded size, as u32s, to
///   prove that it's 4-byte-aligned and a whole number of words. The first 16
///   words of this slice are the header.
///
/// This API design might be surprising, but it's deliberate.
///
/// 1. Keeping access to the `IMAGE_A`/`IMAGE_B` statics inside this function
///    (rather than letting you pass a pointer) ensures that it's always dealing
///    with a controlled, aligned flash image, and not some random data.
/// 2. Returning aliased references avoids generating bounds checks in the
///    caller. If we could return a type "slice of u32s of at least 16 entries,"
///    we would, but there's no such type.
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
        // Safety: access to this static is unsafe because it's extern "C", and
        // so the compiler is nervous that some other chunk of code is monkeying
        // with it behind our backs. In our case, this is not the case; it's
        // only extern "C" to make sure we can correctly define it in the linker
        // script.
        SlotId::A => unsafe { &IMAGE_A },
        // Safety: same
        SlotId::B => unsafe { &IMAGE_B },
    };

    // Convert the image address to an fword (flash word) number. Because flash
    // starts at the bottom of the address space, this is a matter of dividing
    // the image base address by the size of an fword. Because flash is aliased
    // twice, we also mask off the top bits, which aren't decoded by the flash
    // controller interface.
    let start_fword =
        (image.as_ptr() as u32 / BYTES_PER_FWORD as u32) & FLASH_DECODE_MASK;
    // Verify that the _first_ page of the image has been programmed. Without
    // this, we can't load the image size.
    if !is_programmed(flash, start_fword) {
        // Welp, we certainly can't boot an image that's missing its first page.
        return None;
    }

    // Do not permit the compiler to hoist any accesses through `image` above
    // that check. This is not a memory-safety-in-the-Rust sense thing: if an
    // access through `image` were hoisted above the erase check, we'd just
    // crash. But we don't want to crash.
    core::sync::atomic::compiler_fence(Ordering::SeqCst);

    // Okay, now we're willing to interact with the actual array.
    //
    // Attempt to pun the first 64 bytes as an image header. This doesn't
    // dereference the reference yet, but we get the following checks for free
    // from `zerocopy`:
    // - Image is 4-byte aligned (we get this from the use of u32 anyway, but it
    //   is re-checked)
    // - Image is large enough to contain the image header as a prefix.
    let (header, _) = 
        LayoutVerified::<_, NxpImageHeader>::new_from_prefix(image.as_bytes())
        .unwrap();
    // We don't need to carry the properties of the LayoutVerified type, and
    // doing so makes certain things awkward; just a reference please.
    let header = header.into_ref();

    // The LPC55 aliases flash in two places, 0 and `0x1000_0000`. These
    // locations differ in bit 28, which is not actually passed to the flash
    // controller. The distinction is that the addresses with bit 28 set are, by
    // default, set secure-only by the IDAU. We link bootleby to run from
    // addresses with bit 28 set, but we will tolerate next-stage programs
    // linked at either location.
    //
    // This means we have to be a smidge careful in testing things like the
    // reset vector below, and that we should also be polite and set the VTOR
    // the way the program expects when we launch.
    //
    // Figure out which alias the program was linked in using bit 28 of the
    // reset vector.
    let bit_28_set = header.reset_vector & 1 << 28 != 0;

    // Start processing the header's image length field.
    //
    // For implementation convenience reasons below, we require that the image's
    // internally stated size is a multiple of 4. The NXP ROM doesn't require
    // this, so, we're being slightly stricter than necessary.
    if header.image_length % 4 != 0 {
        return None;
    }
    // The claimed length must be large enough to contain the header we're
    // already using. This is the practical minimum length for an NXP-format
    // image, anything less is likely garbage.
    if (header.image_length as usize) < size_of::<NxpImageHeader>() {
        return None;
    }

    // Slice off the unused portion of the image while simultaneously checking
    // that the image length fits within the slot (since `image` has the length
    // of the slot). This avoids a bunch of checks below.
    let image = image.get(..header.image_length as usize / 4)?;

    // Round up to a whole number of fwords.
    //
    // Rustc likes to insert an overflow check here on the add. We know this
    // isn't going to overflow because `image_length / 4 < SLOT_LEN_WORDS`, and
    // so `image_length` is significantly smaller than `u32::MAX`. So, we
    // override the overflow check.
    let image_length_fwords =
        header.image_length.wrapping_add(BYTES_PER_FWORD_U32 + 1)
            / BYTES_PER_FWORD_U32;

    // Verify that every. single. page. of the image is readable, because the
    // ROM doesn't do this despite NXP suggesting it in their app notes.
    //
    // Skip the first page because we checked it above.
    let fword_range = start_fword .. start_fword + image_length_fwords;
    for w in fword_range.step_by(FWORDS_PER_PAGE).skip(1) {
        if !is_programmed(flash, w) {
            return None;
        }
    }

    // Ensure that our call to ROM, below, happens after our program checks,
    // above. Necessary? Almost certainly not; emphasis on the "almost."
    core::sync::atomic::compiler_fence(Ordering::SeqCst);

    // Because of our past experience with the implementation quality of the
    // ROM, let's do some basic checks before handing it a blob to inspect,
    // shall we?
    {
        match header.image_type {
            4 => {
                // Validate that the secondary header offset is in bounds.
                let header_offset = header.type_specific_header;
                if header_offset >= SLOT_SIZE_BYTES as u32 {
                    return None;
                }
            }
            #[cfg(feature = "allow-unsigned-images")]
            5 => {
                // CRC checksum used by the ROM. It'd be great if the ROM would
                // check this for us, wouldn't it?
                //
                // It won't though; there's no entry point for it.

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
                // The CRC format (ab)uses the `type_specific_header` field to
                // store the CRC.
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

        // Verify that the reset vector is a valid Thumb-2 function pointer.
        if header.reset_vector & 1 == 0 {
            // This'll cause an immediate usage fault. Reject it.
            return None;
        }

        // Compute the pointer range corresponding to the image, taking its bit
        // 28 preference into account.
        let image_addr_range = if bit_28_set {
            image.as_ptr_range()
        } else {
            let r = image.as_ptr_range();
            let mask_without_28 = !(1 << 28);
            let start = r.start as u32 & mask_without_28;
            let end = r.end as u32 & mask_without_28;
            start as *const _ .. end as *const _
        };

        // Verify that the reset vector points within the image. Without doing
        // this, you could admit a signed image that maliciously jumps into the
        // other, unverified image slot.
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

    // Time to check the signatures!

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

/// Layout of the NXP image header, which is also the ARMv8-M vector table.
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

/// Layout of the Customer Field Programmble Area structure in Flash.
///
/// This struct should be exactly 512 bytes. If you change it such that its size
/// is no longer 512 bytes, it will not compromise security, but bootleby will
/// panic while checking the persistent settings (and with any luck the static
/// assertion below will fire before you hit the panic).
#[derive(Copy, Clone, Debug, AsBytes, FromBytes)]
#[repr(C)]
pub struct CfpaPage {
    // Fields defined by NXP:

    pub header: u32,
    pub monotonic_version: u32,
    _fields_we_do_not_use: [u32; 10],
    _prince_ivs: [[u32; 14]; 3],
    _nxp_reserved: [u32; 10],

    // We are now at offset 0x100.

    // Fields defined by us:

    /// Flags controlling persistent boot behavior. Currently only bit 0 is
    /// meaningful.
    ///
    /// 0 means prefer slot A; 1 means prefer slot B.
    ///
    /// Top bits are ignored.
    pub boot_flags: u32,

    // Padding to describe remainder of region -- you will need to adjust this
    // down if you add fields.
    _padding: [u8; 252],
}

// It's really quite important that the CFPA data structure be exactly the size
// of a flash page, 512 bytes.
static_assertions::const_assert_eq!(size_of::<CfpaPage>(), 512);

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
    // Note: this implementation drives the flash controller directly rather
    // than setting up and calling the ROM Flash API. It turns out to be
    // substantially smaller to do it ourselves!

    // Issue a blank-check command. There's a pseudocode example of this in UM
    // 5.7.11.
    //
    // Since the STOPA is _inclusive_ we can use the same address for both.
    //
    // Safety: this is unsafe only because the register is incompletely modeled
    // in the PAC.
    flash.int_clr_status.write(|w| unsafe { w.bits(0xF) });
    // Safety: same
    flash.starta.write(|w| unsafe { w.starta().bits(word_number) });
    // Safety: same
    flash.stopa.write(|w| unsafe { w.stopa().bits(word_number) });
    // Safety: same
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

extern "C" {
    // Image regions, placed by the linker script.
    static IMAGE_A: [u32; SLOT_SIZE_WORDS];
    static IMAGE_B: [u32; SLOT_SIZE_WORDS];

    // CFPA ping-pong pages, placed by the linker script.
    static CFPA: [CfpaPage; 2];
}

// Transient boot preference override support.
//
// There are two magic constants that, if deposited in a particular location in
// memory, will affect our boot image selection. They are the SHA256 hashes of
// two English sentences, because why not. See RFD374.
pub const PREFER_SLOT_A: [u8; 32] = hex!(
    "edb23f2e9b399c3d57695262f29615910ed10c8d9b261bfc2076b8c16c84f66d"
);
pub const PREFER_SLOT_B: [u8; 32] = hex!(
    "70ed2914e6fdeeebbb02763b96da9faa0160b7fc887425f4d45547071d0ce4ba"
);

/// Inspects the contents of `buffer` to see if it contains one of the special
/// byte sequences for overriding boot preference.
///
/// If it _does,_ it will be cleared and the bottom bit of the first byte set to
/// reflect the choice, which is why this requires a `&mut`. If it contains
/// other arbitrary data, it will be preserved. This is arguably an odd division
/// of responsibilities, but it makes our standard use case -- processing a boot
/// command _exactly once_ -- far harder to screw up.
///
/// This function doesn't implicitly access the `TRANSIENT_OVERRIDE` buffer
/// because, to do so safely, we need to know about the processor's situation
/// and interrupt handlers. You'll have to do it when you call.
pub fn check_transient_override(buffer: &mut [u8; 32]) -> Option<SlotId> {
    let choice = if buffer == &PREFER_SLOT_A {
        Some(SlotId::A)
    } else if buffer == &PREFER_SLOT_B {
        Some(SlotId::B)
    } else {
        None
    };

    if let Some(slot) = choice {
        buffer.fill(0);
        buffer[0] = if slot == SlotId::A { 0 } else { 1 };
    }

    choice
}

/// Reads the committed pages (ping-pong pages) of the CFPA, determines which
/// represents newer content, and returns a reference to it.
///
/// If the two are tied -- they have the same monotonic version, which should
/// only happen on a factory-fresh part -- we arbitrarily choose the first page.
pub fn read_cfpa() -> &'static CfpaPage {
    // Safety: Rust is concerned about this because we've marked the CFPA array
    // as extern "C", and this means a C program might be sneaking around
    // violating our assumptions. In our case, this is not true -- we only
    // marked it extern "C" because the final location is decided by the linker
    // script, and the contents aren't described by this program. So it's always
    // ok to do this:
    let cfpa = unsafe { &CFPA };

    // It's not clear how the ROM handles integer wraparound if the CFPA version
    // gets high enough -- it seems unlikely to occur in practice. So, we will
    // use non-wrapping comparison here for the time being.
    if cfpa[0].monotonic_version < cfpa[1].monotonic_version {
        &cfpa[1]
    } else {
        &cfpa[0]
    }
}
