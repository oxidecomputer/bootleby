//! Simple driver for the SHA256 hardware in the LPC55S, aimed at the specific
//! use case of measuring an image and folding it into a DICE CDI.

/// This routine will read the existing DICE CDI out of SYSCON and combine it
/// with a measurement of `data`.
///
/// Concretely,
///
/// - We compute the SHA256 hash of `data`.
/// - We concatenate that with the existing DICE CDI.
/// - We compute the SHA256 hash of the concatenated data.
/// - The result is the new DICE CDI, which we load into SYSCON.
///
/// This is approximately, but not quite, an HMAC.
#[inline(never)]
pub fn update_cdi(
    syscon: &lpc55_pac::SYSCON,
    engine: &lpc55_pac::HASHCRYPT,
    data: &[u32],
) {
    let mut inner_result = [0; 16];
    inner_result[..8].copy_from_slice(&hash(syscon, engine, data));
    for (i, dest) in inner_result[8..].iter_mut().enumerate() {
        *dest = unsafe {
            core::ptr::read_volatile((0x5000_0000 + 0x900 + 4 * i) as *const u32)
        };
    }

    let outer_result = hash(syscon, engine, &inner_result);
    for (i, &src) in outer_result.iter().enumerate() {
        unsafe {
            core::ptr::write_volatile(
                (0x5000_0000 + 0x900 + 4 * i) as *mut u32,
                src,
            );
        }
    }

}

/// Uses the SHA256 hardware (`engine`) to compute a SHA256 hash of `data`.
///
/// Access to `SYSCON` is required to ensure that the SHA256 block is properly
/// reset before use, because the ROM leaves it in a weird state.
#[inline(never)]
pub fn hash(
    syscon: &lpc55_pac::SYSCON,
    engine: &lpc55_pac::HASHCRYPT,
    data: &[u32],
) -> [u32; 8] {
    // The ROM does stuff with the hash block and leaves it in an intermediate
    // state, because of course it does. Reset it.
    syscon.presetctrl2.modify(|_, w| w.hash_aes_rst().asserted());
    syscon.presetctrl2.modify(|_, w| w.hash_aes_rst().released());

    // Those writes go to an entirely different part of the address space than
    // our writes to the hash controller; make sure they happen-before.
    cortex_m::asm::dsb();

    // Put the multi-function thingy into SHA2 256 mode and start a new hash.
    engine.ctrl.write(|w| w.mode().sha2_256().new_hash().start());

    // The SHA-256 hardware works in units of 16 words / 64 bytes / 512 bits,
    // called blocks. After the actual `data` goes into the hardware, we have to
    // finish it off with something called Merkle-Damgård (MD) padding. The
    // variety of MD padding specified in the SHA-256 spec is:
    //
    // - Add a 1 bit.
    // - Add enough 0 bits for the current block to reach 448 (mod 512) bits.
    //   (That is, until there are only 64 bits left in the block.) If the block
    //   is already past 448 bits by the time we added the 1, this means
    //   finishing out this block, and then starting a new one with 448 zeros.
    // - Add the length of the original data, _in bits,_ as a 64-bit big-endian
    //   integer to round out the final block to 512 bits.
    // - Add the final block(s) to the digest.
    //
    // (If you're curious, this construction provides a defense against messages
    // of slightly different lengths hashing to the same value.)
    //
    // Since we move data in 32-bit words only, the padding process is slightly
    // simplified here:
    //
    // - If the user data filled its final block, start a new empty one.
    // - Append a word with only its MSB set.
    // - Append words of zeros until two words of space remain in the block.
    //   This may require starting a new block.
    // - Append the high word of the data length in bits, and the low word, in
    //   that order, as big-endian integers.

    // First, separate `data` into some number of whole 16-word blocks, followed
    // by zero or more straggler words, by splitting it at its size rounded down
    // to the next-smallest multiple of 16:
    let (prefix, tail) = data.split_at(data.len() & !0xF);

    // Load the whole blocks into the peripheral, pausing before each block to
    // wait for it to be ready.
    for block in prefix.chunks_exact(16) {
        // Wait for the controller to be interested in what we have to say.
        while engine.status.read().waiting().is_not_waiting() {
            // spin.
        }
        // Load data into the peripheral, optimizing for code size over speed.
        // (It has a bulk-load mechanism but it'd unroll this loop.)
        for &word in block {
            load_next_word(engine, word);
        }
    }

    // Because `tail.len()` is guaranteed to be 15 words or lower by the
    // rounding above, the initial padding word will always fit in the same
    // block as any words in `tail`. The length, however, may not, and this
    // affects our padding strategy.
    let (first_padding, second_padding) = if tail.len() > 16 - 3 {
        // There's no room for three words (pad+len-hi+len-lo) in this block, so
        // generate padding after the first pad word, and insert 14 zero words
        // into the next block before adding the length.
        (16 - 1 - tail.len(), 14)
    } else {
        // We can fit things in this block, another block is not necessary.
        (16 - 3 - tail.len(), 0)
    };

    for &word in tail {
        load_next_word(engine, word);
    }

    // We want the PAD bit to be in the MSB of the first byte added to the
    // digest, which, due to us being little-endian, means our pad value is:
    const PAD: u32 = 0x00000080;
    load_next_word(engine, PAD);

    // Zero padding!
    for _ in 0..first_padding {
        load_next_word(engine, 0);
    }
    if second_padding != 0 {
        // We've just finished a block, so, synchronize with the hardware.
        spin_until_engine_waiting(engine);
        for _ in 0..second_padding {
            load_next_word(engine, 0);
        }
    }

    // We are now 14 words into a block, no synchronization is necessary, we
    // just need to load the length in bits. As with PAD above, since these
    // aren't round-tripping through little-endian memory, we wind up having to
    // swap their bytes:
    let length = data.len() as u64 * 32;
    load_next_word(engine, u32::swap_bytes((length >> 32) as u32));
    load_next_word(engine, u32::swap_bytes(length as u32));
   
    // Wait for our result!
    while engine.status.read().digest().is_not_ready() {
        // spin.
    }

    // The result arrives in registers called digest0..digest7, which the PAC
    // calls digest0[0] .. digest0[7] for some reason.
    let mut result = [0; 8];
    for (i, dest) in result.iter_mut().enumerate() {
        *dest = engine.digest0[i].read().bits();
    }

    // Just for good measure, make sure the reset below isn't hoisted above our
    // accesses above.
    cortex_m::asm::dsb();

    syscon.presetctrl2.modify(|_, w| w.hash_aes_rst().asserted());

    result
}

fn load_next_word(engine: &lpc55_pac::HASHCRYPT, word: u32) {
    engine.indata.write(|w| unsafe { w.data().bits(word) });
}

fn spin_until_engine_waiting(engine: &lpc55_pac::HASHCRYPT) {
    while engine.status.read().waiting().is_not_waiting() {
        // spin.
    }
}
