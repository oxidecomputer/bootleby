//! Simple driver for the SHA256 hardware in the LPC55S, aimed at the specific
//! use case of measuring an image and folding it into a DICE CDI.

use core::num::Wrapping;

const WORDS_PER_BLOCK: usize = 512 / 32;  // which is to say, 16
const WORDS_PER_HASH: usize = 256 / 32 ;  // which is to say, 8

// It's also convenient to have this as Wrapping u64:
const WORDS_PER_BLOCK64: Wrapping<u64> = Wrapping(WORDS_PER_BLOCK as u64);

/// This routine will read the existing DICE CDI out of SYSCON and combine it
/// with a measurement of `data` using an HMAC. The result is deposited back in
/// SYSCON, destroying the original CDI so it cannot be used for eeeeeevil.
#[inline(never)]
pub fn update_cdi(
    syscon: &lpc55_pac::SYSCON,
    engine: &lpc55_pac::HASHCRYPT,
    data: &[u32],
) {
    // Collect the current CDI from SYSCON, which we assume is the one from the
    // ROM. (If this is the first time you're calling this routine since boot,
    // it should be the one from ROM.)
    //
    // Note that the PAC fails to include these registers, so we're doing unsafe
    // pointer accesses. Registers are at offset 0x900 (in bytes) from the base
    // of SYSCON, see UM 4.5 table 38.
    let cdi_pointer = {
        let x: *const lpc55_pac::syscon::RegisterBlock = &**syscon;
        // Safety: ptr::add is unsafe because of the potential for overflow in
        // the addition. In this case we're offsetting within the peripheral to
        // a struct field that should really already be defined, so overflow
        // can't occur.
        unsafe {
            (x as *mut u32).add(0x900 / 4) 
        }
    };
    let mut current_cdi = [0; WORDS_PER_HASH];
    for (i, dest) in current_cdi.iter_mut().enumerate() {
        *dest = unsafe {
            core::ptr::read_volatile(cdi_pointer.add(i))
        };
    }

    // Compute the new CDI by HMAC, using the ROM CDI as key, and the `data` as,
    // well, the data.
    let new_cdi = hmac(syscon, engine, &current_cdi, data);

    // Deposit it into SYSCON. This has the side effect of preventing disclosure
    // of the original CDI value.
    for (i, src) in new_cdi.into_iter().enumerate() {
        unsafe {
            core::ptr::write_volatile(
                cdi_pointer.add(i),
                src,
            );
        }
    }
}

#[inline(never)]
pub fn hmac(
    syscon: &lpc55_pac::SYSCON,
    engine: &lpc55_pac::HASHCRYPT,
    key: &[u32; 8],
    data: &[u32],
) -> [u32; WORDS_PER_HASH] {
    // HMAC is specified by RFC 2104 if you'd like to follow along.

    // We assume that the key is 8 words, i.e. 256 bits. This is smaller than
    // the SHA256 block size of 512 bits. HMAC specifies that if the key is
    // smaller than a block size, we must pad it with zeros. So, we'll feed in
    // the key, followed by some zeros, each time.

    // HMAC has us whiten the key in two different ways for the two hash phases,
    // inner and outer. The two differ in the value that gets XOR'd in. Those
    // constants are called ipad and opad, respectively, in the RFC.
    const IPAD: u32 = 0x36363636;
    const OPAD: u32 = 0x5c5c5c5c;
    let zeros = [0; WORDS_PER_BLOCK - WORDS_PER_HASH];

    // Compute the inner result: H((k ^ ipad) || data)
    let inner_hash = {
        let mut h = Hasher::begin(syscon, engine);
        h.update(key, IPAD);
        h.update(&zeros, IPAD);
        h.update(data, 0);
        h.finish()
    };

    // Compute the outer result: H((k ^ opad) || inner)
    let outer_result = {
        let mut h = Hasher::begin(syscon, engine);
        h.update(key, OPAD);
        h.update(&zeros, IPAD);
        h.update(&inner_hash, 0);
        h.finish()
    };

    outer_result
}

/// State we maintain for an ongoing hash operation.
struct Hasher<'a> {
    engine: &'a lpc55_pac::HASHCRYPT,
    syscon: &'a lpc55_pac::SYSCON,
    /// The number of words that have been fed to `update` so far. (During
    /// execution of `finish` this also counts padding words.)
    ///
    /// We use this for two purposes:
    /// 1. Keeping track of where we are in the current block.
    /// 2. Writing the length of data in bits to the final block as required by
    ///    SHA256.
    ///
    /// In both of these cases, wrapping is fine -- SHA256 actually specifies
    /// the count as wrapping at 64 bits. So using a `Wrapping<u64>` saves some
    /// overflow checks.
    ///
    /// This is `u64` instead of `usize` because you can call `update`
    /// repeatedly with new slices, meaning the number stored here can easily
    /// exceed `usize::MAX` on a 32-bit platform.
    word_count: Wrapping<u64>,
}

impl<'a> Hasher<'a> {
    /// Starts a new SHA256 hash operation, initializing the `HASHCRYPT` unit.
    #[inline(never)]
    pub fn begin(
        syscon: &'a lpc55_pac::SYSCON,
        engine: &'a lpc55_pac::HASHCRYPT,
    ) -> Self {
        // The ROM does stuff with the hash block and leaves it in an
        // intermediate state, because of course it does. Reset it.
        syscon.presetctrl2.modify(|_, w| w.hash_aes_rst().asserted());
        syscon.presetctrl2.modify(|_, w| w.hash_aes_rst().released());

        // Those writes go to an entirely different part of the address space
        // than our writes to the hash controller; make sure they happen-before.
        cortex_m::asm::dsb();

        // Put the multi-function thingy into SHA2 256 mode and start a new
        // hash. (The UM is not entirely clear whether setting the mode and
        // starting the hash in a single write is legal, but it works and NXP's
        // code appears to do the same thing.)
        engine.ctrl.write(|w| w.mode().sha2_256().new_hash().start());

        Self {
            syscon,
            engine,
            word_count: Wrapping(0),
        }
    }

    /// Extends the current hash-in-progress with the given `data`,
    /// exclusive-ORing each word with `mask.
    ///
    /// `data` may cross block boundaries, be a partial block, etc. It will be
    /// concatenated with the `data` passed to any other `update` call.
    ///
    /// In most cases you want a `mask` of 0, the parameter is provided because
    /// it's useful in certain HMAC operations and using the same routine for
    /// both cases saves some space.
    #[inline(never)]
    pub fn update(&mut self, data: &[u32], mask: u32) {
        for &word in data {
            self.load_word(word, mask);
        }
    }

    /// Completes the SHA256 hash and turns the `HASHCRYPT` unit back off.
    #[inline(never)]
    pub fn finish(mut self) -> [u32; 8] {
        // The SHA-256 hardware works in units of 16 words / 64 bytes / 512
        // bits, called blocks. After the actual `data` goes into the hardware,
        // we have to finish it off with something called Merkle-Damgård (MD)
        // padding. The variety of MD padding specified in the SHA-256 spec is:
        //
        // - Add a 1 bit.
        // - Add enough 0 bits for the current block to reach 448 (mod 512)
        //   bits.  (That is, until there are only 64 bits left in the block.)
        //   If the block is already past 448 bits by the time we added the 1,
        //   this means finishing out this block, and then starting a new one
        //   with 448 zeros.
        // - Add the length of the original data, _in bits,_ as a 64-bit
        //   big-endian integer to round out the final block to 512 bits.
        // - Add the final block(s) to the digest.
        //
        // (If you're curious, this construction provides a defense against
        // messages of slightly different lengths hashing to the same value.)
        //
        // Since we move data in 32-bit words only, the padding process is
        // slightly simplified here:
        //
        // - If the user data filled its final block, start a new empty one.
        // - Append a word with only its MSB set.
        // - Append words of zeros until two words of space remain in the block.
        //   This may require starting a new block.
        // - Append the high word of the data length in bits, and the low word,
        //   in that order, as big-endian integers.

        let word_count_before_padding = self.word_count;

        // We want the PAD bit to be in the MSB of the first byte added to the
        // digest, which, due to us being little-endian, means our pad value is:
        const PAD: u32 = 0x80_00_00_00_u32.swap_bytes();

        self.load_word(PAD, 0);
        // Extend with zeros until we're aligned properly for the final length.
        while self.word_count % WORDS_PER_BLOCK64 != WORDS_PER_BLOCK64 - Wrapping(2) {
            self.load_word(0, 0);
        }
        // We are now 14 words into a block, no synchronization is necessary, we
        // just need to load the length of the pre-padded data in bits. As with
        // PAD above, since these aren't round-tripping through little-endian
        // memory, we wind up having to swap their bytes:
        let Wrapping(length) = word_count_before_padding * Wrapping(32);
        self.load_word(u32::swap_bytes((length >> 32) as u32), 0);
        self.load_word(u32::swap_bytes(length as u32), 0);

        // Wait for our result!
        while self.engine.status.read().digest().is_not_ready() {
            // spin.
        }

        // The result arrives in registers called digest0..digest7, which the
        // PAC calls digest0[0] .. digest0[7] for some reason.
        let mut result = [0; WORDS_PER_HASH];
        for (i, dest) in result.iter_mut().enumerate() {
            *dest = self.engine.digest0[i].read().bits();
        }

        // Just for good measure, make sure the reset below isn't hoisted above
        // our accesses above.
        cortex_m::asm::dsb();

        self.syscon.presetctrl2.modify(|_, w| w.hash_aes_rst().asserted());

        result
    }

    /// Utility factor for making sure we synchronize with the device at the
    /// start of each 16-word input block.
    #[inline(never)]
    fn load_word(&mut self, word: u32, mask: u32) {
        if self.word_count % WORDS_PER_BLOCK64 == Wrapping(0) {
            // Wait for the controller to be interested in what we have to say.
            while self.engine.status.read().waiting().is_not_waiting() {
                // spin.
            }
        }
        self.engine.indata.write(|w| unsafe { w.data().bits(word ^ mask) });
        self.word_count += Wrapping(1);
    }
}
