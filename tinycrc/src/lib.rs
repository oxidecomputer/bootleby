//! `tinycrc`: a tiny CRC implementation.
//!
//! This is a CRC32 implementation that focuses on size over performance. It
//! uses no lookup tables and about 16 bytes of RAM (or, in the common case when
//! it gets inlined, a handful of registers).
//!
//! Algorithms are those defined in the `crc_catalog` crate, used by `crc` (a
//! crate that you should use instead if performance is important).

#![no_std]

use crc_catalog::Algorithm;

/// A CRC32 operation-in-progress using a particular algorithm.
#[derive(Clone, Debug)]
pub struct Crc32 {
    /// Algorithm polynomial.
    poly: u32,
    /// Should data be bit-reversed on the way in?
    reflect_in: bool,
    /// Should data be bit-reversed on the way out?
    reflect_out: bool,
    /// Value to XOR into the CRC at the end.
    xorout: u32,
    /// Current CRC value.
    value: u32,
}

impl Crc32 {
    /// Creates a new `Crc32` using `algorithm`'s settings.
    pub fn new(algorithm: &Algorithm<u32>) -> Self {
        let value = if algorithm.refin {
            algorithm.init.reverse_bits()
        } else {
            algorithm.init
        };
        Self {
            poly: algorithm.poly,
            reflect_in: algorithm.refin,
            reflect_out: algorithm.refout,
            xorout: algorithm.xorout,
            value,
        }
    }

    /// Updates this CRC with the content of `data`.
    pub fn update(&mut self, data: &[u8]) {
        if self.reflect_in {
            for &byte in data {
                let v = self.value ^ u32::from(byte);
                self.value = crc32_reflect(self.poly, v) ^ (self.value >> 8);
            }
        } else {
            for &byte in data {
                let v = (self.value >> 24) ^ u32::from(byte);
                self.value = crc32(self.poly, v) ^ (self.value << 8);
            }
        }
    }

    /// Performs any final computations required and returns the computed CRC32.
    pub fn finish(mut self) -> u32 {
        if self.reflect_in ^ self.reflect_out {
            self.value = self.value.reverse_bits();
        }
        self.value ^ self.xorout
    }
}

fn crc32_reflect(poly: u32, mut value: u32) -> u32 {
    for _ in 0..8 {
        value = (value >> 1) ^ ((value & 1) * poly);
    }
    value
}

fn crc32(poly: u32, mut value: u32) -> u32 {
    value <<= 24;
    for _ in 0..8 {
        value = (value << 1) ^ (((value >> 31) & 1) * poly);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_data() {
        let mine = Crc32::new(&crc_catalog::CRC_32_MPEG_2);
        let result = mine.finish();

        let good = crc::Crc::<u32>::new(&crc::CRC_32_MPEG_2);
        let good = good.digest();
        let correct_result = good.finalize();

        assert_eq!(result, correct_result);
    }

    #[test]
    fn some_data() {
        let fixture = b"the quick brown fox jumps over the lazy dog";

        let mut mine = Crc32::new(&crc_catalog::CRC_32_MPEG_2);
        mine.update(fixture);
        let result = mine.finish();

        let good = crc::Crc::<u32>::new(&crc::CRC_32_MPEG_2);
        let mut good = good.digest();
        good.update(fixture);
        let correct_result = good.finalize();

        assert_eq!(result, correct_result);
    }
}
