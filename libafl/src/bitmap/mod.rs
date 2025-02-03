//! Bitmap module for managing bit information.
use alloc::vec::Vec;
use std::fs::File;
use std::io::Read;

/// Bitmap structure used to store bit information.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Bitmap {
    /// Byte array storing the bit information.
    pub buf: Vec<u8>,
}

/// Popcount function for counting the number of set bits in a byte.
pub fn popcount8(b: u8) -> u8 {
    let mut count = 0;
    for i in 0..8 {
        count += (b >> i) & 1;
    }
    return count;
}

impl Bitmap {
    /// Creates a new instance of the bitmap.
    ///
    /// # Arguments
    ///
    /// * `len` - Total length of the bitmap in bits.
    pub fn new(len: usize) -> Bitmap {
        let rounded_len = (len + 7) / 8 * 8;
        Bitmap {
            buf: vec![0; ((rounded_len + 7) / 8).try_into().unwrap()],
        }
    }

    /// Returns the length of the bitmap in bits.
    pub fn len(&self) -> usize {
        self.buf.len() * 8
    }

    /// Retrieves the value of a specific bit index.
    ///
    /// # Arguments
    ///
    /// * `idx` - Index of the bit to query.
    ///
    /// # Returns
    ///
    /// Returns `true` if the bit is set, otherwise returns `false`.
    pub fn get(&self, idx: usize) -> bool {
        if idx >= self.len() {
            panic!("index out of range");
        }

        let byte = self.buf[idx / 8];
        (byte & (1 << (idx % 8))) != 0
    }

    /// Get a specific byte index.
    pub fn get_ubyte(&self, idx: usize) -> u8 {
        // the length of bitmap is always a multiple of 8
        assert_eq!(self.len() % 8, 0);

        if idx >= self.len() / 8 {
            panic!("index out of range");
        }

        let byte = self.buf[idx / 8];
        return byte;
    }

    /// Set a specific byte index.
    pub fn set_ubyte(&mut self, idx: usize, byte: u8) {
        if idx >= self.len() / 8 {
            panic!("index out of range");
        }

        self.buf[idx / 8] = byte;
    }

    /// Sets a specific bit index.
    ///
    /// # Arguments
    ///
    /// * `idx` - Index of the bit to set.
    pub fn set(&mut self, idx: usize) {
        if idx >= self.len() {
            panic!("index out of range");
        }

        self.buf[idx / 8] |= 1 << (idx % 8);
    }

    /// Clears a specific bit index.
    ///
    /// # Arguments
    ///
    /// * `idx` - Index of the bit to clear.
    pub fn clear(&mut self, idx: usize) {
        if idx >= self.len() {
            panic!("index out of range");
        }

        self.buf[idx / 8] &= !(1 << (idx % 8));
    }

    /// Clear all bits in the bitmap.
    pub fn clear_all(&mut self) {
        self.buf.fill(0);
    }
}

impl Default for Bitmap {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Open /dev/random and read 8 bytes to fill a 64-bit random number.
pub fn getrand64() -> usize {
    // open /dev/random
    let mut fobj: File = File::open("/dev/random").unwrap();
    let mut buf: [u8; 8] = [0; 8];
    fobj.read(&mut buf).unwrap();
    return usize::from_be_bytes(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmap() {
        let mut bitmap = Bitmap::new(8);
        assert_eq!(bitmap.len(), 8);
        for i in 0..bitmap.len() {
            assert_eq!(bitmap.get(i), false);
        }

        bitmap.set(0);
        assert_eq!(bitmap.get(0), true);

        bitmap.clear(0);
        assert_eq!(bitmap.get(0), false);
    }

    #[test]
    fn test_random() {
        for _i in 0..5 {
            println!("{}", getrand64());
        }

        // OK
    }
}
