use std::io;

#[derive(PartialEq, Eq)]
pub(super) struct PathKey([u64; 3]);

unsafe extern "C" {
    fn aivpn_path_hash(path: *const u8, length: u32, k0: u64, k1: u64, output: *mut u64);
}

impl PathKey {
    pub(super) fn words(&self) -> [u64; 3] {
        self.0
    }
    pub(super) fn new(seed: [u8; 16], path: &[u8], scope: u64) -> io::Result<Self> {
        if path.is_empty() || path.len() >= 4096 || path.contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let [low, high] = hash(seed, path);
        Ok(Self([low, high, scope]))
    }
}

fn hash(seed: [u8; 16], path: &[u8]) -> [u64; 2] {
    let mut result = [0; 2];
    unsafe {
        aivpn_path_hash(
            path.as_ptr(),
            path.len() as u32,
            u64::from_ne_bytes(seed[..8].try_into().unwrap()),
            u64::from_ne_bytes(seed[8..].try_into().unwrap()),
            result.as_mut_ptr(),
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_c_hash_matches_independent_siphash_128_vectors() {
        // CC0: https://github.com/veorq/SipHash/blob/master/vectors.h
        let key = std::array::from_fn(|index| index as u8);
        let input: Vec<u8> = (0..64).collect();
        for (length, expected) in [
            (0, [16620575905680425379, 10593123587058759277]),
            (1, [4949343203980576730, 5042943732154463796]),
            (7, [6035346699615728033, 4144138625858844864]),
            (8, [7058645172034822715, 13012892683912512271]),
            (15, [1272460630404207444, 15691613774403078270]),
            (63, [5369223345559654481, 8988410351658090064]),
        ] {
            assert_eq!(hash(key, &input[..length]), expected, "length={length}");
        }
    }

    #[test]
    fn paths_are_bounded_and_scope_is_part_of_the_complete_key() {
        for path in [vec![], vec![b'/'; 4096], b"/app\0suffix".to_vec()] {
            assert!(PathKey::new([0; 16], &path, 0).is_err());
        }
        let maximum = vec![b'/'; 4095];
        assert!(PathKey::new([0; 16], &maximum, 0).is_ok());
        let physical = PathKey::new([0; 16], b"/app", 0).unwrap();
        assert!(physical != PathKey::new([0; 16], b"/app", 1).unwrap());
        assert!(physical != PathKey::new([0; 16], b"/app", u64::MAX).unwrap());
        assert!(physical != PathKey::new([1; 16], b"/app", 0).unwrap());
        assert!(physical != PathKey::new([0; 16], b"/other", 0).unwrap());
    }
}
