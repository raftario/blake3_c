mod utils {
    use std::slice;

    #[inline(always)]
    pub fn deref<'a, T>(ptr: *const T) -> &'a T {
        assert!(!ptr.is_null());
        unsafe { &*ptr }
    }

    #[inline(always)]
    pub fn deref_mut<'a, T>(ptr: *mut T) -> &'a mut T {
        assert!(!ptr.is_null());
        unsafe { &mut *ptr }
    }

    #[inline(always)]
    pub fn deref_slice<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
        assert!(!ptr.is_null());
        unsafe { slice::from_raw_parts(ptr, len) }
    }

    #[inline(always)]
    pub fn deref_slice_mut<'a, T>(ptr: *mut T, len: usize) -> &'a mut [T] {
        assert!(!ptr.is_null());
        unsafe { slice::from_raw_parts_mut(ptr, len) }
    }

    #[inline(always)]
    pub fn free<T>(ptr: *mut T) {
        if ptr.is_null() {
            return;
        }
        unsafe { Box::from_raw(ptr) };
    }
}

use blake3::{Hasher, KEY_LEN, OUT_LEN};
use std::convert::TryInto;
use utils::*;

/// Construct a new BLAKE3 `Hasher` for the regular hash function.
///
/// ```c
/// void* blake3_new()
/// ```
#[no_mangle]
pub extern "C" fn blake3_new() -> *mut Hasher {
    Box::into_raw(Box::new(Hasher::new()))
}

/// Construct a new BLAKE3 `Hasher` for the keyed hash function.
/// The key is assumed to be 32 bytes long.
///
/// ```c
/// void* blake3_new_keyed(uint8_t* key_ptr)
/// ```
#[no_mangle]
pub extern "C" fn blake3_new_keyed(key_ptr: *const u8) -> *mut Hasher {
    let key = deref_slice(key_ptr, KEY_LEN);
    Box::into_raw(Box::new(Hasher::new_keyed(key.try_into().unwrap())))
}

/// Free a BLAKE3 `Hasher`.
///
/// ```c
/// void blake3_free(void* ptr)
/// ```
#[no_mangle]
pub extern "C" fn blake3_free(ptr: *mut Hasher) {
    free(ptr);
}

/// Reset a BLAKE3 `Hasher` to its initial state.
///
/// ```c
/// void blake3_reset(void* ptr)
/// ```
#[no_mangle]
pub extern "C" fn blake3_reset(ptr: *mut Hasher) {
    let hasher = deref_mut(ptr);
    hasher.reset();
}

/// Add input bytes to the hash state of a BLAKE3 `Hasher`.
///
/// ```c
/// void blake3_update(void* ptr, uint8_t* const input_ptr, size_t input_len)
/// ```
#[no_mangle]
pub extern "C" fn blake3_update(ptr: *mut Hasher, input_ptr: *const u8, input_len: usize) {
    let hasher = deref_mut(ptr);
    let input = deref_slice(input_ptr, input_len);
    hasher.update(input);
}

/// Finalize the hash state of a BLAKE3 `Hasher` fills the output array with the hash of the input.
/// The `Hasher` isn't consumed in the process.
///
/// ```c
/// void blake3_finalize(void* const ptr, uint8_t* output_ptr, size_t output_len)
/// ```
#[no_mangle]
pub extern "C" fn blake3_finalize(ptr: *const Hasher, output_ptr: *mut u8, output_len: usize) {
    let hasher = deref(ptr);
    let output = deref_slice_mut(output_ptr, output_len);
    if output_len == OUT_LEN {
        output.copy_from_slice(hasher.finalize().as_bytes());
    } else {
        hasher.finalize_xof().fill(output);
    }
}
