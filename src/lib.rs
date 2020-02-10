mod utils {
    use blake3::Hasher;
    use std::slice;

    #[inline(always)]
    pub fn deref<'a>(ptr: *const Hasher) -> &'a Hasher {
        assert!(!ptr.is_null());
        unsafe { &*ptr }
    }

    #[inline(always)]
    pub fn deref_mut<'a>(ptr: *mut Hasher) -> &'a mut Hasher {
        assert!(!ptr.is_null());
        unsafe { &mut *ptr }
    }

    #[inline(always)]
    pub fn deref_bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
        assert!(!ptr.is_null());
        unsafe { slice::from_raw_parts(ptr, len) }
    }

    #[inline(always)]
    pub fn deref_bytes_mut<'a>(ptr: *mut u8, len: usize) -> &'a mut [u8] {
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

#[no_mangle]
pub extern "C" fn blake3_new() -> *mut Hasher {
    Box::into_raw(Box::new(Hasher::new()))
}

#[no_mangle]
pub extern "C" fn blake3_new_keyed(ptr: *const u8) -> *mut Hasher {
    let key = deref_bytes(ptr, KEY_LEN);
    Box::into_raw(Box::new(Hasher::new_keyed(key.try_into().unwrap())))
}

#[no_mangle]
pub extern "C" fn blake3_free(ptr: *mut Hasher) {
    free(ptr);
}

#[no_mangle]
pub extern "C" fn blake3_reset(ptr: *mut Hasher) {
    let hasher = deref_mut(ptr);
    hasher.reset();
}

#[no_mangle]
pub extern "C" fn blake3_update(ptr: *mut Hasher, input_ptr: *const u8, input_len: usize) {
    let hasher = deref_mut(ptr);
    let input = deref_bytes(input_ptr, input_len);
    hasher.update(input);
}

#[no_mangle]
pub extern "C" fn blake3_finalize(ptr: *const Hasher, output_ptr: *mut u8, output_len: usize) {
    let hasher = deref(ptr);
    let output = deref_bytes_mut(output_ptr, output_len);
    if output_len == OUT_LEN {
        output.copy_from_slice(hasher.finalize().as_bytes());
    } else {
        hasher.finalize_xof().fill(output);
    }
}
