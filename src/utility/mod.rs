use std::convert::AsMut;
use std::fmt::{Write};

pub fn clone_into_array<A, T>(slice: &[T]) -> A
where
    A: Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = A::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

pub fn to_u16(array: &[u8; 2]) -> u16 {
    ((array[0] as u16) << 8) | array[1] as u16
}

pub fn to_compact_hex(vector_u8: &[u8]) -> String {
    const MAXIMUM_PRINTABLE_PAYLOAD : usize = 75;

    let mut res = String::new();
    let mut i = 0;
    for &byte in vector_u8 {
        write!(&mut res, "{:02x}", byte).expect("Unable to write");
        i += 1;
        if i >= MAXIMUM_PRINTABLE_PAYLOAD {
            write!(&mut res, "...").expect("Unable to write");
            break;
        }
    }
    res
}

