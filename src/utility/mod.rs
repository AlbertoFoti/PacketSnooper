use std::convert::AsMut;

pub fn clone_into_array<A, T>(slice: &[T]) -> A
    where
        A: Default + AsMut<[T]>,
        T: Clone,
{
    let mut a = A::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

pub fn to_hex16(array: &[u8; 2]) -> u16 {
    ((array[0] as u16) << 8) | array[1] as u16
}