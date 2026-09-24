pub const fn any_transmute<Src: Sized + Copy, Dst: Sized + Copy>(val: Src) -> Dst {
    #[repr(C)]
    union _Translator<T: Sized + Copy, U: Sized + Copy> {
        src: T,
        dst: U,
    }

    let translator = _Translator { src: val };

    unsafe { translator.dst }
}
