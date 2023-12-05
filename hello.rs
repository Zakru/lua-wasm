#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::ffi::c_char;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

extern "C" {
    #[link_name = "print"]
    fn n_print(msg: *const c_char, len: usize);
}

fn print(msg: &str) {
    unsafe { n_print(msg.as_bytes().as_ptr() as *const i8, msg.len()); }
}

#[no_mangle]
extern "C" fn main() {
    print("Hello, world!");
}
