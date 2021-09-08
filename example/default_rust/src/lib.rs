#![no_std]

use core::panic::PanicInfo;

mod constants;
mod println;

#[path = "../../../syscall/include/rust/bf_types.rs"]
mod bf_types;
#[path = "../../../syscall/include/rust/bf_constants.rs"]
mod bf_constants;

#[no_mangle]
pub fn ext_main_entry() -> i32 {
    println!("hello world {}\n", 42);
    return 0;
}

#[panic_handler]
pub fn panic_implementation(info: &PanicInfo) -> ! {
    println!("panic: {}\n", info);
    loop{}
}

