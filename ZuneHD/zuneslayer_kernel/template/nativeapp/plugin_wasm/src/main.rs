#![no_std]
#![no_main]


use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
fn wasm_main() -> u32{
    return 32;
}
