// src/main.rs
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::mem::MaybeUninit;

fn main() {
    unsafe {
        arith_setup();
        random_init();

        // allocate pk and sk on stack (uninitialized)
        let mut pk = MaybeUninit::<pk_t>::uninit();
        let mut sk = MaybeUninit::<sk_t>::uninit();

        // initialize structures
        keys_init(pk.as_mut_ptr(), sk.as_mut_ptr());

        // generate keypair
        keygen(pk.as_mut_ptr(), sk.as_mut_ptr());

        println!("Generated keypair (C side)");

        // clear and teardown
        keys_clear(pk.as_mut_ptr(), sk.as_mut_ptr());
        arith_teardown();
    }
}