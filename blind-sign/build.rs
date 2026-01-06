use std::env;
use std::path::PathBuf;

fn main() {
    // ---- paths -------------------------------------------------------------

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let code_dir = manifest
        .parent()
        .expect("manifest has no parent")
        .join("code");

    if !code_dir.exists() {
        panic!("Expected `code` in parent directory: {:?}", code_dir);
    }

    // ---- flint -------------------------------------------------------------

    let default_flint = code_dir.join("libs/flint/_build/lib/libflint.so");
    let flint_lib = env::var("FLINT_LIB")
        .map(PathBuf::from)
        .unwrap_or(default_flint);

    // ---- cmake -------------------------------------------------------------

    let dst = cmake::Config::new(&code_dir)
        .define("CMAKE_BUILD_TYPE", "Release")
        .define("FLINT_LIB", flint_lib.to_string_lossy().as_ref())
        .build_target("lbsig")
        .build();

println!(
    "cargo:rustc-link-search=native={}",
    dst.join("build/lib").display()
);    println!("cargo:rustc-link-lib=static=lbsig");
    

    println!("cargo:rustc-link-search=native={}",flint_lib.parent().unwrap().display());
    println!("cargo:rustc-link-lib=dylib=flint");
    // ---- bindgen -----------------------------------------------------------

    let include_dir = code_dir.join("include");
    let signer_h = include_dir.join("bsig_signer.h");
    let user_h   = include_dir.join("bsig_user.h");
    let bsig_verify_h = include_dir.join("bsig_verify.h");

    // rerun when headers change
    println!("cargo:rerun-if-changed={}", signer_h.display());
    println!("cargo:rerun-if-changed={}", user_h.display());

    let include_subs = [
        "",
        "arith",
        "arith/arith_q",
        "arith/arith_p",
        "arith/arith_qiss",
        "arith/arith_qshow",
        "arith/arith_real",
        "arith/arith_z",
    ];

    let mut builder = bindgen::Builder::default()
        .header(signer_h.to_string_lossy())
        .header(user_h.to_string_lossy())
        .header(bsig_verify_h.to_string_lossy())
        // important for modern clang
        .clang_arg("-std=c11");

    for sub in &include_subs {
        let p = include_dir.join(sub);
        builder = builder.clang_arg(format!("-I{}", p.display()));
    }

    let bindings = builder
        .generate()
        .expect("bindgen failed to generate bindings");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_file = out_dir.join("bindings.rs");

    bindings
        .write_to_file(&out_file)
        .expect("failed to write bindings.rs");

    // debug help (safe to keep)
    println!("cargo:warning=generated {}", out_file.display());
}
