use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::ptr;
use std::{
    fs,
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
};
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
extern crate regex;

use regex::Regex;
unsafe fn serialize_poly_q_vec_d(vec_ptr: *mut __poly_q_vec_d) -> Vec<i64> {
    let mut coeffs = Vec::new();
    for d in 0..PARAM_D {
        let poly_ptr = &mut (*vec_ptr).entries[d as usize][0] as *mut nmod_poly_struct;
        for i in 0..PARAM_N {
            coeffs.push(poly_q_get_coeff(poly_ptr, i as usize));
        }
    }
    coeffs
}

unsafe fn deserialize_poly_q_vec_d(vec_ptr: *mut __poly_q_vec_d, coeffs: &[i64]) {
    let mut idx = 0;
    for d in 0..PARAM_D {
        let poly_ptr = &mut (*vec_ptr).entries[d as usize] as *mut _ as *mut nmod_poly_struct;
        for i in 0..PARAM_N {
            poly_q_set_coeff(poly_ptr, i as usize, coeffs[idx]);
            idx += 1;
        }
    }
}

unsafe fn serialize_poly_q(poly_ptr: *mut nmod_poly_struct) -> Vec<i64> {
    (0..PARAM_N)
        .map(|i| poly_q_get_coeff(poly_ptr, i as usize))
        .collect()
}

unsafe fn deserialize_poly_q(poly_ptr: *mut nmod_poly_struct, coeffs: &[i64]) {
    for (i, &coeff) in coeffs.iter().enumerate() {
        poly_q_set_coeff(poly_ptr, i, coeff);
    }
}

unsafe fn serialize_pre_sig(pre_sig_ptr: *mut pre_sig_t) -> Vec<i64> {
    let mut all_coeffs = Vec::new();

    // v12
    let v12_ptr = &mut (*pre_sig_ptr).v12[0] as *mut __poly_q_vec_d;
    all_coeffs.extend(serialize_poly_q_vec_d(v12_ptr));

    // v2[PARAM_K]
    for k in 0..PARAM_K {
        let v2_ptr = &mut (*pre_sig_ptr).v2[k as usize][0] as *mut __poly_q_vec_d;
        all_coeffs.extend(serialize_poly_q_vec_d(v2_ptr));
    }

    // v3
    let v3_ptr = &mut (*pre_sig_ptr).v3[0] as *mut __poly_q_vec_k;
    for k in 0..PARAM_K {
        let poly_ptr = &mut (*v3_ptr).entries[k as usize][0] as *mut nmod_poly_struct;
        all_coeffs.extend(serialize_poly_q(poly_ptr));
    }

    all_coeffs
}

fn send_coeffs<W: Write>(stream: &mut W, coeffs: &[i64]) -> std::io::Result<()> {
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            coeffs.as_ptr() as *const u8,
            coeffs.len() * std::mem::size_of::<i64>(),
        )
    };
    stream.write_all(&(bytes.len() as u64).to_le_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}

fn recv_coeffs<R: Read>(stream: &mut R) -> std::io::Result<Vec<i64>> {
    let mut size_buf = [0u8; 8];
    stream.read_exact(&mut size_buf)?;
    let size = u64::from_le_bytes(size_buf) as usize;

    let mut bytes = vec![0u8; size];
    stream.read_exact(&mut bytes)?;

    let coeffs = unsafe {
        std::slice::from_raw_parts(
            bytes.as_ptr() as *const i64,
            size / std::mem::size_of::<i64>(),
        )
        .to_vec()
    };
    Ok(coeffs)
}

unsafe fn serialize_vec_d(vec: *const poly_q_vec_d) -> Vec<Vec<i64>> {
    let mut out = Vec::with_capacity(PARAM_D.try_into().unwrap());
    for i in 0..PARAM_D {
        let poly = (*vec)[0].entries[i as usize];
        out.push(serialize_poly_q(&poly as *const _ as *mut nmod_poly_struct));
    }
    out
}

/* unsafe fn serialize_pk(pk: *const pk_t) -> (Vec<Vec<Vec<Vec<i64>>>>, Vec<u8>) {
    let mut b_serialized = Vec::with_capacity(PARAM_K.try_into().unwrap());
    for k in 0..PARAM_K {
        let mat = &(*pk).B[k as usize][0];
        let mut mat_serialized = Vec::with_capacity(PARAM_D.try_into().unwrap());
        for row in 0..PARAM_D {
            let poly_row = &mat.rows[row as usize];
            mat_serialized.push(serialize_vec_d(poly_row));
        }
        b_serialized.push(mat_serialized);
    }

    let seed = std::slice::from_raw_parts((*pk).seed.as_ptr(), SEED_BYTES as usize).to_vec();
    (b_serialized, seed)
} */
/* unsafe fn blind_sign_request(
    stream: &mut TcpStream,
    sk: &mut MaybeUninit<sk_t>,
    pk: &mut MaybeUninit<pk_t>,
) {
    // Receive and reconstruct commitment
    let cmt_coeffs = recv_coeffs(&mut stream)?;
    let mut cmt = MaybeUninit::<poly_q_vec_d>::uninit();
    poly_q_vec_d_init(cmt.as_mut_ptr() as *mut __poly_q_vec_d);
    deserialize_poly_q_vec_d(cmt.as_mut_ptr() as *mut __poly_q_vec_d, &cmt_coeffs);
    println!(
        "Server: received commitment {}: {:?}",
        cmt_coeffs.len(),
        &cmt_coeffs[..cmt_coeffs.len().min(6)]
    );

    // Receive and reconstruct tag
    let tag_coeffs = recv_coeffs(&mut stream)?;
    let mut tag = MaybeUninit::<poly_q>::uninit();
    poly_q_init(tag.as_mut_ptr() as *mut nmod_poly_struct);
    deserialize_poly_q(tag.as_mut_ptr() as *mut nmod_poly_struct, &tag_coeffs);
    println!("Server: received tag");

    // Generate pre-signature
    let mut pre_sig = MaybeUninit::<pre_sig_t>::uninit();
    pre_sig_init(pre_sig.as_mut_ptr());
    pre_sign_commitment(
        pre_sig.as_mut_ptr(),
        sk.as_mut_ptr(),
        pk.as_mut_ptr(),
        cmt.as_mut_ptr() as *mut __poly_q_vec_d,
        tag.as_mut_ptr() as *mut nmod_poly_struct,
    );
    println!("Server: pre-signature generated");

    // Send pre-signature
    let pre_sig_coeffs = serialize_pre_sig(pre_sig.as_mut_ptr());
    send_coeffs(&mut stream, &pre_sig_coeffs)?;
    println!(
        "Server: sent pre-signature ({} coefficients)",
        pre_sig_coeffs.len()
    );

    // Cleanup
    poly_q_vec_d_clear(cmt.as_mut_ptr() as *mut __poly_q_vec_d);
    poly_q_clear(tag.as_mut_ptr() as *mut nmod_poly_struct);
    pre_sig_clear(pre_sig.as_mut_ptr());
} */
fn handle_connection(stream: &mut TcpStream) {
    let buf_reader = BufReader::new(stream);
    let request_line = buf_reader.lines().next().unwrap().unwrap();

    let re_pk = Regex::new(r"GET\s/pk").unwrap();
    let re_blind_sign = Regex::new(r"GET\s/blind_sign").unwrap();

    let (_, filename) = if re_pk.is_match(&request_line) {
        ("HTTP/1.1 200 OK", "pk.html")
    } else if re_blind_sign.is_match(&request_line) {
        ("HTTP/1.1 200 OK", "blind.html")
    } else {
        ("HTTP/1.1 404 NOT FOUND", "404.html")
    };
    println!("{}, {}", request_line, filename);

    /* let contents = fs::read_to_string(filename).unwrap();
    let length = contents.len();

    let response = format!("{status_line}\r\nContent-Length: {length}\r\n\r\n{contents}");

    stream.write_all(response.as_bytes()).unwrap(); */
}

use actix_web::{get, web::Data, App, HttpResponse, HttpServer, Responder};

#[get("/pk")]
async fn pk() -> impl Responder {
    HttpResponse::Ok().body("Hello pk!")
}

#[get("/blind_sign")]
async fn blind_sign() -> impl Responder {
    HttpResponse::Ok().body("Hello blind_sign!")
}

/* #[actix_web::main]
async fn main() -> std::io::Result() {
    /* let db = Database::init().await;
    let db_data = Data::new(db); */
    HttpServer::new(move || {
        App::new()
            //.app_data(db_data.clone())
            .service(pk)
            .service(blind_sign)
    })
    .bind(("127.0.0.1", 4000))?
    .run()
    .await
} */
/* fn main() -> std::io::Result<()> {
    unsafe {
        arith_setup();
        random_init();

        let mut pk = MaybeUninit::<pk_t>::uninit();
        let mut sk = MaybeUninit::<sk_t>::uninit();
        keys_init(pk.as_mut_ptr(), sk.as_mut_ptr());

        //let fixed_seed = [42u8; SEED_BYTES as usize];
        // Derive seed from a string (if SEED_BYTES is 32)
        let seed_string = b"my_fixed_seed_for_testing";
        let mut fixed_seed = [0u8; SEED_BYTES as usize];
        fixed_seed[..seed_string.len().min(SEED_BYTES as usize)]
            .copy_from_slice(&seed_string[..seed_string.len().min(SEED_BYTES as usize)]);
        ptr::copy_nonoverlapping(
            fixed_seed.as_ptr(),
            (*pk.as_mut_ptr()).seed.as_mut_ptr(),
            SEED_BYTES as usize,
        );

        keygen(pk.as_mut_ptr(), sk.as_mut_ptr());
        println!("Server: keypair generated (using fixed seed)");

        // Print seed
        let pk_seed = &(*pk.as_ptr()).seed;
        println!("Seed (first 16 bytes): {:02x?}", &pk_seed[..16]);

        // Print a hash/checksum of the entire pk structure for comparison
        let pk_bytes: &[u8] =
            std::slice::from_raw_parts(pk.as_ptr() as *const u8, std::mem::size_of::<pk_t>());
        let checksum: u64 = pk_bytes
            .iter()
            .take(64)
            .fold(0u64, |acc, &b| acc.wrapping_add(b as u64));
        println!("PK checksum (first 64 bytes): {}", checksum);
        let listener = TcpListener::bind("127.0.0.1:4000").unwrap();
        println!("Server listening on 127.0.0.1:4000");

        for stream in listener.incoming() {
            //let stream = stream.unwrap();

            handle_connection(stream);
        }

        keys_clear(pk.as_mut_ptr(), sk.as_mut_ptr());
        arith_teardown();
    }

    Ok(())
} */
