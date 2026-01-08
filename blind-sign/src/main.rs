// src/main.rs
use actix_web::web::Data;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::ptr;
use std::sync::Arc;
use std::{
    fs,
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
};
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[derive(Serialize, Deserialize)]
struct BlindSignRequest {
    cmt_coeffs: Vec<i64>,
    tag_coeffs: Vec<i64>,
}

#[derive(Serialize, Deserialize)]
struct BlindSignResponse {
    pre_sig_coeffs: Vec<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct SerializablePoly {
    pub modulus: u64,     // nmod_t.n (mp_limb_t)
    pub coeffs: Vec<i64>, // coeff_q = i64
}

#[derive(Serialize, Deserialize)]
pub struct SerializableVector {
    pub entries: Vec<SerializablePoly>, // length = PARAM_D
}

#[derive(Serialize, Deserialize)]
pub struct SerializableMatrix {
    pub rows: Vec<SerializableVector>, // length = PARAM_D
}

#[derive(Serialize, Deserialize)]
pub struct SerializablePk {
    pub B: Vec<SerializableMatrix>, // length = PARAM_K
    pub seed: Vec<u8>,              // length = SEED_BYTES
}
#[derive(Serialize)]
pub struct PublicKeyResponse {
    /// B[k][row][col][coeff_index]
    pub b: Vec<Vec<Vec<Vec<i64>>>>,
    pub seed: Vec<u8>,
}

unsafe fn serialize_poly_q_vec_d(vec_ptr: *mut __poly_q_vec_d) -> Vec<i64> {
    let mut coeffs = Vec::new();
    for d in 0..PARAM_D {
        let poly_ptr = &mut (*vec_ptr).entries[d as usize] as *mut nmod_poly_struct;
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
pub type SerializedPkB = Vec<Vec<Vec<Vec<i64>>>>;
unsafe fn serialize_pk_b(pk: *const pk_t) -> SerializedPkB {
    let mut result = Vec::with_capacity(PARAM_K as usize);

    for k in 0..PARAM_K as usize {
        let mut matrix = Vec::with_capacity(PARAM_D as usize);

        // B[k] is poly_q_mat_d_d
        let mat = &(*pk).B[k];

        for row in 0..PARAM_D as usize {
            let mut row_vec = Vec::with_capacity(PARAM_D as usize);

            // rows[row] is poly_q_vec_d
            let vec_d = &mat[0].rows[row];

            for col in 0..PARAM_D as usize {
                let poly = &vec_d[0].entries[col];
                let coeffs = serialize_poly_q(&poly[0] as *const _ as *mut nmod_poly_struct);
                row_vec.push(coeffs);
            }

            matrix.push(row_vec);
        }

        result.push(matrix);
    }

    result
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
        let poly_ptr = &mut (*v3_ptr).entries[k as usize] as *mut nmod_poly_struct;
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
    let mut out = Vec::with_capacity(PARAM_D as usize);
    for i in 0..PARAM_D {
        let poly = (*vec)[0].entries[i as usize];
        out.push(serialize_poly_q(&poly as *const _ as *mut nmod_poly_struct));
    }
    out
}

/* unsafe fn poly_to_serializable(poly: &nmod_poly_struct) -> SerializablePoly {
    let modulus = poly.mod_.n as u64;
    let length = poly.length as usize;

    let mut coeffs = Vec::with_capacity(length);
    for i in 0..length {
        let coeff_raw = nmod_poly_get_coeff_ui(poly, i as c_long);
        // FLINT stores coefficients as non-negative residues mod n
        // Cast to i64 (safe if modulus < 2^63, which it usually is)
        coeffs.push(coeff_raw as i64);
    }

    SerializablePoly { modulus, coeffs }
} */
struct KeyPair {
    sk: *const sk_t, // const pointer since we only read
    pk: *const pk_t,
}
unsafe impl Send for KeyPair {}
unsafe impl Sync for KeyPair {}
struct AppState {
    keys: Arc<KeyPair>, // No Mutex needed - just Arc for shared ownership
}

#[post("/blind_sign")]
async fn blind_sign_request(
    data: web::Data<AppState>,
    req: web::Json<BlindSignRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    unsafe {
        let keys = &data.keys;
        // Reconstruct commitment
        let mut cmt = MaybeUninit::<poly_q_vec_d>::uninit();
        poly_q_vec_d_init(cmt.as_mut_ptr() as *mut __poly_q_vec_d);
        deserialize_poly_q_vec_d(cmt.as_mut_ptr() as *mut __poly_q_vec_d, &req.cmt_coeffs);

        // Reconstruct tag
        let mut tag = MaybeUninit::<poly_q>::uninit();
        poly_q_init(tag.as_mut_ptr() as *mut nmod_poly_struct);
        deserialize_poly_q(tag.as_mut_ptr() as *mut nmod_poly_struct, &req.tag_coeffs);
        println!(
            "Client: sent commitment {} and tag coefficients: {:?}",
            req.cmt_coeffs.len(),
            &req.cmt_coeffs[..req.cmt_coeffs.len().min(6)]
        );
        // Generate pre-signature
        let mut pre_sig = MaybeUninit::<pre_sig_t>::uninit();
        pre_sig_init(pre_sig.as_mut_ptr());
        pre_sign_commitment(
            pre_sig.as_mut_ptr(),
            keys.sk as *mut sk_t, // Cast back to mut for C function
            keys.pk as *mut pk_t,
            cmt.as_mut_ptr() as *mut __poly_q_vec_d,
            tag.as_mut_ptr() as *mut nmod_poly_struct,
        );
        println!("Server: pre-signature generated");

        // Serialize pre-signature
        let pre_sig_coeffs = serialize_pre_sig(pre_sig.as_mut_ptr());

        // Cleanup
        poly_q_vec_d_clear(cmt.as_mut_ptr() as *mut __poly_q_vec_d);
        poly_q_clear(tag.as_mut_ptr() as *mut nmod_poly_struct);
        pre_sig_clear(pre_sig.as_mut_ptr());

        Ok(HttpResponse::Ok().json(BlindSignResponse { pre_sig_coeffs }))
    }
}

#[get("/pk")]
async fn pk_get(data: web::Data<AppState>) -> Result<HttpResponse, actix_web::Error> {
    unsafe {
        let keys = &data.keys;

        // Serialize entire pk structure as bytes
        let pk_bytes =
            std::slice::from_raw_parts(keys.pk as *const u8, std::mem::size_of::<pk_t>());
        println!(
            "Server: sending public key ({} bytes): {:?}\n with seed {:?}",
            pk_bytes.len(),
            &pk_bytes[..pk_bytes.len().min(6)],
            &(*keys.pk).seed,
        );

        Ok(HttpResponse::Ok().json(PublicKeyResponse {
            b: serialize_pk_b(&(*keys.pk)),
            seed: (*keys.pk).seed.to_vec(),
        }))
    }
}

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    unsafe {
        arith_setup();
        random_init();

        // Allocate keys on the heap
        let pk_box = Box::new(MaybeUninit::<pk_t>::uninit());
        let sk_box = Box::new(MaybeUninit::<sk_t>::uninit());
        let pk_ptr = Box::into_raw(pk_box) as *mut pk_t;
        let sk_ptr = Box::into_raw(sk_box) as *mut sk_t;

        keys_init(pk_ptr, sk_ptr);
        keygen(pk_ptr, sk_ptr);
        println!("Server: keypair generated");

        let app_state = Data::new(AppState {
            keys: Arc::new(KeyPair {
                sk: sk_ptr,
                pk: pk_ptr,
            }),
        });
        HttpServer::new(move || {
            App::new()
                .app_data(app_state.clone())
                .service(hello)
                .service(pk_get)
                .service(blind_sign_request)
            //.route("/hey", web::get().to(manual_hello))
        })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
    }
}
