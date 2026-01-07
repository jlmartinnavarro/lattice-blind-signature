use reqwest;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::ptr;

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
#[derive(Deserialize)]
pub struct PublicKeyResponse {
    /// B[k][row][col][coeff_index]
    pub b: Vec<Vec<Vec<Vec<i64>>>>,
    pub seed: Vec<u8>,
}
unsafe fn serialize_poly_q_vec_d(vec_ptr: *mut __poly_q_vec_d) -> Vec<i64> {
    let mut coeffs = Vec::new();
    for d in 0..PARAM_D {
        let poly_ptr = &mut (*vec_ptr).entries[d as usize] as *mut _ as *mut nmod_poly_struct;
        for i in 0..PARAM_N {
            coeffs.push(poly_q_get_coeff(poly_ptr, i as usize));
        }
    }
    coeffs
}

/*unsafe fn serialize_poly_q(poly_ptr: *mut nmod_poly_struct) -> Vec<i64> {
    (0..PARAM_N)
        .map(|i| poly_q_get_coeff(poly_ptr, i as usize))
        .collect()
}
 */
use flint_sys::nmod_poly::*;

unsafe fn serialize_poly_q(poly: *const nmod_poly_struct) -> Vec<i64> {
    let len = nmod_poly_length(poly);
    let mut coeffs = Vec::with_capacity(len as usize);

    for i in 0..len {
        let c = nmod_poly_get_coeff_ui(poly, i);
        coeffs.push(c as i64);
    }

    coeffs
}

unsafe fn deserialize_pre_sig(pre_sig_ptr: *mut pre_sig_t, coeffs: &[i64]) {
    let mut idx = 0;

    // v12
    let v12_ptr = &mut (*pre_sig_ptr).v12[0] as *mut __poly_q_vec_d;
    for d in 0..PARAM_D {
        let poly_ptr = &mut (*v12_ptr).entries[d as usize][0] as *mut nmod_poly_struct;
        for i in 0..PARAM_N {
            poly_q_set_coeff(poly_ptr, i as usize, coeffs[idx]);
            idx += 1;
        }
    }

    // v2[PARAM_K]
    for k in 0..PARAM_K {
        let v2_ptr = &mut (*pre_sig_ptr).v2[k as usize][0] as *mut __poly_q_vec_d;
        for d in 0..PARAM_D {
            let poly_ptr = &mut (*v2_ptr).entries[d as usize][0] as *mut nmod_poly_struct;
            for i in 0..PARAM_N {
                poly_q_set_coeff(poly_ptr, i as usize, coeffs[idx]);
                idx += 1;
            }
        }
    }

    // v3
    let v3_ptr = &mut (*pre_sig_ptr).v3[0] as *mut __poly_q_vec_k;
    for k in 0..PARAM_K {
        let poly_ptr = &mut (*v3_ptr).entries[k as usize][0] as *mut nmod_poly_struct;
        for i in 0..PARAM_N {
            poly_q_set_coeff(poly_ptr, i as usize, coeffs[idx]);
            idx += 1;
        }
    }
}

unsafe fn load_pk_from_serialized(
    serialized_b: &Vec<Vec<Vec<Vec<i64>>>>, // [K][D][D][coeffs]
    seed: &[u8; SEED_BYTES as usize],
) -> pk_t {
    // Allocate uninitialized pk
    let mut pk = MaybeUninit::<pk_t>::uninit();

    // IMPORTANT: initialize pk (this initializes ALL poly_q inside)
    keys_init(pk.as_mut_ptr(), std::ptr::null_mut());

    let pk = &mut *pk.as_mut_ptr();

    // Fill matrix B
    for k in 0..PARAM_K as usize {
        for row in 0..PARAM_D as usize {
            for col in 0..PARAM_D as usize {
                let coeffs = &serialized_b[k][row][col];

                let poly: *mut poly_q = &mut pk.B[k][0].rows[row].entries[col];

                // Always zero first
                poly_q_zero(poly);

                for (i, &c) in coeffs.iter().enumerate() {
                    poly_q_set_coeff(poly, i, c);
                }
            }
        }
    }

    // Copy seed
    pk.seed.copy_from_slice(seed);

    *pk
}
/* fn send_coeffs<W: Write>(stream: &mut W, coeffs: &[i64]) -> std::io::Result<()> {
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

unsafe fn deserialize_poly_q(poly_ptr: *mut nmod_poly_struct, coeffs: &[i64]) {
    for (i, &coeff) in coeffs.iter().enumerate() {
        poly_q_set_coeff(poly_ptr, i, coeff);
    }
} */

/* unsafe fn deserialize_pk(data: &Vec<Vec<Vec<i64>>>, seed: &[u8], pk: *mut pk_t) {
    for k in 0..PARAM_K {
        let mat_serialized = &data[k as usize];
        let mat: &mut __poly_q_mat_d_d = &mut (*pk).B[k as usize]; // IMPORTANT: &mut __poly_q_mat_d_d

        for row in 0..PARAM_D {
            let row_serialized = &mat_serialized[row as usize];

            // rows[row] is [__poly_q_vec_d;1], so take [0]
            let poly_row: &mut __poly_q_vec_d = &mut mat.rows[row as usize][0];

            for i in 0..PARAM_D {
                let coeffs = &row_serialized[i as usize];
                let poly: &mut nmod_poly_struct = &mut poly_row.entries[i as usize];
                deserialize_poly_q(poly as *mut _, coeffs);
            }
        }
    }

    // Copy the seed
    (*pk).seed.copy_from_slice(seed);
}
 */

fn main() -> std::io::Result<()> {
    unsafe {
        arith_setup();
        random_init();
        println!("Client: arithmetic and random initialized");
        // Initialize keys (same seed as server)
        let mut pk = MaybeUninit::<pk_t>::uninit();
        let mut sk = MaybeUninit::<sk_t>::uninit();
        keys_init(pk.as_mut_ptr(), sk.as_mut_ptr());
        let client = reqwest::blocking::Client::new();

        let pk_response: PublicKeyResponse = client
            .get("http://127.0.0.1:8080/pk")
            .send()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
            .json()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?; //

        println!(
            "Client: received public key ({} bytes): {:?}}\n seed: {:?}",
            &pk_response.b.len(),
            &pk_response.b[..pk_response.b.len().min(6)],
            &pk_response.seed
        );
        /* let blind_sign_response: BlindSignResponse = response_pk
                   .json::<BlindSignResponse>()
                   .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?; // Now call json() on Response
        */
        // After keygen() call
        /*       assert_eq!(pk_response.pk_bytes.len(), std::mem::size_of::<pk_t>());
               ptr::copy_nonoverlapping(
                   pk_response.pk_bytes.as_ptr(),
                   pk.as_mut_ptr() as *mut u8,
                   pk_response.pk_bytes.len(),
               );
        */
        //        let pk = load_pk_from_serialized(&pk_data.b, &pk_data.seed);
        let pk = unsafe {
            load_pk_from_serialized(&pk_response.b, &pk_response.seed.try_into().unwrap())
        };
        println!("Client: public key reconstructed");
        //keygen(pk.as_mut_ptr(), sk.as_mut_ptr());

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
        // Prepare message
        let message = b"Hello world!";
        let mut msg = [0u8; (PARAM_N as usize) / 8];
        msg[..message.len()].copy_from_slice(message);

        // Generate commitment
        let mut rand = MaybeUninit::<rand_t>::uninit();
        rand_init(rand.as_mut_ptr());
        println!("Client: random generated");

        let mut cmt = MaybeUninit::<poly_q_vec_d>::uninit();
        let mut tag = MaybeUninit::<poly_q>::uninit();
        let mut state = [0u8; STATE_BYTES as usize];
        poly_q_vec_d_init(cmt.as_mut_ptr() as *mut __poly_q_vec_d);
        poly_q_init(tag.as_mut_ptr() as *mut nmod_poly_struct);
        randombytes(state.as_mut_ptr(), STATE_BYTES as usize);

        println!("Client: init generated");
        tag_gen(
            tag.as_mut_ptr() as *mut nmod_poly_struct,
            state.as_mut_ptr(),
        );
        println!("Client: tag generated");

        commit(
            rand.as_mut_ptr(),
            cmt.as_mut_ptr() as *mut __poly_q_vec_d,
            tag.as_mut_ptr() as *mut nmod_poly_struct,
            msg.as_mut_ptr(),
            pk.as_mut_ptr(),
        );
        println!("Client: commitment generated");

        // Send commitment and tag
        let cmt_coeffs = serialize_poly_q_vec_d(cmt.as_mut_ptr() as *mut __poly_q_vec_d);
        //send_coeffs(&mut stream, &cmt_coeffs)?;

        let tag_coeffs = serialize_poly_q(tag.as_mut_ptr() as *mut nmod_poly_struct);

        println!(
            "Client: sent commitment {} and tag {} coefficients: {:?}",
            cmt_coeffs.len(),
            tag_coeffs.len(),
            &cmt_coeffs[..cmt_coeffs.len().min(6)]
        );

        let request_data = BlindSignRequest {
            cmt_coeffs: cmt_coeffs,
            tag_coeffs: tag_coeffs,
        };
        // In your client code, replace the TCP stream parts with:

        let response = client
            .post("http://127.0.0.1:8080/blind_sign")
            .json(&request_data)
            .send()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let blind_sign_response: BlindSignResponse = response
            .json::<BlindSignResponse>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?; // Now call json() on Response
                                                                              //            .json::<BlindSignResponse>();

        let pre_sig_coeffs = blind_sign_response.pre_sig_coeffs;
        println!(
            "Client: received pre-signature ({} coefficients)",
            pre_sig_coeffs.len()
        );

        // Receive and reconstruct pre-signature
        let mut pre_sig = MaybeUninit::<pre_sig_t>::uninit();
        pre_sig_init(pre_sig.as_mut_ptr());
        deserialize_pre_sig(pre_sig.as_mut_ptr(), &pre_sig_coeffs);
        println!(
            "Client: received pre-signature ({} coefficients)",
            pre_sig_coeffs.len()
        );

        // Verify pre-signature
        let mut v11 = MaybeUninit::<poly_q_vec_d>::uninit();
        poly_q_vec_d_init(v11.as_mut_ptr() as *mut __poly_q_vec_d);

        let is_valid = pre_sig_verify_from_commitment(
            v11.as_mut_ptr() as *mut __poly_q_vec_d,
            tag.as_mut_ptr() as *mut nmod_poly_struct,
            pre_sig.as_ptr(),
            cmt.as_mut_ptr() as *mut __poly_q_vec_d,
            pk.as_ptr(),
        );

        if is_valid == 0 {
            eprintln!("ERROR: pre-signature verification failed");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid pre-signature",
            ));
        }
        println!("Client: pre-signature verified");

        // Complete decompose
        let mut bsig = MaybeUninit::<bsig_t>::uninit();
        bsig_init(bsig.as_mut_ptr());

        let mut w1H: [MaybeUninit<poly_q_vec_d>; 2] =
            [MaybeUninit::uninit(), MaybeUninit::uninit()];
        for i in 0..2 {
            poly_q_vec_d_init(w1H[i].as_mut_ptr() as *mut __poly_q_vec_d);
        }

        let mut w2H: [MaybeUninit<poly_q_vec_d>; PARAM_K as usize] =
            [(); PARAM_K as usize].map(|_| MaybeUninit::uninit());
        for i in 0..PARAM_K as usize {
            poly_q_vec_d_init(w2H[i].as_mut_ptr() as *mut __poly_q_vec_d);
        }

        let mut w3H = MaybeUninit::<poly_q_vec_k>::uninit();
        poly_q_vec_k_init(w3H.as_mut_ptr() as *mut __poly_q_vec_k);

        complete_decompose(
            bsig.as_mut_ptr() as *mut _,
            w1H.as_mut_ptr() as *mut _,
            w2H.as_mut_ptr() as *mut _,
            w3H.as_mut_ptr() as *mut _,
            v11.as_mut_ptr() as *mut _,
            pre_sig.as_mut_ptr(),
            rand.as_mut_ptr(),
        );
        println!("Client: signature completed");

        // Verify signature
        let valid = bsig_verify(bsig.as_ptr(), pk.as_ptr(), msg.as_ptr());
        println!("Client: signature valid? {}", valid != 0);

        // Cleanup
        bsig_clear(bsig.as_mut_ptr());
        for i in 0..2 {
            poly_q_vec_d_clear(w1H[i].as_mut_ptr() as *mut __poly_q_vec_d);
        }
        for i in 0..PARAM_K as usize {
            poly_q_vec_d_clear(w2H[i].as_mut_ptr() as *mut __poly_q_vec_d);
        }
        poly_q_vec_k_clear(w3H.as_mut_ptr() as *mut __poly_q_vec_k);
        poly_q_vec_d_clear(v11.as_mut_ptr() as *mut __poly_q_vec_d);
        poly_q_vec_d_clear(cmt.as_mut_ptr() as *mut __poly_q_vec_d);
        poly_q_clear(tag.as_mut_ptr() as *mut nmod_poly_struct);
        pre_sig_clear(pre_sig.as_mut_ptr());
        keys_clear(pk.as_mut_ptr(), std::ptr::null_mut());
        rand_clear(rand.as_mut_ptr());
        arith_teardown();
    }

    Ok(())
}
