use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::net::TcpListener;
use std::ptr;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

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
        let listener = TcpListener::bind("127.0.0.1:4000")?;
        println!("Server listening on 127.0.0.1:4000");

        for stream in listener.incoming() {
            let mut stream = stream?;
            println!("Server: client connected");

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
        }

        keys_clear(pk.as_mut_ptr(), sk.as_mut_ptr());
        arith_teardown();
    }

    Ok(())
}
