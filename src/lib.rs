

// Allow `cargo stylus export-abi` to generate a main function.
#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

use alloc::{vec::Vec};
use std::io::Cursor;


/// Use an efficient WASM allocator.
#[global_allocator]
static ALLOC: mini_alloc::MiniAlloc = mini_alloc::MiniAlloc::INIT;

/// Import items from the SDK. The prelude contains common traits and macros.
use stylus_sdk::{  prelude::*};


use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::One;
use ark_groth16::{PreparedVerifyingKey};
use rand_core::SeedableRng;

// use snarkpack::{proof::AggregateProof, srs::VerifierSRS, transcript::Transcript};
mod snarkpack;
use snarkpack::{proof::AggregateProof, srs::VerifierSRS, transcript::Transcript};



// // 反序列化
use ark_serialize::{CanonicalDeserialize};

sol_storage! {
    #[entrypoint]
    pub struct Verifier {
        
    }
}

// 实现链上验证聚合证明的逻辑
#[external]
impl Verifier{
    pub fn verify_aggregate_proof_custom(
        ver_srs_bytes: Vec<u8>,
        pvk_bytes: Vec<u8>,
        aggregate_proof_bytes: Vec<u8>
    )-> bool{

        // let ver_srs_uncompressed: snarkpack::srs::VerifierSRS<Bls12_381> = snarkpack::srs::VerifierSRS::deserialize_compressed(ver_srs_cursor).unwrap();
        // 创建一个Cursor，它实现了std::io::Read
        let ver_srs_cursor = Cursor::new(ver_srs_bytes);
        // 反序列化ver_srs
        let ver_srs_uncompressed: snarkpack::srs::VerifierSRS<Bls12_381> = match snarkpack::srs::VerifierSRS::deserialize_compressed(ver_srs_cursor){
            Ok(srs) => srs,
            Err(_) => return false,
        };
        
        let pvk_cursor = Cursor::new(pvk_bytes);
        // 反序列化pvk
        let pvk_uncompressed: PreparedVerifyingKey<Bls12_381> = match PreparedVerifyingKey::deserialize_compressed(pvk_cursor){
            Ok(pvk) => pvk,
            Err(_) => return false,
        };
        
        let aggregate_proof_cursor = Cursor::new(aggregate_proof_bytes);
        // 反序列化aggregate_proof
        let aggregate_proof_uncompressed: snarkpack::proof::AggregateProof<Bls12_381> = match snarkpack::proof::AggregateProof::deserialize_compressed(aggregate_proof_cursor){
            Ok(proof) => proof,
            Err(_) => return false,
        };
        
        let nproofs = 8; // 被聚合的证明数量
        // 创建公开输入
        let inputs: Vec<_> = [Fr::one(); 2].to_vec(); // 创建一个包含两个单位元的输入向量，用于证明验证
        let all_inputs = (0..nproofs).map(|_| inputs.clone()).collect::<Vec<_>>(); // 为每个证明复制这个输入向量
        
        // 创建ver_transcript
        let mut ver_transcript = snarkpack::transcript::new_merlin_transcript(b"test aggregation");
        ver_transcript.append(b"public-inputs", &all_inputs);

        
        // 创建随机数生成器
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(1u64);

        match snarkpack::verify_aggregate_proof(
            &ver_srs_uncompressed,
            &pvk_uncompressed,
            &all_inputs,
            &aggregate_proof_uncompressed,
            &mut rng,
            &mut ver_transcript,
        ){
            Ok(_) => true,
            Err(_) => false,
        }
       
    }
    
}
