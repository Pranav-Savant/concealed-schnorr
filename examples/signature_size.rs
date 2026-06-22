use concealed_schnorr::*;
use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::PrimeGroup;
use ark_serialize::CanonicalSerialize;

fn serialized_size<T: CanonicalSerialize>(obj: &T) -> usize {
    let mut bytes = Vec::new();
    obj.serialize_compressed(&mut bytes).unwrap();
    bytes.len()
}

fn main() {
    let g = G1::generator();
    let m = Fr::from(55u64);
    let (sk, pk) =Schnorr::keyGen(g);
    let sig =Schnorr::Sign(g,m,&sk);
    let pcs = ParamCS::new();
    let (cs, _) =pcs.cs_convert(&sig,m,&pk);
    
    println!("Public Key Size: {} bytes",serialized_size(&pk.pk));
    println!("Schnorr Signature Size: {} bytes",serialized_size(&sig.c)+serialized_size(&sig.z));
    println!("Commitment Size: {} bytes",serialized_size(&cs.C.com));
    println!("Groth16 Proof Size: {} bytes",serialized_size(&cs.proof));
    println!("Concealed Signature Size: {} bytes",serialized_size(&cs.proof)+ serialized_size(&cs.C.com));
}