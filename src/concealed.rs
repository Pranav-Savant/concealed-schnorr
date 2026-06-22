use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, BigInteger};
use ark_groth16::{Groth16,Proof,ProvingKey,VerifyingKey};
use ark_snark::SNARK;
use ark_std::{UniformRand, ops::Mul};
use rand::thread_rng;
use crate::schnorr::{Signature,PublicKey};
use crate::circuit::ConcealedSignatureCircuit;
use crate::utils::{get_poseidon_config,poseidon_hash,poseidon_hash2};

pub struct ParamCS{
    pub pvk:ProvingKey<Bn254>,
    pub vk:VerifyingKey<Bn254>
}

pub struct Commitment{
    pub com:Fr
}

pub struct ConcealedSignature{
    pub proof:Proof<Bn254>,
    pub C:Commitment
}

impl ParamCS {

    pub fn new() -> Self{
        let circuit = ConcealedSignatureCircuit {
            commitment:None,
            pkx:None,
            pky:None,
            m:None,
            t:None,
            c:None,
            z:None,
        };
        let mut rng=thread_rng();
        let (pvk, vk) =Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        Self{pvk,vk}
    }

    pub fn cs_convert(&self,sig:&Signature,m:Fr,pk:&PublicKey)->(ConcealedSignature,Fr){
        let (C,t)=commit(m,&sig);
        // let proof=proof using SNARK
        let pk_affine=pk.pk.into_affine();
        let circuit = ConcealedSignatureCircuit {
            commitment: Some(C.com),
            pkx:Some(pk_affine.x),
            pky:Some(pk_affine.y),
            m: Some(m),
            t: Some(t),
            c: Some(sig.c),
            z: Some(sig.z)
        };
        // let mut rng = StdRng::seed_from_u64(0);
        let mut rng=thread_rng();
        let proof =Groth16::<Bn254>::prove(&self.pvk, circuit, &mut rng).unwrap();
        (ConcealedSignature{proof,C},t)
    }
    
    pub fn cs_verify(&self,pk:&PublicKey,cs:&ConcealedSignature)->bool{
        let public_inputs = vec![cs.C.com];
        let result =Groth16::<Bn254>::verify(&self.vk, &public_inputs, &cs.proof).unwrap();
        result
    }
        
}

fn commit(m:Fr,sig:&Signature)->(Commitment,Fr){
    let mut rng=thread_rng();
    let config=get_poseidon_config();
    let t=Fr::rand(&mut rng);
    let com=poseidon_hash2(sig.c,t,&config);
    (Commitment{com},t)
}
pub fn cs_decommit(m:Fr,sig:&Signature,t:Fr,C:&Commitment,pk:&PublicKey)->bool{
    let g=G1::generator();
    let config=get_poseidon_config();
    let R=g.mul(sig.z)-pk.pk.mul(sig.c);
    let R_affine=R.into_affine();
    let Rx=Fr::from_le_bytes_mod_order(&R_affine.x.into_bigint().to_bytes_le());
    let Ry=Fr::from_le_bytes_mod_order(&R_affine.y.into_bigint().to_bytes_le());
    let cp=poseidon_hash(m, Rx, Ry, &config);
    let comp=poseidon_hash2(cp,t,&config);
    C.com==comp
}
