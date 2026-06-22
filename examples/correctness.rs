use concealed_schnorr::{
    Schnorr,
    ParamCS,
    cs_decommit
};

use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::PrimeGroup;

fn main() {

    let g = G1::generator();
    let m = Fr::from(911u64);
    
    let (sk, pk) =Schnorr::keyGen(g);

    let sig =Schnorr::Sign(g,m,&sk);
    
    println!("Signature Verify : {}",Schnorr::verify(g,&pk,&sig,m));
    
    let pcs = ParamCS::new();
    
    let (cs, t) =pcs.cs_convert(&sig,m,&pk);
    
    println!("Concealed Verify : {}",pcs.cs_verify(&pk,&cs));
    
    println!("Decommit : {}",cs_decommit(m,&sig,t,&cs.C,&pk));
}