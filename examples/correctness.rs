use concealed_schnorr::{
    Schnorr,
    ParamCS,
    cs_decommit
};

use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::PrimeGroup;
use  std::time::Instant;
fn main() {

    let g = G1::generator();
    let m = Fr::from(911u64);

    let start=Instant::now();
    let (sk, pk) =Schnorr::keyGen(g);
    println!("Key Generation Time:{:?}",start.elapsed());
    
    let sig =Schnorr::Sign(g,m,&sk);
    
    println!("Signature Verify : {}",Schnorr::verify(g,&pk,&sig,m));
    
    let start=Instant::now();
    let pcs = ParamCS::new();
    println!("CS Setup Time:{:?}",start.elapsed());
    
    let (cs, t) =pcs.cs_convert(&sig,m,&pk);
    
    println!("Concealed Verify : {}",pcs.cs_verify(&pk,&cs));
    
    println!("Decommit : {}",cs_decommit(m,&sig,t,&cs.C,&pk));
}