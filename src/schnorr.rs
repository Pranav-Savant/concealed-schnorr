use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::{CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_std::{ops::Mul, UniformRand};
use rand::thread_rng;
use crate::utils::{get_poseidon_config, poseidon_hash};

pub struct SecretKey {
    x: Fr,
}
pub struct PublicKey {
    pub pk: G1,
}

pub struct Signature {
    pub c: Fr,
    pub z: Fr,
}

pub struct Schnorr;

impl Schnorr {
    pub fn keyGen(g:G1)->(SecretKey,PublicKey){
        let mut rng=thread_rng();
        let x=Fr::rand(&mut rng);
        let pk=g.mul(x);
        (SecretKey{x},PublicKey{pk})
    }
        
    pub fn Sign(g:G1,m:Fr,sk:&SecretKey)->Signature{
        let mut rng=thread_rng();
        let config=get_poseidon_config();
        //nonce
        let r=Fr::rand(&mut rng);
        //Initial Comm
        let R=g.mul(r);
        let R_affine=R.into_affine();
        let Rx=Fr::from_le_bytes_mod_order(&R_affine.x.into_bigint().to_bytes_le());
        let Ry=Fr::from_le_bytes_mod_order(&R_affine.y.into_bigint().to_bytes_le());
        //challenge (Replace with hash afterwards)
        let c=poseidon_hash(m, Rx, Ry,&config);
        //response
        let z=r+c*sk.x;
        Signature{c,z}
    }
        
    pub fn verify(g:G1,pk:&PublicKey,sig:&Signature,m:Fr)->bool{
        let config=get_poseidon_config();
        let Rp=g.mul(sig.z)-pk.pk.mul(sig.c);
        let Rp_affine=Rp.into_affine();
        let Rpx=Fr::from_le_bytes_mod_order(&Rp_affine.x.into_bigint().to_bytes_le());
        let Rpy=Fr::from_le_bytes_mod_order(&Rp_affine.y.into_bigint().to_bytes_le());
        let cp=poseidon_hash(m,Rpx,Rpy,&config);
        sig.c==cp
    }

}