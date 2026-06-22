use ark_bn254::{Fq, Fr};
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use ark_r1cs_std::fields::emulated_fp::EmulatedFpVar;
use light_poseidon::parameters::bn254_x5::get_poseidon_parameters;

pub type FqVar=EmulatedFpVar<Fq,Fr>;

pub fn get_poseidon_config() -> PoseidonConfig<Fr>{
    let params = get_poseidon_parameters::<Fr>(3).unwrap();
    // Convert flattened ark constants into Arkworks format
    let ark: Vec<Vec<Fr>> = params.ark.chunks(3).map(|chunk| chunk.to_vec()).collect();

    // Build Arkworks PoseidonConfig
    PoseidonConfig::<Fr> {
        full_rounds: params.full_rounds,
        partial_rounds: params.partial_rounds,
        alpha: params.alpha,
        ark,
        mds: params.mds,
        rate: 2,
        capacity: 1,
    }
}

pub fn poseidon_hash(m:Fr,Rx:Fr,Ry:Fr,config: &PoseidonConfig<Fr>)->Fr{
    let mut sponge = PoseidonSponge::new(&config);
    sponge.absorb(&m);
    sponge.absorb(&Rx);
    sponge.absorb(&Ry);
    sponge.squeeze_field_elements::<Fr>(1)[0]
    
}

pub fn poseidon_hash2(m:Fr,t:Fr,config:&PoseidonConfig<Fr>)->Fr{
    let mut sponge = PoseidonSponge::new(&config);
    sponge.absorb(&m);
    sponge.absorb(&t);
    sponge.squeeze_field_elements::<Fr>(1)[0]
}
