use ark_bn254::{Fq, Fr, G1Projective as G1};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{Zero};
use ark_relations::r1cs::{ConstraintSynthesizer,ConstraintSystemRef,SynthesisError};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::{
        fp::FpVar,
        FieldVar,
    },
    select::CondSelectGadget,
};
use ark_crypto_primitives::sponge::{constraints::CryptographicSpongeVar,poseidon::constraints::PoseidonSpongeVar};
use crate::utils::{FqVar,get_poseidon_config};

pub struct ECPointVar {
    x: FqVar,
    y: FqVar,
    inf: Boolean<Fr>,
}

#[derive(Clone)]
pub struct ConcealedSignatureCircuit{
    pub commitment:Option<Fr>,
    pub pkx: Option<Fq>,
    pub pky: Option<Fq>, 
    pub m:Option<Fr>,
    pub t:Option<Fr>,
    pub c:Option<Fr>,
    pub z:Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for ConcealedSignatureCircuit{
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(),SynthesisError> {
        let commitment_var=FpVar::new_input(cs.clone(),||self.commitment.ok_or(SynthesisError::AssignmentMissing),)?;
        let pkx_var=FqVar::new_input(cs.clone(), ||self.pkx.ok_or(SynthesisError::AssignmentMissing),)?;
        let pky_var=FqVar::new_input(cs.clone(), ||self.pky.ok_or(SynthesisError::AssignmentMissing),)?;
        let m_var=FpVar::new_witness(cs.clone(),||self.m.ok_or(SynthesisError::AssignmentMissing),)?;
        let t_var=FpVar::new_witness(cs.clone(),||self.t.ok_or(SynthesisError::AssignmentMissing),)?;
        let c_var=FpVar::new_witness(cs.clone(),||self.c.ok_or(SynthesisError::AssignmentMissing),)?;
        let z_var=FpVar::new_witness(cs.clone(),||self.z.ok_or(SynthesisError::AssignmentMissing),)?;

        //R=zg-cpk
        let z_bits = z_var.to_bits_le()?;
        let c_bits = c_var.to_bits_le()?;
        let g_affine = G1::generator().into_affine();

        let g_point = ECPointVar {
            x: FqVar::constant(g_affine.x),
            y: FqVar::constant(g_affine.y),
            inf: Boolean::constant(false),
        };
        let pk_point = ECPointVar {
            x: pkx_var.clone(),
            y: pky_var.clone(),
            inf: Boolean::constant(false),
        };
        let zg = scalar_mul(&z_bits[..3], &g_point)?;
        let cpk = scalar_mul(&c_bits[..3], &pk_point)?;
        let neg_cpk = ECPointVar {
            x: cpk.x.clone(),
            y: FqVar::constant(Fq::zero())-cpk.y.clone(),
            inf: cpk.inf.clone(),
        };
        let R = ec_add_inf(&zg,&neg_cpk,)?;

        let Rx_bits=R.x.to_bits_le()?;
        let Ry_bits=R.y.to_bits_le()?;
        let Rx_fr = Boolean::le_bits_to_fp(&Rx_bits)?;
        let Ry_fr = Boolean::le_bits_to_fp(&Ry_bits)?;
        let config = get_poseidon_config();
        let mut sponge2 = PoseidonSpongeVar::new(cs.clone(), &config);
        sponge2.absorb(&m_var)?;
        sponge2.absorb(&Rx_fr)?;
        sponge2.absorb(&Ry_fr)?;
        let cp=sponge2.squeeze_field_elements(1)?[0].clone();

        let mut sponge = PoseidonSpongeVar::new(cs.clone(), &config);
        sponge.absorb(&cp)?;
        sponge.absorb(&t_var)?;
        let commitment_hash_var = sponge.squeeze_field_elements(1)?[0].clone();
        
        commitment_hash_var.enforce_equal(&commitment_var)?;
        cp.enforce_equal(&c_var)?;
        Ok(())  
    }
}

fn point_at_infinity() -> ECPointVar {
    let g = G1::generator().into_affine();
    ECPointVar {
        x: FqVar::constant(g.x),
        y: FqVar::constant(g.y),
        inf: Boolean::constant(true),
    }
}

fn scalar_mul(bits: &[Boolean<Fr>],p: &ECPointVar,) -> Result<ECPointVar, SynthesisError> {
    let mut result = point_at_infinity();
    let mut base = ECPointVar {
        x: p.x.clone(),
        y: p.y.clone(),
        inf: p.inf.clone(),
    };
    for bit in bits {
        let candidate =ec_add_inf(&result,&base)?;
        let new_x =FqVar::conditionally_select(bit,&candidate.x,&result.x)?;
        let new_y =FqVar::conditionally_select(bit,&candidate.y,&result.y)?;
        let new_inf =Boolean::<Fr>::conditionally_select(bit,&candidate.inf,&result.inf)?;
        result = ECPointVar {
            x: new_x,
            y: new_y,
            inf: new_inf,
        };
        base =ec_double_inf(&base)?;
    }
    Ok(result)
}

fn ec_double(x: &FqVar,y: &FqVar,) -> Result<(FqVar, FqVar), SynthesisError> {
    let three = FqVar::constant(Fq::from(3u64));
    let two = FqVar::constant(Fq::from(2u64));
    let lambda= (three*x.clone()*x.clone())*(two*y.clone()).inverse()?;
    let x2= &lambda*&lambda-x.clone()-x.clone();
    let y2=&lambda*(x.clone()-&x2)-y.clone();
    Ok((x2, y2))
}

fn ec_double_inf(p: &ECPointVar,) -> Result<ECPointVar, SynthesisError> {
    let (normal_x, normal_y) =ec_double(&p.x,&p.y,)?;
    let inf_point = point_at_infinity();
    let final_x =FqVar::conditionally_select(&p.inf,&inf_point.x,&normal_x,)?;
    let final_y =FqVar::conditionally_select(&p.inf,&inf_point.y,&normal_y)?;
    let final_inf =Boolean::<Fr>::conditionally_select(&p.inf,&Boolean::constant(true),&Boolean::constant(false))?;
    Ok(
        ECPointVar {
            x: final_x,
            y: final_y,
            inf: final_inf,
        }
    )
}

fn ec_add(x1: &FqVar,y1: &FqVar,x2: &FqVar,y2: &FqVar,) -> Result<(FqVar, FqVar), SynthesisError> {
    let lambda=(y2.clone()-y1.clone())*(x2.clone()-x1.clone()).inverse()?;
    let x3 =&lambda * &lambda-x1.clone()-x2.clone();
    let y3 =&lambda*(x1.clone()-&x3)-y1.clone();
    Ok((x3, y3))
}

fn ec_add_inf(
    p1: &ECPointVar,
    p2: &ECPointVar,) -> Result<ECPointVar, SynthesisError> {
    let (normal_x, normal_y) =ec_add(&p1.x,&p1.y,&p2.x,&p2.y)?;
    let x_after_p1 =FqVar::conditionally_select(&p1.inf,&p2.x,&normal_x,)?;
    let y_after_p1 =FqVar::conditionally_select(&p1.inf,&p2.y,&normal_y,)?;
    let inf_after_p1 =Boolean::<Fr>::conditionally_select(&p1.inf,&p2.inf,&Boolean::constant(false),)?;
    let final_x =FqVar::conditionally_select(&p2.inf,&p1.x,&x_after_p1,)?;
    let final_y =FqVar::conditionally_select(&p2.inf,&p1.y,&y_after_p1,)?;
    let final_inf =Boolean::<Fr>::conditionally_select(&p2.inf,&p1.inf,&inf_after_p1,)?;
    Ok(
        ECPointVar {
            x: final_x,
            y: final_y,
            inf: final_inf,
        }
    )
}

