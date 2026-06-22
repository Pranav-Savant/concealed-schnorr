use criterion::{
    criterion_group,
    criterion_main,
    Criterion,
};

use concealed_schnorr::*;
use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::PrimeGroup;

fn bench_sign(c: &mut Criterion) {
    let g = G1::generator();
    let (sk, _) = Schnorr::keyGen(g);
    let m = Fr::from(55u64);

    c.bench_function("Schnorr Sign", |b| {
        b.iter(|| {
            Schnorr::Sign(
                g,
                m,
                &sk
            )
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    let g = G1::generator();
    let (sk, pk) = Schnorr::keyGen(g);
    let m = Fr::from(55u64);
    let sig = Schnorr::Sign(g,m,&sk);

    c.bench_function("Schnorr Verify", |b| {
        b.iter(|| {
            Schnorr::verify(
                g,
                &pk,
                &sig,
                m
            )
        })
    });
}

fn bench_convert(c: &mut Criterion) {
    let mut group =c.benchmark_group("Concealed Convert");
    group.sample_size(10);
    let g = G1::generator();
    let (sk, pk) =Schnorr::keyGen(g);
    let m = Fr::from(55u64);
    let sig =Schnorr::Sign(g,m,&sk);
    let pcs = ParamCS::new();

    group.bench_function("Convert",|b| {
            b.iter(|| {
                pcs.cs_convert(
                    &sig,
                    m,
                    &pk,
                )
            })
        },
    );

    group.finish();
}

fn bench_cverify(c: &mut Criterion) {
    let mut group =c.benchmark_group("Concealed Verify");
    group.sample_size(20);
    let g = G1::generator();
    let (sk, pk) =Schnorr::keyGen(g);
    let m = Fr::from(55u64);
    let sig =Schnorr::Sign(g,m,&sk);
    let pcs = ParamCS::new();
    let (cs, _) =pcs.cs_convert(&sig,m,&pk);

    group.bench_function("CVerify",|b| {
            b.iter(|| {
                pcs.cs_verify(
                    &pk,
                    &cs,
                )
            })
        },
    );

    group.finish();
}

fn bench_decommit(c: &mut Criterion) {
    let mut group =c.benchmark_group("Decommit");
    group.sample_size(100);
    let g = G1::generator();
    let (sk, pk) =Schnorr::keyGen(g);
    let m = Fr::from(55u64);
    let sig =Schnorr::Sign(g,m,&sk);
    let pcs = ParamCS::new();
    let (cs, t) =pcs.cs_convert(&sig,m,&pk,);

    group.bench_function("Decommit",|b| {
            b.iter(|| {
                cs_decommit(
                    m,
                    &sig,
                    t,
                    &cs.C,
                    &pk,
                )
            })
        },
    );

    group.finish();
}

criterion_group!(
    benches,
    bench_sign,
    bench_verify,
    bench_convert,
    bench_cverify,
    bench_decommit
);

criterion_main!(benches);