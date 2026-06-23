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

/*
Schnorr Sign            time:   [115.81 µs 115.83 µs 115.85 µs]
Found 7 outliers among 100 measurements (7.00%)
  4 (4.00%) high mild
  3 (3.00%) high severe

Schnorr Verify          time:   [139.21 µs 139.28 µs 139.38 µs]
Found 10 outliers among 100 measurements (10.00%)
  2 (2.00%) high mild
  8 (8.00%) high severe

Benchmarking Concealed Convert/Convert: Warming up for 3.0000 s
Warning: Unable to complete 100 samples in 5.0s. You may wish to increase target time to 9843.4s, or reduce sample count to 10.
Concealed Convert/Convert
                        time:   [96.112 s 96.161 s 96.212 s]

Concealed Verify/CVerify
                        time:   [2.1419 ms 2.1425 ms 2.1431 ms]
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) low mild

Decommit/Decommit       time:   [163.97 µs 164.03 µs 164.11 µs]
Found 9 outliers among 100 measurements (9.00%)
  1 (1.00%) low mild
  3 (3.00%) high mild
  5 (5.00%) high severe
*/