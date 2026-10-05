//! Shared pricing vectors (protocol/risk-v1/pricing-vectors.json): both
//! cores must resolve every vector to the identical work score and
//! rung. The corpus header records the consts table; the reader asserts
//! it equals the compiled table, so a constant change without a corpus
//! regeneration fails loudly. `RISK_PRICING_VECTORS_PATH` overrides the
//! corpus location.

use kiwicaptcha_risk::pricing::{PriceConsts, PriceModel, ValueClass, PRICE_CONSTS};
use serde_json::Value;

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol/risk-v1/pricing-vectors.json"
);

/// The JSON shape of the consts table (the mirror of the PHP
/// `PriceModel::CONSTS` keys).
fn consts_as_json(consts: &PriceConsts) -> Value {
    serde_json::json!({
        "version": consts.version,
        "score_saturation": consts.score_saturation,
        "trust_saturation": consts.trust_saturation,
        "trust_half_scale": consts.trust_half_scale,
        "trusted_bucket_credit": consts.trusted_bucket_credit,
        "pressure_gain_saturation": consts.pressure_gain_saturation,
        "value_weights": consts.value_weights,
        "band_edges": consts.band_edges,
        "argon_capacity_floor": consts.argon_capacity_floor,
    })
}

#[test]
fn shared_pricing_vectors_match_exactly() {
    let path =
        std::env::var("RISK_PRICING_VECTORS_PATH").unwrap_or_else(|_| VECTORS_PATH.to_string());
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("pricing vectors not readable at {path}: {e}"));
    let value: Value = serde_json::from_str(&raw).expect("valid json");
    assert_eq!(value["protocol"], "risk-v1");
    assert_eq!(value["kind"], "pricing-vectors");
    assert_eq!(value["version"], 1);
    assert_eq!(
        value["price_model_version"],
        PriceModel::version(),
        "the corpus was generated under a different price model version"
    );
    assert_eq!(
        value["constants"],
        consts_as_json(&PRICE_CONSTS),
        "the corpus consts table must equal the compiled table byte for byte"
    );

    let vectors = value["vectors"].as_array().expect("vectors array");
    let recorded = value["generator"]["count"].as_u64().expect("count");
    assert_eq!(
        vectors.len() as u64,
        recorded,
        "the recorded count must match the array length"
    );
    assert_eq!(
        vectors.len(),
        10_000,
        "the corpus must ship its documented size"
    );

    for vector in vectors {
        let risk = vector["risk"].as_u64().expect("risk") as u16;
        let class = ValueClass::parse(vector["value_class"].as_str().expect("class"))
            .unwrap_or_else(|| panic!("unknown class {}", vector["value_class"]));
        let trust = vector["trust"].as_u64().expect("trust") as u32;
        let pressure = vector["pressure"].as_u64().expect("pressure") as u16;
        let expected_score = vector["work_score"].as_u64().expect("work score") as u16;
        let expected_rung = vector["expected_rung"].as_str().expect("rung");

        let score = PriceModel::work_score(risk, class, trust, pressure);
        assert_eq!(
            score, expected_score,
            "work score mismatch at risk {risk} {:?} trust {trust} pressure {pressure}",
            class
        );
        let rung = PriceModel::price(risk, class, trust, pressure);
        assert_eq!(
            rung.as_str(),
            expected_rung,
            "rung mismatch at risk {risk} {:?} trust {trust} pressure {pressure}",
            class
        );
    }
}
