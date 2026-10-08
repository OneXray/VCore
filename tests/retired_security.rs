#![cfg(feature = "outbound-vless")]

use serde_json::{Value, json};
use vole::config::Config;

fn node() -> Value {
    json!({"name":"edge", "type":"vless", "server":"example.invalid", "port":443,
        "uuid":"07070707-0707-0707-0707-070707070707", "tls":true})
}

fn parse(node: Value) -> vole::Result<Config> {
    Config::parse_yaml(
        &serde_json::to_vec(&json!({
            "mixed-port":1080, "proxies":[node], "rules":["MATCH,edge"]
        }))
        .unwrap(),
    )
}

fn retired_values() -> [Value; 4] {
    [
        json!({"password":"retired-secret-marker", "version-hint":"tls12"}),
        json!({}),
        Value::Null,
        json!("retired-secret-marker"),
    ]
}

#[test]
fn restls_is_rejected_but_jls_remains_valid_on_the_primary_leg() {
    parse(node()).expect("ordinary TLS remains valid");
    let mut baseline = node();
    baseline["jls-opts"] = json!({"username":"retained-user", "password":"retained-password"});
    parse(baseline.clone()).expect("JLS remains supported");
    for original in [node(), baseline] {
        for value in retired_values() {
            let mut input = original.clone();
            input["restls-opts"] = value;
            let error = parse(input).expect_err("Restls must not be silently ignored");
            assert!(!error.to_string().contains("retired-secret-marker"));
        }
    }
}

#[test]
fn restls_is_rejected_but_jls_remains_valid_on_the_download_leg() {
    let mut ordinary = node();
    ordinary["network"] = json!("xhttp");
    ordinary["xhttp-opts"] = json!({"mode":"stream-up", "download-settings":{}});
    parse(ordinary.clone()).expect("independent ordinary TLS remains valid");
    let mut jls = ordinary.clone();
    jls["jls-opts"] = json!({"username":"retained-user", "password":"retained-password"});
    parse(jls.clone()).expect("inherited JLS remains supported");
    for baseline in [ordinary, jls] {
        for value in retired_values() {
            let mut input = baseline.clone();
            input["xhttp-opts"]["download-settings"]["restls-opts"] = value;
            let error = parse(input).expect_err("retired download option must be rejected");
            assert!(!error.to_string().contains("retired-secret-marker"));
        }
    }
}
