//! Minimal native XHTTP/H3 stream-one probe, not a production transport.

use std::{net::SocketAddr, time::Instant};

use bytes::{Buf, Bytes};
use serde_json::{Value, json};
use tokio::task::JoinHandle;

use crate::{GREETING, PAYLOAD_BYTES, TRAILER, field};

const RESPONSE_LIMIT: usize = 257 + GREETING.len() + PAYLOAD_BYTES + TRAILER.len();

fn request_header(config: &Value) -> Result<Bytes, &'static str> {
    let uuid = field(config, "uuid")?.replace('-', "");
    if uuid.len() != 32 || !uuid.is_ascii() {
        return Err("invalid_fixture");
    }
    let mut header = vec![0]; // VLESS version.
    for offset in (0..32).step_by(2) {
        header.push(
            u8::from_str_radix(&uuid[offset..offset + 2], 16).map_err(|_| "invalid_fixture")?,
        );
    }
    header.extend_from_slice(&[0, 1]); // No addons, TCP command.
    let target: SocketAddr = field(config, "target")?
        .parse()
        .map_err(|_| "invalid_fixture")?;
    let SocketAddr::V4(target) = target else {
        return Err("invalid_fixture");
    };
    header.extend_from_slice(&target.port().to_be_bytes());
    header.push(1); // VLESS IPv4 (not SOCKS address ordering).
    header.extend_from_slice(&target.ip().octets());
    Ok(header.into())
}

fn append(output: &mut Vec<u8>, mut chunk: impl Buf) -> Result<(), &'static str> {
    if chunk.remaining() > RESPONSE_LIMIT - output.len() {
        return Err("xhttp_response_budget");
    }
    while chunk.has_remaining() {
        let bytes = chunk.chunk();
        output.extend_from_slice(bytes);
        let len = bytes.len();
        chunk.advance(len);
    }
    Ok(())
}

pub async fn exercise(
    connection: quinn::Connection,
    config: &Value,
    h3_task: &mut Option<JoinHandle<()>>,
    phase: &mut &'static str,
) -> Result<Value, &'static str> {
    let started = Instant::now();
    let (mut control, mut requests) = h3::client::builder()
        .max_field_section_size(8192)
        .build(h3_quinn::Connection::new(connection))
        .await
        .map_err(|_| "h3_setup")?;
    *h3_task = Some(tokio::spawn(async move {
        let _ = control.wait_idle().await;
    }));
    let path = field(config, "path")?;
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("https://localhost{path}"))
        .header("content-type", "application/grpc")
        .header(
            "referer",
            format!("https://localhost{path}?x_padding={}", "X".repeat(100)),
        )
        .body(())
        .map_err(|_| "xhttp_request")?;
    *phase = "xhttp_request";
    let stream = requests
        .send_request(request)
        .await
        .map_err(|_| "xhttp_send")?;
    let (mut send, mut receive) = stream.split();
    send.send_data(request_header(config)?)
        .await
        .map_err(|_| "vless_header_send")?;
    let response = receive
        .recv_response()
        .await
        .map_err(|_| "xhttp_response")?;
    let status = response.status().as_u16();
    if status != 200 {
        return Ok(json!({"outcome": "xhttp_status", "http_status": status}));
    }
    *phase = "vless_response";
    let mut output = Vec::new();
    // Validate the VLESS header AND server-first bytes before uploading business
    // data. HTTP 200 alone is not proof of VLESS authentication.
    let header_len = loop {
        match receive.recv_data().await {
            Ok(Some(chunk)) => append(&mut output, chunk)?,
            _ => {
                return Ok(
                    json!({"outcome": "vless_rejected", "http_status": status, "vless_response": false}),
                );
            }
        }
        if output.len() < 2 {
            continue;
        }
        if output[0] != 0 {
            return Err("vless_version");
        }
        let header_len = 2 + usize::from(output[1]);
        if output.len() >= header_len + GREETING.len() {
            if &output[header_len..header_len + GREETING.len()] != GREETING {
                return Err("server_first_mismatch");
            }
            break header_len;
        }
    };
    let setup_ms = started.elapsed().as_secs_f64() * 1000.0;
    let payload: Vec<u8> = (0..PAYLOAD_BYTES)
        .map(|index| (index % 251) as u8)
        .collect();
    let half_close = config["half_close"].as_bool().unwrap_or(false);
    let transfer_started = Instant::now();
    *phase = "xhttp_data";
    let upload = async {
        for chunk in payload.chunks(8192) {
            send.send_data(Bytes::copy_from_slice(chunk))
                .await
                .map_err(|_| "xhttp_data_send")?;
        }
        if half_close {
            send.finish().await.map_err(|_| "xhttp_half_close")?;
        }
        Ok::<_, &'static str>(())
    };
    let download = async {
        while let Some(chunk) = receive
            .recv_data()
            .await
            .map_err(|_| "xhttp_data_receive")?
        {
            append(&mut output, chunk)?;
        }
        Ok::<_, &'static str>(())
    };
    tokio::try_join!(upload, download)?;
    let body = &output[header_len..];
    if body.len() != GREETING.len() + PAYLOAD_BYTES + TRAILER.len()
        || &body[..GREETING.len()] != GREETING
        || body[GREETING.len()..GREETING.len() + PAYLOAD_BYTES] != payload
        || &body[GREETING.len() + PAYLOAD_BYTES..] != TRAILER
    {
        return Ok(
            json!({"outcome": "xhttp_data_mismatch", "http_status": status,
            "vless_response": true, "half_close_requested": half_close,
            "expected_response_bytes": GREETING.len() + PAYLOAD_BYTES + TRAILER.len(),
            "received_response_bytes": body.len(),
            "payload_prefix_matches": body.iter().skip(GREETING.len()).zip(&payload).all(|(a, b)| a == b),
            "trailer_matches": body.ends_with(TRAILER)}),
        );
    }
    if !half_close {
        let _ = send.finish().await;
    }
    // Keep the last request sender alive until both business directions finish.
    drop(requests);
    Ok(
        json!({"outcome": "pass", "http_status": status, "vless_response": true,
        "payload_bytes": PAYLOAD_BYTES, "server_first": true, "tcp_half_close": half_close,
        "setup_ms": setup_ms, "transfer_ms": transfer_started.elapsed().as_secs_f64() * 1000.0}),
    )
}
