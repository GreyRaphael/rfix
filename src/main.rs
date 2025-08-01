// Minimal FIX 4.2 Server (Logon + Order Handling)
// 包含 Logon 必需字段：8,9,35,34,49,56,52,98,108,141,10
// 依赖: tokio, bytes, ahash, memchr, dashmap, anyhow, chrono

use ahash::AHashMap;
use anyhow::Result;
use chrono::Utc;
use dashmap::DashMap;
use memchr::memchr;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[derive(Debug)]
struct Session {
    logged_on: bool,
    sender: String,
    target: String,
    seq_num: u32,
    encrypt_method: String,
    heart_bt_int: String,
}

type SessionMap = Arc<DashMap<SocketAddr, Session>>;

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:9888").await?;
    let sessions: SessionMap = Arc::new(DashMap::new());

    loop {
        let (socket, addr) = listener.accept().await?;
        let sessions = sessions.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, addr, sessions).await {
                eprintln!("Client {} error: {:?}", addr, e);
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, addr: SocketAddr, sessions: SessionMap) -> Result<()> {
    let mut buf = [0u8; 4096];
    let mut data = Vec::new();

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);

        while let Some(end) = find_fix_end(&data) {
            let raw = data.drain(..end).collect::<Vec<u8>>();
            let tags = parse_fix(&raw);
            println!("{:?}", tags);
            match tags.get(&35).copied() {
                Some("A") => {
                    let client = tags.get(&49).unwrap_or(&"").to_string(); // From client
                    let server = tags.get(&56).unwrap_or(&"").to_string(); // Our server ID
                    let encrypt = tags.get(&98).unwrap_or(&"0").to_string();
                    let hb = tags.get(&108).unwrap_or(&"30").to_string();

                    let mut sess = sessions.entry(addr).or_insert(Session {
                        logged_on: false,
                        sender: server.clone(), // Our ID
                        target: client.clone(), // Client ID
                        seq_num: 1,
                        encrypt_method: encrypt.clone(),
                        heart_bt_int: hb.clone(),
                    });

                    sess.logged_on = true;

                    let resp = build_logon_response(&sess.sender, &sess.target, sess.seq_num, &encrypt, &hb);
                    sess.seq_num += 1;
                    stream.write_all(&resp).await?;
                }
                Some("D") => {
                    if let Some(mut sess) = sessions.get_mut(&addr) {
                        if sess.logged_on {
                            let exec = build_execution_report(&sess.target, &sess.sender, sess.seq_num, &tags);
                            sess.seq_num += 1;
                            stream.write_all(&exec).await?;
                        }
                    }
                }
                Some("5") => {
                    println!("Logout received from {}", addr);
                    if let Some(mut sess) = sessions.get_mut(&addr) {
                        let logout_resp = build_standard_response("5", &sess.target, &sess.sender, sess.seq_num);
                        sess.seq_num += 1;
                        stream.write_all(&logout_resp).await?;
                        sessions.remove(&addr);
                    }
                    break;
                }

                _ => {}
            }
        }
    }
    Ok(())
}

/// Logon 响应：包含 98,108,141,52
fn build_logon_response(sender: &str, target: &str, seq: u32, encrypt: &str, hb: &str) -> Vec<u8> {
    // Body
    let sending_time = Utc::now().format("%Y%m%d-%H:%M:%S%.3f").to_string();
    let body = format!(
        "35=A34={}49={}56={}52={}98={}108={}141=Y",
        seq, sender, target, sending_time, encrypt, hb
    );
    let body_len = body.as_bytes().len();
    let header = format!("8=FIX.4.29={}", body_len);
    let mut msg = Vec::new();
    msg.extend_from_slice(header.as_bytes());
    msg.extend_from_slice(body.as_bytes());
    let csum = msg.iter().map(|b| *b as u32).sum::<u32>() % 256;
    let chk = format!("10={:03}", csum);
    msg.extend_from_slice(chk.as_bytes());
    msg
}

/// 普通执行/拒绝响应
fn build_standard_response(msg_type: &str, sender: &str, target: &str, seq: u32) -> Vec<u8> {
    let body = format!("35={}34={}49={}56={}", msg_type, seq, sender, target);
    let body_len = body.as_bytes().len();
    let header = format!("8=FIX.4.29={}", body_len);
    let mut msg = Vec::new();
    msg.extend_from_slice(header.as_bytes());
    msg.extend_from_slice(body.as_bytes());
    let csum = msg.iter().map(|b| *b as u32).sum::<u32>() % 256;
    let chk = format!("10={:03}", csum);
    msg.extend_from_slice(chk.as_bytes());
    msg
}

fn build_execution_report(sender: &str, target: &str, seq: u32, tags: &AHashMap<u16, &str>) -> Vec<u8> {
    let sending_time = Utc::now().format("%Y%m%d-%H:%M:%S%.3f").to_string();
    let cl_ord_id = tags.get(&11).unwrap_or(&"UNKNOWN");
    let symbol = tags.get(&55).unwrap_or(&"SYM");
    let price = tags.get(&44).unwrap_or(&"0");
    let qty = tags.get(&38).unwrap_or(&"0");
    let body = format!(
        "35=834={}49={}56={}52={}11={}17=EX12320=039=255={}54=138={}44={}",
        seq, sender, target, sending_time, cl_ord_id, symbol, qty, price
    );
    let body_len = body.as_bytes().len();
    let header = format!("8=FIX.4.29={}", body_len);
    let mut msg = Vec::new();
    msg.extend_from_slice(header.as_bytes());
    msg.extend_from_slice(body.as_bytes());
    let csum = msg.iter().map(|b| *b as u32).sum::<u32>() % 256;
    msg.extend_from_slice(format!("10={:03}", csum).as_bytes());
    msg
}

fn parse_fix<'a>(msg: &'a [u8]) -> AHashMap<u16, &'a str> {
    let mut map = AHashMap::new();
    let mut i = 0;
    while i < msg.len() {
        if let Some(eq) = memchr(b'=', &msg[i..]) {
            if let Some(end) = memchr(1, &msg[i + eq..]) {
                let tag = std::str::from_utf8(&msg[i..i + eq]).unwrap_or("").parse().unwrap_or(0);
                let val = std::str::from_utf8(&msg[i + eq + 1..i + eq + end]).unwrap_or("");
                map.insert(tag, val);
                i += eq + end + 1;
                continue;
            }
        }
        break;
    }
    map
}

fn find_fix_end(buf: &[u8]) -> Option<usize> {
    let start = buf.windows(2).position(|w| w == b"8=")?; // MsgStart
    let body_start = buf[start..].windows(2).position(|w| w == b"9=")? + start;
    let from = body_start + 2;
    let end_pos = memchr(1, &buf[from..])?;
    let len_str = std::str::from_utf8(&buf[from..from + end_pos]).ok()?;
    let body_len: usize = len_str.parse().ok()?;
    Some(from + end_pos + 1 + body_len + 7) // +7 是末尾10=xxx|（含字段头与校验和）
}
