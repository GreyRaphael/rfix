use ahash::AHashMap;
use anyhow::Result;
use chrono::Utc;
use dashmap::DashMap;
use log::{error, info};
use log4rs;
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

type SessionMap = Arc<DashMap<String, Session>>;

#[tokio::main]
async fn main() -> Result<()> {
    log4rs::init_file("config/log4rs.yaml", Default::default())?;
    info!("Server starting...");

    let listener = TcpListener::bind("0.0.0.0:9888").await?;
    let sessions: SessionMap = Arc::new(DashMap::new());

    loop {
        let (socket, addr) = listener.accept().await?;
        let sessions = Arc::clone(&sessions);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, addr, sessions).await {
                error!("Client {} error: {:?}", addr, e);
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, _addr: SocketAddr, sessions: SessionMap) -> Result<()> {
    let mut buf = [0u8; 4096];
    let mut data = Vec::with_capacity(8192);

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            info!("Connection closed by peer");
            break;
        }
        data.extend_from_slice(&buf[..n]);

        while let Some(end) = find_fix_end(&data) {
            let raw = data.drain(..end).collect::<Vec<u8>>();
            let tags = parse_fix(&raw);
            info!("{:?}", tags);

            let msg_type = tags.get(&35).copied();
            let client = tags.get(&49).unwrap_or(&"").to_string();
            let server = tags.get(&56).unwrap_or(&"").to_string();

            match msg_type {
                Some("A") => {
                    let encrypt = tags.get(&98).unwrap_or(&"0").to_string();
                    let hb = tags.get(&108).unwrap_or(&"30").to_string();
                    let seq = 1;

                    sessions.insert(
                        client.clone(),
                        Session {
                            logged_on: true,
                            sender: server.clone(),
                            target: client.clone(),
                            seq_num: seq + 1,
                            encrypt_method: encrypt.clone(),
                            heart_bt_int: hb.clone(),
                        },
                    );

                    stream.write_all(&build_logon_response(&server, &client, seq, &encrypt, &hb)).await?;
                }
                Some("D") => {
                    if let Some(mut sess) = sessions.get_mut(&client) {
                        if sess.logged_on {
                            stream
                                .write_all(&build_execution_report(&sess.sender, &sess.target, sess.seq_num, &tags))
                                .await?;
                            sess.seq_num += 1;
                        }
                    }
                }
                Some("5") => {
                    if let Some(sess) = sessions.get(&client) {
                        stream
                            .write_all(&build_standard_response("5", &sess.sender, &sess.target, sess.seq_num))
                            .await?;
                        info!("Logout complete: {}", client);
                    }
                    let _ = stream.shutdown().await;
                    sessions.remove(&client);
                }
                Some("0") => {
                    if let Some(mut sess) = sessions.get_mut(&client) {
                        stream.write_all(&build_heartbeat(&sess.sender, &sess.target, sess.seq_num)).await?;
                        sess.seq_num += 1;
                        info!("Responded Heartbeat to {}", client);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn build_logon_response(sender: &str, target: &str, seq: u32, encrypt: &str, hb: &str) -> Vec<u8> {
    build_message(&format!(
        "35=A\u{1}34={}\u{1}49={}\u{1}56={}\u{1}52={}\u{1}98={}\u{1}108={}\u{1}141=Y\u{1}",
        seq,
        sender,
        target,
        Utc::now().format("%Y%m%d-%H:%M:%S%.3f"),
        encrypt,
        hb
    ))
}

fn build_standard_response(msg_type: &str, sender: &str, target: &str, seq: u32) -> Vec<u8> {
    build_message(&format!("35={}\u{1}34={}\u{1}49={}\u{1}56={}\u{1}", msg_type, seq, sender, target))
}

fn build_heartbeat(sender: &str, target: &str, seq: u32) -> Vec<u8> {
    build_message(&format!(
        "35=0\u{1}34={}\u{1}49={}\u{1}56={}\u{1}52={}\u{1}",
        seq,
        sender,
        target,
        Utc::now().format("%Y%m%d-%H:%M:%S%.3f")
    ))
}

fn build_execution_report(sender: &str, target: &str, seq: u32, tags: &AHashMap<u16, &str>) -> Vec<u8> {
    build_message(&format!(
        "35=8\u{1}34={}\u{1}49={}\u{1}56={}\u{1}52={}\u{1}6={}\u{1}11={}\u{1}14={}\u{1}17=8\u{1}20=0\u{1}31={}\u{1}32={}\u{1}37=8\u{1}38={}\u{1}39=2\u{1}54={}\u{1}55={}\u{1}150=2\u{1}151=0.00\u{1}",
        seq,
        sender,
        target,
        Utc::now().format("%Y%m%d-%H:%M:%S%.3f"),
        tags.get(&44).unwrap_or(&"0"),
        tags.get(&11).unwrap_or(&"UNKNOWN"),
        tags.get(&38).unwrap_or(&"0"),
        tags.get(&44).unwrap_or(&"0"),
        tags.get(&38).unwrap_or(&"0"),
        tags.get(&38).unwrap_or(&"0"),
        tags.get(&54).unwrap_or(&"1"),
        tags.get(&55).unwrap_or(&"UNKNOWN")
    ))
}

fn build_message(body: &str) -> Vec<u8> {
    let body_bytes = body.as_bytes();
    let header = format!("8=FIX.4.2\u{1}9={}\u{1}", body_bytes.len());
    let mut msg = Vec::with_capacity(header.len() + body_bytes.len() + 10);
    msg.extend_from_slice(header.as_bytes());
    msg.extend_from_slice(body_bytes);
    let checksum = msg.iter().map(|b| *b as u32).sum::<u32>() % 256;
    msg.extend_from_slice(format!("10={:03}\u{1}", checksum).as_bytes());
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
