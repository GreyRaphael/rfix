use anyhow::Result;
use bytes::{BufMut, BytesMut};
use chrono::Utc;
use dashmap::DashMap;
use log::{debug, error, info};
use log4rs;
use memchr::memchr;
use smallvec::SmallVec;
use std::{fmt::Write, net::SocketAddr, str, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[derive(Debug, Clone, Copy)]
pub struct FixField<'a> {
    pub tag: u16,
    pub value: &'a [u8],
}

#[derive(Debug)]
pub struct FixMessage<'a> {
    pub fields: SmallVec<[FixField<'a>; 32]>,
}

impl<'a> FixMessage<'a> {
    #[inline(always)]
    pub fn parse(msg: &'a [u8]) -> Self {
        // warning字段太长久就改回vec,性能损失1us
        let mut fields = SmallVec::<[FixField; 32]>::new();
        let mut i = 0;

        while i < msg.len() {
            let eq = match memchr(b'=', &msg[i..]) {
                Some(pos) => i + pos,
                None => break,
            };
            let tag = unsafe { str::from_utf8_unchecked(&msg[i..eq]) }.parse().unwrap_or(0);

            let vs = eq + 1;
            let soh = match memchr(0x01, &msg[vs..]) {
                Some(pos) => vs + pos,
                None => break,
            };

            fields.push(FixField { tag, value: &msg[vs..soh] });
            i = soh + 1;
        }

        FixMessage { fields }
    }

    #[inline(always)]
    pub fn get_raw(&self, tag: u16) -> Option<&'a [u8]> {
        self.fields.iter().find(|f| f.tag == tag).map(|f| f.value)
    }

    #[inline(always)]
    pub fn get_str(&self, tag: u16) -> Option<&'a str> {
        self.get_raw(tag).map(|v| unsafe { std::str::from_utf8_unchecked(v) })
    }

    #[inline(always)]
    pub fn get<T: std::str::FromStr>(&self, tag: u16) -> Option<T> {
        self.get_str(tag).and_then(|s| s.parse::<T>().ok())
    }
}

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
    let mut buf = [0u8; 8192];
    let mut data = BytesMut::with_capacity(65536);

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            info!("Connection closed by peer");
            break;
        }
        data.put_slice(&buf[..n]);
        // 缓存当前时间字符串，避免多次调用格式化
        let now_str = Utc::now().format("%Y%m%d-%H:%M:%S%.3f").to_string();

        // 必须使用find_fix_end，因为buf可能两个message粘起来
        while let Some(end) = find_fix_end(&data) {
            if end > data.len() {
                debug!("Invalid FIX message range: end={}, buffer_len={}", end, data.len());
                break; // Avoid panic, retain data for next round
            }

            let raw = data.split_to(end);
            info!("{}", std::str::from_utf8(&raw)?);

            let msg = FixMessage::parse(&raw);
            let client = msg.get_str(49).unwrap_or("").to_string();
            let server = msg.get_str(56).unwrap_or("").to_string();

            match msg.get_raw(35) {
                Some(b"A") => {
                    let encrypt = msg.get_str(98).unwrap_or("0").to_string();
                    let hb = msg.get_str(108).unwrap_or("30").to_string();
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
                    stream
                        .write_all(&build_logon_response(&server, &client, seq, &encrypt, &hb, &now_str))
                        .await?;
                }
                Some(b"D") => {
                    if let Some(mut sess) = sessions.get_mut(&client) {
                        if sess.logged_on {
                            let resp = build_execution_report(&sess.sender, &sess.target, sess.seq_num, &msg, &now_str);
                            stream.write_all(&resp).await?;
                            sess.seq_num += 1;
                            info!("{}", std::str::from_utf8(&resp)?);
                        }
                    }
                }
                Some(b"5") => {
                    if let Some(sess) = sessions.get(&client) {
                        stream
                            .write_all(&build_logout_response("5", &sess.sender, &sess.target, sess.seq_num))
                            .await?;
                        info!("Logout complete: {}", client);
                    }
                    let _ = stream.shutdown().await;
                    sessions.remove(&client);
                    break;
                }
                Some(b"0") => {
                    if let Some(mut sess) = sessions.get_mut(&client) {
                        stream
                            .write_all(&build_heartbeat_response(&sess.sender, &sess.target, sess.seq_num, &now_str))
                            .await?;
                        sess.seq_num += 1;
                        debug!("Responded Heartbeat to {}", client);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn build_logon_response(sender: &str, target: &str, seq: u32, encrypt: &str, hb: &str, now_str: &str) -> BytesMut {
    let mut body = BytesMut::with_capacity(128);
    write!(
        body,
        "35=A\u{1}34={}\u{1}49={}\u{1}56={}\u{1}52={}\u{1}98={}\u{1}108={}\u{1}141=Y\u{1}",
        seq, sender, target, now_str, encrypt, hb
    )
    .unwrap();
    build_message(body)
}

fn build_logout_response(msg_type: &str, sender: &str, target: &str, seq: u32) -> BytesMut {
    let mut body = BytesMut::with_capacity(128);
    write!(body, "35={}\u{1}34={}\u{1}49={}\u{1}56={}\u{1}", msg_type, seq, sender, target).unwrap();
    build_message(body)
}

fn build_heartbeat_response(sender: &str, target: &str, seq: u32, now_str: &str) -> BytesMut {
    let mut body = BytesMut::with_capacity(128);
    write!(body, "35=0\u{1}34={}\u{1}49={}\u{1}56={}\u{1}52={}\u{1}", seq, sender, target, now_str).unwrap();
    build_message(body)
}

fn build_execution_report(sender: &str, target: &str, seq: u32, msg: &FixMessage, now_str: &str) -> BytesMut {
    let get = |tag| msg.get_str(tag).unwrap_or("0");
    let mut body = BytesMut::with_capacity(1024);
    write!(body,
        "35=8\u{1}34={}\u{1}49={}\u{1}56={}\u{1}52={}\u{1}6={}\u{1}11={}\u{1}14={}\u{1}17=8\u{1}20=0\u{1}31={}\u{1}32={}\u{1}37=8\u{1}38={}\u{1}39=2\u{1}54={}\u{1}55={}\u{1}150=2\u{1}151=0.00\u{1}",
        seq,
        sender,
        target,
        now_str,
        get(44), get(11), get(38), get(44), get(38), get(38), get(54), get(55)
    ).unwrap();
    build_message(body)
}

fn build_message(body: BytesMut) -> BytesMut {
    let body_len = body.len();
    let mut msg = BytesMut::with_capacity(32 + body_len + 10);
    write!(msg, "8=FIX.4.2\u{1}9={}\u{1}", body_len).unwrap();
    msg.unsplit(body);
    let checksum = msg.iter().map(|b| *b as u32).sum::<u32>() % 256;
    write!(msg, "10={:03}\u{1}", checksum).unwrap();
    msg
}

fn find_fix_end(buf: &[u8]) -> Option<usize> {
    // 定位 8= 开头
    let start = buf.windows(2).position(|w| w == b"8=")?;
    // 定位 9= 后面的 body length
    let body_start = buf[start..].windows(2).position(|w| w == b"9=")? + start;
    let from = body_start + 2;
    let end_pos = memchr(1, &buf[from..])?;
    let len_str = std::str::from_utf8(&buf[from..from + end_pos]).ok()?;
    let body_len: usize = len_str.parse().ok()?;
    Some(from + end_pos + 1 + body_len + 7) // +7 是末尾10=xxx|（含字段头与校验和）
}
