// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Discovery of the domain controllers through DNS SRV records (RFC 2782).
//!
//! Port of `annuaire/core/srv.py`. The Python module calls `res_query` of libresolv; that
//! would be an `unsafe` call here, so this module has its own small stub resolver: the
//! servers of `/etc/resolv.conf` (with its `timeout` and `attempts` options), a UDP query,
//! TCP when the answer is truncated (ADR 0016, § 2). The local resolver of systemd
//! (`127.0.0.53`), which routes the lab zone and the zones of a VPN, answers as it does for
//! `res_query`. Parsing and ordering are pure.

use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CLASS_IN: u16 = 1;
const TYPE_SRV: u16 = 33;
/// Temporary failures (timeout, SERVFAIL) are asked again, like `srv.py`: a DNS server
/// behind a tunnel may miss the first question while the tunnel comes up.
const TRY_AGAIN_ATTEMPTS: u32 = 3;

/// One SRV record; the target is in lower case, without the final dot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

/// Why a DNS message was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidResponse(pub &'static str);

impl fmt::Display for InvalidResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid DNS response: {}", self.0)
    }
}

impl std::error::Error for InvalidResponse {}

/// Failure of a discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrvError {
    /// No SRV record for this name (`ErreurDecouverte`).
    NotFound { name: String },
    /// The DNS servers of the host do not answer (`ErreurInjoignable`).
    Unreachable { detail: String },
}

impl fmt::Display for SrvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { name } => write!(f, "no domain controller found: {name}"),
            Self::Unreachable { detail } => write!(f, "DNS server not answering: {detail}"),
        }
    }
}

impl std::error::Error for SrvError {}

fn read_u16(message: &[u8], position: usize) -> Result<u16, InvalidResponse> {
    match message.get(position..position + 2) {
        Some(&[a, b]) => Ok(u16::from_be_bytes([a, b])),
        _ => Err(InvalidResponse("truncated field")),
    }
}

/// Reads a name, compression included (RFC 1035, 4.1.4). Returns the name (no final dot)
/// and the position after it in the message (after the first pointer, if any).
fn read_name(message: &[u8], mut position: usize) -> Result<(String, usize), InvalidResponse> {
    let mut labels: Vec<String> = Vec::new();
    let mut next: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let length = *message
            .get(position)
            .ok_or(InvalidResponse("truncated name"))?;
        if length & 0xC0 == 0xC0 {
            let low = *message
                .get(position + 1)
                .ok_or(InvalidResponse("truncated pointer"))?;
            if next.is_none() {
                next = Some(position + 2);
            }
            jumps += 1;
            if jumps > 64 {
                return Err(InvalidResponse("compression loop"));
            }
            position = (usize::from(length & 0x3F) << 8) | usize::from(low);
            continue;
        }
        if length & 0xC0 != 0 {
            return Err(InvalidResponse("unknown label type"));
        }
        position += 1;
        if length == 0 {
            break;
        }
        let label = message
            .get(position..position + usize::from(length))
            .ok_or(InvalidResponse("truncated label"))?;
        // Like `decode("ascii", "replace")` of the Python module.
        labels.push(
            label
                .iter()
                .map(|&b| {
                    if b.is_ascii() {
                        char::from(b)
                    } else {
                        '\u{FFFD}'
                    }
                })
                .collect(),
        );
        position += usize::from(length);
    }
    Ok((labels.join("."), next.unwrap_or(position)))
}

/// The SRV records of the answer section of a DNS message; other types are skipped.
pub fn parse_srv_response(message: &[u8]) -> Result<Vec<SrvRecord>, InvalidResponse> {
    if message.len() < 12 {
        return Err(InvalidResponse("truncated header"));
    }
    let questions = read_u16(message, 4)?;
    let answers = read_u16(message, 6)?;
    let mut position = 12;
    for _ in 0..questions {
        position = read_name(message, position)?.1 + 4;
    }
    let mut records = Vec::new();
    for _ in 0..answers {
        position = read_name(message, position)?.1;
        let rr_type = read_u16(message, position)?;
        let class = read_u16(message, position + 2)?;
        let length = usize::from(read_u16(message, position + 8)?);
        let data = position + 10;
        if data + length > message.len() {
            return Err(InvalidResponse("truncated data"));
        }
        if rr_type == TYPE_SRV && class == CLASS_IN {
            let (target, _) = read_name(message, data + 6)?;
            records.push(SrvRecord {
                priority: read_u16(message, data)?,
                weight: read_u16(message, data + 2)?,
                port: read_u16(message, data + 4)?,
                target: target.to_lowercase(),
            });
        }
        position = data + length;
    }
    Ok(records)
}

/// Source of the weighted draw: `next_in(n)` returns an integer in `0..=n`.
pub trait Draw {
    fn next_in(&mut self, n: u32) -> u32;
}

/// SplitMix64, seeded from the clock: enough to spread the load over equal DCs.
#[derive(Debug, Clone)]
pub struct ClockDraw(u64);

impl ClockDraw {
    pub fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        Self(nanos as u64 ^ u64::from(std::process::id()).rotate_left(32))
    }
}

impl Default for ClockDraw {
    fn default() -> Self {
        Self::new()
    }
}

impl Draw for ClockDraw {
    fn next_in(&mut self, n: u32) -> u32 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z % (u64::from(n) + 1)) as u32
    }
}

/// Order of the attempts (RFC 2782): increasing priority, then a draw weighted by the
/// weights, zero weights first. A target "." (service explicitly absent) is dropped.
pub fn order_srv(records: &[SrvRecord], draw: &mut dyn Draw) -> Vec<SrvRecord> {
    let mut left: Vec<SrvRecord> = records
        .iter()
        .filter(|r| !r.target.is_empty() && r.target != ".")
        .cloned()
        .collect();
    left.sort_by_key(|r| r.priority);
    let mut order = Vec::with_capacity(left.len());
    while let Some(first) = left.first() {
        let priority = first.priority;
        let count = left.iter().take_while(|r| r.priority == priority).count();
        let mut group: Vec<SrvRecord> = left.drain(..count).collect();
        group.sort_by_key(|r| r.weight);
        while !group.is_empty() {
            let total: u32 = group.iter().map(|r| u32::from(r.weight)).sum();
            let drawn = draw.next_in(total);
            let mut sum = 0u32;
            let index = group
                .iter()
                .position(|r| {
                    sum += u32::from(r.weight);
                    sum >= drawn
                })
                .unwrap_or(0);
            order.push(group.remove(index));
        }
    }
    order
}

/// What `/etc/resolv.conf` says about the servers to ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvConf {
    pub servers: Vec<IpAddr>,
    pub timeout: Duration,
    pub attempts: u32,
}

impl ResolvConf {
    /// Reads `resolv.conf` text: `nameserver` (three at most, like glibc), `options timeout:`
    /// and `attempts:`. No server: the local one.
    pub fn parse(text: &str) -> Self {
        let mut conf = Self {
            servers: Vec::new(),
            timeout: Duration::from_secs(5),
            attempts: 2,
        };
        for line in text.lines() {
            let mut words = line.split_whitespace();
            match words.next() {
                Some("nameserver") => {
                    let address = words.next().and_then(|w| w.split('%').next());
                    if let Some(ip) = address.and_then(|w| w.parse().ok()) {
                        if conf.servers.len() < 3 {
                            conf.servers.push(ip);
                        }
                    }
                }
                Some("options") => {
                    for option in words {
                        if let Some(n) = option.strip_prefix("timeout:") {
                            if let Ok(n) = n.parse::<u64>() {
                                conf.timeout = Duration::from_secs(n.clamp(1, 30));
                            }
                        } else if let Some(n) = option.strip_prefix("attempts:") {
                            if let Ok(n) = n.parse::<u32>() {
                                conf.attempts = n.clamp(1, 5);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if conf.servers.is_empty() {
            conf.servers.push(IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
        conf
    }

    /// `/etc/resolv.conf` of the host (defaults if unreadable).
    pub fn system() -> Self {
        Self::parse(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default())
    }
}

/// A DNS question for the SRV records of `name`.
fn build_query(id: u16, name: &str) -> Option<Vec<u8>> {
    let mut query = Vec::with_capacity(name.len() + 18);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, one question
    for label in name.trim_end_matches('.').split('.') {
        let length = u8::try_from(label.len())
            .ok()
            .filter(|&n| n > 0 && n < 64)?;
        if !label.is_ascii() {
            return None;
        }
        query.push(length);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&TYPE_SRV.to_be_bytes());
    query.extend_from_slice(&CLASS_IN.to_be_bytes());
    Some(query)
}

enum Answer {
    Records(Vec<SrvRecord>),
    /// NXDOMAIN or no SRV data.
    Missing,
    /// SERVFAIL or no answer in time: worth asking again.
    TryAgain(String),
    /// Any other refusal.
    Failed(String),
}

fn exchange_udp(server: SocketAddr, query: &[u8], timeout: Duration) -> std::io::Result<Vec<u8>> {
    let bind: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(server)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.send(query)?;
    let mut buffer = vec![0u8; 4096];
    loop {
        let n = socket.recv(&mut buffer)?;
        let reply = buffer.get(..n).unwrap_or_default();
        if reply.get(..2) == query.get(..2) {
            return Ok(reply.to_vec());
        }
    }
}

fn exchange_tcp(server: SocketAddr, query: &[u8], timeout: Duration) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&server, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let length = u16::try_from(query.len()).unwrap_or(u16::MAX);
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(query)?;
    let mut size = [0u8; 2];
    stream.read_exact(&mut size)?;
    let mut reply = vec![0u8; usize::from(u16::from_be_bytes(size))];
    stream.read_exact(&mut reply)?;
    Ok(reply)
}

fn ask(conf: &ResolvConf, name: &str, id: u16) -> Answer {
    let Some(query) = build_query(id, name) else {
        return Answer::Failed(format!("invalid name {name:?}"));
    };
    let mut last = String::from("no server");
    for _ in 0..conf.attempts {
        for &ip in &conf.servers {
            let server = SocketAddr::new(ip, 53);
            let mut reply = match exchange_udp(server, &query, conf.timeout) {
                Ok(reply) => reply,
                Err(e) => {
                    last = format!("{server}: {e}");
                    continue;
                }
            };
            if reply.get(2).is_some_and(|flags| flags & 0x02 != 0) {
                match exchange_tcp(server, &query, conf.timeout) {
                    Ok(full) => reply = full,
                    Err(e) => {
                        last = format!("{server} (TCP): {e}");
                        continue;
                    }
                }
            }
            match reply.get(3).map(|b| b & 0x0F) {
                Some(0) => {
                    return match parse_srv_response(&reply) {
                        Ok(records) if records.is_empty() => Answer::Missing,
                        Ok(records) => Answer::Records(records),
                        Err(e) => Answer::Failed(e.to_string()),
                    };
                }
                Some(3) => return Answer::Missing,
                Some(2) => last = format!("{server}: SERVFAIL"),
                Some(rcode) => return Answer::Failed(format!("{server}: rcode {rcode}")),
                None => last = format!("{server}: truncated answer"),
            }
        }
    }
    Answer::TryAgain(last)
}

/// Asks the DNS servers of the host for the SRV records of `name` (blocking). Empty if the
/// name does not exist; `SrvError::Unreachable` if no server answers.
pub fn query_srv(conf: &ResolvConf, name: &str) -> Result<Vec<SrvRecord>, SrvError> {
    let mut draw = ClockDraw::new();
    let mut detail = String::new();
    for attempt in 0..TRY_AGAIN_ATTEMPTS {
        let id = draw.next_in(u32::from(u16::MAX)) as u16;
        match ask(conf, name, id) {
            Answer::Records(records) => return Ok(records),
            Answer::Missing => return Ok(Vec::new()),
            Answer::Failed(e) => {
                detail = e;
                break;
            }
            Answer::TryAgain(e) => detail = e,
        }
        if attempt + 1 < TRY_AGAIN_ATTEMPTS {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    Err(SrvError::Unreachable {
        detail: format!("SRV {name}: {detail}"),
    })
}

pub fn dc_srv_name(domain: &str) -> String {
    format!("_ldap._tcp.dc._msdcs.{domain}")
}

pub fn pdc_srv_name(domain: &str) -> String {
    format!("_ldap._tcp.pdc._msdcs.{domain}")
}

/// Domain controllers announced for `domain`, in the order of the attempts (blocking).
pub fn find_dcs(conf: &ResolvConf, domain: &str) -> Result<Vec<SrvRecord>, SrvError> {
    let name = dc_srv_name(domain);
    let dcs = order_srv(&query_srv(conf, &name)?, &mut ClockDraw::new());
    if dcs.is_empty() {
        return Err(SrvError::NotFound { name });
    }
    Ok(dcs)
}

/// The PDC emulator of the domain, default target of the writes (blocking).
pub fn find_pdc(conf: &ResolvConf, domain: &str) -> Result<Option<SrvRecord>, SrvError> {
    let records = query_srv(conf, &pdc_srv_name(domain))?;
    Ok(order_srv(&records, &mut ClockDraw::new())
        .into_iter()
        .next())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Answer of the Samba DNS of the lab for `_ldap._tcp.dc._msdcs.lab.test`, as in the
    /// Python tests (two DCs, compressed names).
    fn lab_answer() -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x85, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        let question = build_query(0, "_ldap._tcp.dc._msdcs.lab.test").unwrap();
        m.extend_from_slice(&question[12..]);
        for (target, weight) in [("dc1", 100u16), ("dc2", 100)] {
            m.extend_from_slice(&[0xC0, 12]); // name: pointer to the question
            m.extend_from_slice(&[0, 33, 0, 1, 0, 0, 3, 0x84]);
            let mut data = vec![0, 0];
            data.extend_from_slice(&weight.to_be_bytes());
            data.extend_from_slice(&389u16.to_be_bytes());
            data.push(3);
            data.extend_from_slice(target.to_uppercase().as_bytes());
            data.extend_from_slice(&[0xC0, 12 + 1 + 5 + 1 + 4 + 1 + 2 + 1 + 6]); // "lab.test"
            m.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            m.extend_from_slice(&data);
        }
        m
    }

    #[test]
    fn parses_compressed_answer() {
        let records = parse_srv_response(&lab_answer()).unwrap();
        assert_eq!(
            records
                .iter()
                .map(|r| r.target.as_str())
                .collect::<Vec<_>>(),
            ["dc1.lab.test", "dc2.lab.test"]
        );
        assert_eq!(records[0].port, 389);
        assert_eq!(records[0].weight, 100);
    }

    #[test]
    fn refuses_malformed_messages() {
        assert_eq!(
            parse_srv_response(&[0; 5]),
            Err(InvalidResponse("truncated header"))
        );
        let answer = lab_answer();
        for n in 12..answer.len() {
            assert!(parse_srv_response(&answer[..n]).is_err(), "cut at {n}");
        }
        // Pointer to itself.
        let mut looped = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12];
        looped.extend_from_slice(&[0, 33, 0, 1]);
        assert_eq!(
            parse_srv_response(&looped),
            Err(InvalidResponse("compression loop"))
        );
    }

    struct Fixed(Vec<u32>);

    impl Draw for Fixed {
        fn next_in(&mut self, n: u32) -> u32 {
            self.0.remove(0).min(n)
        }
    }

    fn rec(priority: u16, weight: u16, target: &str) -> SrvRecord {
        SrvRecord {
            priority,
            weight,
            port: 389,
            target: target.into(),
        }
    }

    #[test]
    fn orders_by_priority_then_weight() {
        let records = [
            rec(10, 0, "c"),
            rec(0, 60, "a"),
            rec(0, 40, "b"),
            rec(0, 0, "zero"),
            rec(5, 1, "."),
        ];
        // Group of priority 0 sorted by weight: zero(0), b(40), a(60); total 100.
        let order = order_srv(&records, &mut Fixed(vec![50, 0, 0, 0]));
        let names: Vec<&str> = order.iter().map(|r| r.target.as_str()).collect();
        assert_eq!(names, ["a", "zero", "b", "c"]);
    }

    #[test]
    fn reads_resolv_conf() {
        let conf = ResolvConf::parse(
            "# comment\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\noptions edns0 timeout:2 attempts:3\nsearch lab.test\n",
        );
        assert_eq!(conf.servers.len(), 2);
        assert_eq!(conf.timeout, Duration::from_secs(2));
        assert_eq!(conf.attempts, 3);
        assert_eq!(
            ResolvConf::parse("").servers,
            [IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
    }

    #[test]
    fn builds_queries() {
        let q = build_query(0xABCD, "_ldap._tcp.lab.test.").unwrap();
        assert_eq!(&q[..4], &[0xAB, 0xCD, 1, 0]);
        assert_eq!(&q[12..18], b"\x05_ldap");
        assert_eq!(&q[q.len() - 4..], &[0, 33, 0, 1]);
        assert!(build_query(1, "a..b").is_none());
        assert!(build_query(1, "été.test").is_none());
    }
}
