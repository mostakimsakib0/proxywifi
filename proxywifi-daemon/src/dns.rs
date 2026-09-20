//! DNS-over-TCP forwarder.
//!
//! Most SOCKS5 proxies cannot relay UDP, so plain DNS cannot ride the tunnel.
//! This listens for UDP queries on the tunnel address and re-sends each one as
//! DNS-over-TCP to an upstream resolver; that TCP connection follows the tunnel
//! routes and leaves through the proxy (`SOCKS5 CONNECT`), so resolution never
//! touches the local network. nftables redirects applications' UDP/53 here.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;

/// Upstream resolvers tried in order (reached through the proxy).
pub const UPSTREAMS: [&str; 2] = ["1.1.1.1:53", "9.9.9.9:53"];
const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IN_FLIGHT: usize = 256;

/// One query over TCP: length-prefixed request, length-prefixed reply.
async fn ask(upstream: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut tcp = tokio::time::timeout(TIMEOUT, TcpStream::connect(upstream))
        .await
        .map_err(|_| std::io::ErrorKind::TimedOut)??;
    let len = u16::try_from(query.len()).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    tcp.write_all(&len.to_be_bytes()).await?;
    tcp.write_all(query).await?;
    let mut n = [0u8; 2];
    tokio::time::timeout(TIMEOUT, tcp.read_exact(&mut n))
        .await
        .map_err(|_| std::io::ErrorKind::TimedOut)??;
    let mut reply = vec![0u8; u16::from_be_bytes(n) as usize];
    tokio::time::timeout(TIMEOUT, tcp.read_exact(&mut reply))
        .await
        .map_err(|_| std::io::ErrorKind::TimedOut)??;
    Ok(reply)
}

/// Serve queries arriving on `socket` until the task is aborted.
pub async fn serve(socket: std::net::UdpSocket, upstreams: Vec<SocketAddr>) {
    let socket = match socket
        .set_nonblocking(true)
        .and_then(|_| UdpSocket::from_std(socket))
    {
        Ok(s) => Arc::new(s),
        Err(e) => return tracing::error!("DNS forwarder socket: {e}"),
    };
    let limit = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((n, client)) = socket.recv_from(&mut buf).await else {
            continue;
        };
        // Shed load rather than queue unboundedly; the client retries.
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let (query, socket, upstreams) = (buf[..n].to_vec(), socket.clone(), upstreams.clone());
        tokio::spawn(async move {
            for up in upstreams {
                match ask(up, &query).await {
                    Ok(reply) => {
                        let _ = socket.send_to(&reply, client).await;
                        break;
                    }
                    Err(e) => tracing::debug!("DNS upstream {up}: {e}"),
                }
            }
            drop(permit);
        });
    }
}

/// A minimal A query for `name`, for probes.
pub fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend([1, 0, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, one question
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend(label.as_bytes());
    }
    q.extend([0, 0, 1, 0, 1]); // root, QTYPE A, QCLASS IN
    q
}

/// Whether `reply` answers `id` successfully with at least one record.
pub fn reply_ok(id: u16, reply: &[u8]) -> bool {
    reply.len() >= 12
        && reply[..2] == id.to_be_bytes()
        && reply[2] & 0x80 != 0 // QR
        && reply[3] & 0x0f == 0 // NOERROR
        && u16::from_be_bytes([reply[6], reply[7]]) > 0
}

/// Resolve `name` through the forwarder at `addr`; `true` on a good answer.
pub fn probe(addr: SocketAddr, name: &str) -> bool {
    let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") else {
        return false;
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(6)));
    let query = build_query(0x5057, name);
    let mut buf = [0u8; 1500];
    sock.send_to(&query, addr).is_ok()
        && sock
            .recv_from(&mut buf)
            .map(|(n, _)| reply_ok(0x5057, &buf[..n]))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_query_is_answered_over_tcp() {
        // Fake upstream: replies with the query id, QR set, one answer.
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = upstream.accept().await.unwrap();
            let mut n = [0u8; 2];
            c.read_exact(&mut n).await.unwrap();
            let mut q = vec![0u8; u16::from_be_bytes(n) as usize];
            c.read_exact(&mut q).await.unwrap();
            let mut r = q.clone();
            r[2] |= 0x80;
            r[7] = 1;
            c.write_all(&(r.len() as u16).to_be_bytes()).await.unwrap();
            c.write_all(&r).await.unwrap();
        });

        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let task = tokio::spawn(serve(sock, vec![up_addr]));

        let ok = tokio::task::spawn_blocking(move || probe(addr, "example.com"))
            .await
            .unwrap();
        task.abort();
        assert!(ok, "forwarder must relay the UDP query through TCP");
    }

    #[test]
    fn reply_check_rejects_errors() {
        let mut r = build_query(1, "a.b");
        r[2] |= 0x80;
        assert!(!reply_ok(1, &r), "no answers");
        r[7] = 1;
        assert!(reply_ok(1, &r));
        r[3] |= 3; // NXDOMAIN
        assert!(!reply_ok(1, &r));
    }
}
