use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

extern crate os_socketaddr;

use os_socketaddr::OsSocketAddr;
use winapi::um::winbase::INFINITE;
use windows::{
    core::*, Win32::Foundation::*, Win32::NetworkManagement::IpHelper::*,
    Win32::Networking::WinSock::*, Win32::System::Threading::*, Win32::System::IO::*,
};

struct Client {
    conn: std::pin::Pin<Box<quiche::Connection>>,
}
type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

struct EchoServer {
    socket: SOCKET,
    buf: [u8; 65535],
    out: [u8; 1350],
    dest: OsSocketAddr,
    destlen: i32,
    numberOfBytesRecvd: u32,
    numberOfBytesSend: u32,
    overlapped: OVERLAPPED,
    quic_config: quiche::Config,
    conn_id_seed: ring::hmac::Key,
    clients: ClientMap,
}

impl EchoServer {
    fn process_packets(&mut self) -> bool {
        let mut cbTransfer = 0;
        let mut dwFlags = 0;
        unsafe {
            WSAGetOverlappedResult(
                self.socket,
                &self.overlapped,
                &mut cbTransfer,
                true,
                &mut dwFlags,
            )
        };
        self.numberOfBytesRecvd = cbTransfer;
        println!("cbTransfer={}", cbTransfer);
        let len: usize = cbTransfer as usize;
        let pkt_buf = &mut self.buf[..len];
        let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
            Ok(v) => v,

            Err(e) => {
                println!("Parsing packet header failed: {:?}", e);
                return true;
            }
        };

        let conn_id = ring::hmac::sign(&self.conn_id_seed, &hdr.dcid);
        let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
        let conn_id = conn_id.to_vec().into();
        let client =
            if !self.clients.contains_key(&hdr.dcid) && !self.clients.contains_key(&conn_id) {
                if hdr.ty != quiche::Type::Initial {
                    println!("Packet is not Initial");
                    return true;
                }
                if !quiche::version_is_supported(hdr.version) {
                    println!("Doing version negotiation");

                    let write = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut self.out)
                        .unwrap() as u32;
                    if send(
                        self.socket,
                        &mut self.out,
                        write,
                        self.dest,
                        &mut self.overlapped,
                    ) {
                        return false;
                    }
                    return true;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let scid = quiche::ConnectionId::from_ref(&scid);

                // Token is always present in Initial packets.
                let token = hdr.token.as_ref().unwrap();

                // Do stateless retry if the client didn't send a token.
                if token.is_empty() {
                    println!("Doing stateless retry");

                    let new_token = mint_token(&hdr, &self.dest.into_addr().unwrap());

                    let write = quiche::retry(
                        &hdr.scid,
                        &hdr.dcid,
                        &scid,
                        &new_token,
                        hdr.version,
                        &mut self.out,
                    )
                    .unwrap() as u32;

                    if send(
                        self.socket,
                        &mut self.out,
                        write,
                        self.dest,
                        &mut self.overlapped,
                    ) {
                        return false;
                    }
                    return true;
                }

                let odcid = validate_token(&self.dest.into_addr().unwrap(), token);

                // The token was not valid, meaning the retry failed, so
                // drop the packet.
                if odcid.is_none() {
                    println!("Invalid address validation token");
                    return true;
                }

                if scid.len() != hdr.dcid.len() {
                    println!("Invalid destination connection ID");
                    return true;
                }

                // Reuse the source connection ID we sent in the Retry packet,
                // instead of changing it again.
                let scid = hdr.dcid.clone();

                println!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                let conn = quiche::accept(
                    &scid,
                    odcid.as_ref(),
                    self.dest.into_addr().unwrap(),
                    &mut self.quic_config,
                )
                .unwrap();

                let client = Client { conn };

                self.clients.insert(scid.clone(), client);

                self.clients.get_mut(&scid).unwrap()
            } else {
                match self.clients.get_mut(&hdr.dcid) {
                    Some(v) => v,

                    None => self.clients.get_mut(&conn_id).unwrap(),
                }
            };

        let recv_info = quiche::RecvInfo {
            from: self.dest.into_addr().unwrap(),
        };

        // Process potentially coalesced packets.
        let read = match client.conn.recv(pkt_buf, recv_info) {
            Ok(v) => v,

            Err(e) => {
                println!("{} recv failed: {:?}", client.conn.trace_id(), e);
                return true;
            }
        };

        println!("{} processed {} bytes", client.conn.trace_id(), read);

        if client.conn.is_in_early_data() || client.conn.is_established() {
            // Process all readable streams.
            for s in client.conn.readable() {
                while let Ok((read, fin)) = client.conn.stream_recv(s, &mut self.buf) {
                    println!("{} received {} bytes", client.conn.trace_id(), read);

                    let stream_buf = &self.buf[..read];

                    println!(
                        "{} stream {} has {} bytes (fin? {})",
                        client.conn.trace_id(),
                        s,
                        stream_buf.len(),
                        fin
                    );
                }
            }
        }
        return true;
    }

    fn send_packets(&mut self) {
        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        for client in self.clients.values_mut() {
            loop {
                let (write, send_info) = match client.conn.send(&mut self.out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        println!("{} done writing", client.conn.trace_id());
                        break;
                    }

                    Err(e) => {
                        println!("{} send failed: {:?}", client.conn.trace_id(), e);

                        client.conn.close(false, 0x1, b"fail").ok();
                        break;
                    }
                };

                if send(
                    self.socket,
                    &mut self.out,
                    write as u32,
                    send_info.to.into(),
                    &mut self.overlapped,
                ) {
                    break;
                }

                println!("{} written {} bytes", client.conn.trace_id(), write);
            }
        }
        // Garbage collect closed connections.
        self.clients.retain(|_, ref mut c| {
            println!("Collecting garbage");

            if c.conn.is_closed() {
                println!(
                    "{} connection collected {:?}",
                    c.conn.trace_id(),
                    c.conn.stats()
                );
            }

            !c.conn.is_closed()
        });
    }

    fn recv(&mut self) {
        self.destlen = self.dest.capacity();
        let mut wsabuf = WSABUF {
            len: 65535,
            buf: PSTR(self.buf.as_mut_ptr()),
        };

        loop {
            let mut numberOfBytesRecvd: u32 = 0;
            let mut flagsRecvd: u32 = 0;
            let ret = unsafe {
                WSARecvFrom(
                    self.socket,
                    &mut wsabuf,
                    1u32,
                    &mut numberOfBytesRecvd,
                    &mut flagsRecvd,
                    std::mem::transmute::<*mut winapi::shared::ws2def::SOCKADDR, *mut SOCKADDR>(
                        self.dest.as_mut_ptr(),
                    ),
                    &mut self.destlen,
                    &mut self.overlapped,
                    None,
                )
            };
            if ret == 0 {
                let ret = unsafe { WaitForSingleObject(self.overlapped.hEvent, 0) };
                assert!(ret == WAIT_OBJECT_0);
                self.process_packets();
                self.send_packets();
            } else {
                let ret = unsafe { WSAGetLastError() };
                match ret {
                    WSA_IO_PENDING => {
                        println!("WSA_IO_PENDING");
                        break;
                    }
                    _ => {
                        panic!("WSARecvFrom()={}", ret);
                    }
                }
            }
        }
    }

    fn new(addr: SocketAddr) -> EchoServer {
        let socket = unsafe {
            WSASocketA(
                AF_INET as i32,
                SOCK_DGRAM as i32,
                IPPROTO_UDP,
                std::ptr::null_mut(),
                0,
                WSA_FLAG_OVERLAPPED,
            )
        };
        if socket == INVALID_SOCKET {
            panic!("WSASocket");
        }

        let addr: OsSocketAddr = addr.into();
        unsafe {
            bind(
                socket,
                std::mem::transmute::<*const winapi::shared::ws2def::SOCKADDR, *const SOCKADDR>(
                    addr.as_ptr(),
                ),
                addr.len(),
            )
        };

        let overlapped = OVERLAPPED {
            Anonymous: OVERLAPPED_0 {
                Anonymous: OVERLAPPED_0_0 {
                    Offset: 9,
                    OffsetHigh: 0,
                },
            },
            hEvent: unsafe { CreateEventA(std::ptr::null_mut(), false, false, None) },
            Internal: 0,
            InternalHigh: 0,
        };

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("src/cert.crt")
            .unwrap();
        config.load_priv_key_from_pem_file("src/cert.key").unwrap();

        config
            .set_application_protos(b"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9")
            .unwrap();

        config.set_max_idle_timeout(5000);
        config.set_max_recv_udp_payload_size(1350);
        config.set_max_send_udp_payload_size(1350);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.enable_early_data();

        let rng = ring::rand::SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        EchoServer {
            socket: socket,
            buf: unsafe { std::mem::zeroed() },
            out: unsafe { std::mem::zeroed() },
            dest: OsSocketAddr::new(),
            destlen: 0,
            numberOfBytesRecvd: 0,
            numberOfBytesSend: 0,
            overlapped: overlapped,
            quic_config: config,
            conn_id_seed: conn_id_seed,
            clients: ClientMap::new(),
        }
    }
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &std::net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(
    src: &std::net::SocketAddr,
    token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

fn send(
    socket: SOCKET,
    out: &mut [u8],
    numberOfBytesSend: u32,
    to: OsSocketAddr,
    overlapped: &mut OVERLAPPED,
) -> bool {
    let mut wsabuf = WSABUF {
        len: numberOfBytesSend,
        buf: PSTR(out.as_mut_ptr()),
    };
    let mut numberofbytessent: u32 = 0;
    let ret = unsafe {
        WSASendTo(
            socket,
            &mut wsabuf,
            1,
            &mut numberofbytessent,
            0,
            std::mem::transmute::<*const winapi::shared::ws2def::SOCKADDR, *const SOCKADDR>(
                to.as_ptr(),
            ),
            to.len(),
            overlapped,
            None,
        )
    };
    if ret == 0 {
        let ret = unsafe { WaitForSingleObject(overlapped.hEvent, 0) };
        assert!(ret == WAIT_OBJECT_0);
        return true;
    } else {
        let ret = unsafe { WSAGetLastError() };
        match ret {
            WSA_IO_PENDING => {
                println!("WSA_IO_PENDING");
                return false;
            }
            _ => {
                panic!("WSARecvFrom()={}", ret);
            }
        }
    }
}

fn main() -> Result<()> {
    unsafe {
        let wVersionRequested: u16 = 2 << 8 | 2;
        let mut wsaData = WSAData {
            wVersion: 0,
            wHighVersion: 0,
            iMaxSockets: 0,
            iMaxUdpDg: 0,
            lpVendorInfo: PSTR(std::ptr::null_mut()),
            szDescription: [0; 257],
            szSystemStatus: [0; 129],
        };
        let ret = WSAStartup(wVersionRequested, &mut wsaData);
        if ret != 0 {
            panic!("WSAStartup");
        }
    }

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 4443);
    let mut server = EchoServer::new(addr);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 4567);
    let mut server1 = EchoServer::new(addr);
    server.overlapped.hEvent.ok()?;
    server1.overlapped.hEvent.ok()?;

    server.recv();
    server1.recv();

    loop {
        let handles: [HANDLE; 2] = [server.overlapped.hEvent, server1.overlapped.hEvent];

        match unsafe { WaitForMultipleObjects(2, handles.as_ptr(), false, INFINITE) } {
            0 => {
                println!("server recv");
                server.process_packets();
                server.send_packets();
                server.recv();
            }
            1 => {
                println!("server1 recv");
                server1.process_packets();
                server1.send_packets();
                server1.recv();
            }
            WAIT_TIMEOUT => {
                println!("timeout");
            }
            _ => {
                println!("error");
            }
        }
    }
    unsafe {
        WSACleanup();
    }
    Ok(())
}
