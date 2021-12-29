use std::collections::HashMap;
use std::f32::consts::E;
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

#[derive(Debug)]
enum EchoServerError {
    Discarded,
    Abort,
    RecvPending,
    SendPending,
    Fatal,
}

type EchoServerResult<T> = std::result::Result<T, EchoServerError>;

struct EchoServer {
    socket: SOCKET,
    buf: [u8; 65535],
    stream_buf: [u8; 65535],
    out: [u8; 1350],
    from: OsSocketAddr,
    from_len: i32,
    recv_len: u32,
    send_len: usize,
    recving: bool,
    sending: bool,
    recv_overlapped: OVERLAPPED,
    send_overlapped: OVERLAPPED,
    clients: ClientMap,
    quic_config: quiche::Config,
    keylog: Option<std::fs::File>,
    conn_id_seed: ring::hmac::Key,
}

impl EchoServer {
    fn recv_quic_packets(&mut self) -> EchoServerResult<()> {
        loop {
            if !self.recving {
                match recvfrom(
                    self.socket,
                    &mut self.buf,
                    65535,
                    &mut self.from,
                    &mut self.from_len,
                    &mut self.recv_overlapped,
                ) {
                    Ok(read) => {
                        if read == 0 {
                            self.recving = true;
                            return Err(EchoServerError::RecvPending);
                        }
                    }
                    Err(_) => {
                        return Err(EchoServerError::Fatal);
                    }
                }
            }
            self.recving = false;

            let mut cbTransfer = 0;
            let mut dwFlags = 0;
            let ret = unsafe {
                WSAGetOverlappedResult(
                    self.socket,
                    &self.recv_overlapped,
                    &mut cbTransfer,
                    true,
                    &mut dwFlags,
                )
            };
            if !ret.as_bool() {
                return Err(EchoServerError::Fatal);
            }
            self.recv_len = cbTransfer;
            println!("WSARecvFrom()'s cbTransfer={}", cbTransfer);
            match self.process_quic_packets() {
                Ok(()) | Err(EchoServerError::Discarded) => {
                    continue;
                }
                Err(EchoServerError::Fatal) => {
                    return Err(EchoServerError::Fatal);
                }
                Err(EchoServerError::Abort) | Err(EchoServerError::SendPending) | Err(_) => {
                    break;
                }
            }
        }
        if let Err(_) = recvfrom(
            self.socket,
            &mut self.buf,
            65535,
            &mut self.from,
            &mut self.from_len,
            &mut self.recv_overlapped,
        ) {
            return Err(EchoServerError::Fatal);
        }

        Ok(())
    }

    fn send_quic_packets_completed(&mut self) -> EchoServerResult<()> {
        assert!(self.sending);

        let mut cbTransfer = 0;
        let mut dwFlags = 0;
        let ret = unsafe {
            WSAGetOverlappedResult(
                self.socket,
                &self.send_overlapped,
                &mut cbTransfer,
                true,
                &mut dwFlags,
            )
        };
        if !ret.as_bool() {
            return Err(EchoServerError::Fatal);
        }
        println!("WSASendTo()'s cbTransfer={}", cbTransfer);
        self.sending = false;
        Ok(())
    }

    fn process_quic_packets(&mut self) -> EchoServerResult<()> {
        let pkt_buf = &mut self.buf[..(self.recv_len as usize)];
        let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
            Ok(v) => v,

            Err(e) => {
                println!("Parsing packet header failed: {:?}", e);
                return Err(EchoServerError::Discarded);
            }
        };

        let conn_id = ring::hmac::sign(&self.conn_id_seed, &hdr.dcid);
        let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
        let conn_id = conn_id.to_vec().into();
        let new_conn =
            !self.clients.contains_key(&hdr.dcid) && !self.clients.contains_key(&conn_id);
        if new_conn {
            match self.handle_handshake(&hdr, &conn_id) {
                Ok(Some(client)) => {
                    self.clients.insert(hdr.dcid.clone(), client);
                }
                Ok(None) => {
                    if !self.sending {
                        match sendto(
                            self.socket,
                            &mut self.out,
                            self.send_len as u32,
                            self.from.into(),
                            &mut self.send_overlapped,
                        ) {
                            Ok(written) => {
                                if written > 0 {
                                    return Ok(());
                                } else {
                                    self.sending = true;
                                    return Err(EchoServerError::SendPending);
                                }
                            }
                            Err(_) => {
                                return Err(EchoServerError::Fatal);
                            }
                        }
                    } else {
                        return Err(EchoServerError::SendPending);
                    }
                }
                Err(_) => {
                    return Err(EchoServerError::Discarded);
                }
            }
        }

        self.handle_after_established(&hdr.dcid, &conn_id);

        Ok(())
    }
    fn handle_handshake(
        &mut self,
        hdr: &quiche::Header,
        conn_id: &quiche::ConnectionId,
    ) -> EchoServerResult<Option<Client>> {
        if hdr.ty != quiche::Type::Initial {
            println!("Packet is not Initial");
            return Err(EchoServerError::Discarded);
        }
        if !quiche::version_is_supported(hdr.version) {
            println!("Doing version negotiation");

            self.send_len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut self.out).unwrap();
            return Ok(None);
        }

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        scid.copy_from_slice(&conn_id);

        let scid = quiche::ConnectionId::from_ref(&scid);

        // Token is always present in Initial packets.
        let token = hdr.token.as_ref().unwrap();

        // Do stateless retry if the client didn't send a token.
        if token.is_empty() {
            println!("Doing stateless retry");

            let new_token = mint_token(&hdr, &self.from.into_addr().unwrap());

            self.send_len = quiche::retry(
                &hdr.scid,
                &hdr.dcid,
                &scid,
                &new_token,
                hdr.version,
                &mut self.out,
            )
            .unwrap();

            return Ok(None);
        }

        let odcid = validate_token(&self.from.into_addr().unwrap(), token);

        // The token was not valid, meaning the retry failed, so
        // drop the packet.
        if odcid.is_none() {
            println!("Invalid address validation token");
            return Err(EchoServerError::Discarded);
        }

        if scid.len() != hdr.dcid.len() {
            println!("Invalid destination connection ID");
            return Err(EchoServerError::Discarded);
        }

        // Reuse the source connection ID we sent in the Retry packet,
        // instead of changing it again.
        let scid = hdr.dcid.clone();

        println!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

        let mut conn = quiche::accept(
            &scid,
            odcid.as_ref(),
            self.from.into_addr().unwrap(),
            &mut self.quic_config,
        )
        .unwrap();

        if let Some(keylog) = &mut self.keylog {
            if let Ok(keylog) = keylog.try_clone() {
                println!("{:?}", keylog);
                conn.set_keylog(Box::new(keylog));
            }
        }

        Ok(Some(Client { conn }))
    }

    fn handle_after_established(
        &mut self,
        dcid: &quiche::ConnectionId<'static>,
        conn_id: &quiche::ConnectionId<'static>,
    ) {
        let pkt_buf = &mut self.buf[..(self.recv_len as usize)];
        let recv_info = quiche::RecvInfo {
            from: self.from.into_addr().unwrap(),
        };
        let client = match self.clients.get_mut(dcid) {
            Some(v) => v,

            None => self.clients.get_mut(conn_id).unwrap(),
        };

        // Process potentially coalesced packets.
        let read = match client.conn.recv(pkt_buf, recv_info) {
            Ok(v) => v,

            Err(e) => {
                println!("{} recv failed: {:?}", client.conn.trace_id(), e);
                return;
            }
        };

        println!("{} processed {} bytes", client.conn.trace_id(), read);

        if client.conn.is_in_early_data() || client.conn.is_established() {
            // Process all readable streams.
            for s in client.conn.readable() {
                let mut buf: [u8; 65535];
                while let Ok((read, fin)) = client.conn.stream_recv(s, &mut self.stream_buf) {
                    println!("{} received {} bytes", client.conn.trace_id(), read);

                    let stream_buf = &self.stream_buf[..read];

                    println!(
                        "{} stream {} has {} bytes (fin? {})",
                        client.conn.trace_id(),
                        s,
                        stream_buf.len(),
                        fin
                    );

                    let written = match client.conn.stream_send(s, stream_buf, true) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => 0,

                        Err(e) => {
                            println!("{} stream send failed {:?}", client.conn.trace_id(), e);
                            break;
                        }
                    };
                    println!(
                        "{} write into stream {} {} bytes",
                        client.conn.trace_id(),
                        s,
                        stream_buf.len(),
                    );
                }
            }
        }
    }

    fn send_quic_packets(&mut self) -> EchoServerResult<()> {
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
                        return Err(EchoServerError::Abort);
                    }
                };

                if !self.sending {
                    match sendto(
                        self.socket,
                        &mut self.out,
                        write as u32,
                        send_info.to.into(),
                        &mut self.send_overlapped,
                    ) {
                        Ok(written) => {
                            if written > 0 {
                                println!("{} written {} bytes", client.conn.trace_id(), written);
                            } else {
                                println!(
                                    "{} will be written {} bytes",
                                    client.conn.trace_id(),
                                    write
                                );
                                self.sending = true;
                                return Err(EchoServerError::SendPending);
                            }
                        }
                        Err(_) => {
                            return Err(EchoServerError::Fatal);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn timeout(&mut self) -> Option<std::time::Duration> {
        self.clients.values().filter_map(|c| c.conn.timeout()).min()
    }

    fn on_timeout(&mut self) {
        self.clients.values_mut().for_each(|c| c.conn.on_timeout());
    }

    fn remove_closed_connections(&mut self) -> EchoServerResult<()> {
        self.clients.retain(|_, ref mut c| {
            if c.conn.is_closed() {
                println!(
                    "{} connection collected {:?}",
                    c.conn.trace_id(),
                    c.conn.stats()
                );
            }

            !c.conn.is_closed()
        });
        Ok(())
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
            panic!("WSASocket()");
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

        let recv_overlapped = OVERLAPPED {
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

        let send_overlapped = OVERLAPPED {
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
            .set_application_protos(
                b"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9\x06sample",
            )
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

        let mut keylog = None;
        if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(keylog_path)
                .unwrap();

            keylog = Some(file);

            config.log_keys();
        }
        let rng = ring::rand::SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        EchoServer {
            socket: socket,
            buf: [0; 65535],
            stream_buf: [0; 65535],
            out: [0; 1350],
            from: OsSocketAddr::new(),
            from_len: 0,
            recv_len: 0,
            send_len: 0,
            recv_overlapped: recv_overlapped,
            send_overlapped: send_overlapped,
            recving: false,
            sending: false,
            clients: ClientMap::new(),
            quic_config: config,
            keylog: keylog,
            conn_id_seed: conn_id_seed,
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

fn wsa_startup() -> Result<()> {
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
    let ret = unsafe { WSAStartup(wVersionRequested, &mut wsaData) };
    if ret != 0 {
        return Err(Error::new(
            unsafe { std::mem::transmute::<i32, HRESULT>(WSAGetLastError()) },
            "".into(),
        ));
    }
    return Ok(());
}

fn wsa_cleanup() {
    unsafe {
        WSACleanup();
    }
}

fn recvfrom(
    socket: SOCKET,
    buf: &mut [u8],
    buflen: u32,
    from: &mut OsSocketAddr,
    fromlen: &mut i32,
    overlapped: &mut OVERLAPPED,
) -> Result<usize> {
    let mut wsabuf = WSABUF {
        len: buflen,
        buf: PSTR(buf.as_mut_ptr()),
    };

    let mut numberOfBytesRecvd: u32 = 0;
    let mut flagsRecvd: u32 = 0;
    *fromlen = from.capacity();
    let ret = unsafe {
        WSARecvFrom(
            socket,
            &mut wsabuf,
            1u32,
            &mut numberOfBytesRecvd,
            &mut flagsRecvd,
            std::mem::transmute::<*mut winapi::shared::ws2def::SOCKADDR, &mut SOCKADDR>(
                from.as_mut_ptr(),
            ),
            fromlen,
            overlapped,
            None,
        )
    };
    if ret == 0 {
        let ret = unsafe { WaitForSingleObject(overlapped.hEvent, 0) };
        match ret {
            WAIT_OBJECT_0 => {
                return Ok(numberOfBytesRecvd as usize);
            }
            _ => {
                return Err(Error::new(
                    unsafe { std::mem::transmute::<u32, HRESULT>(ret) },
                    "".into(),
                ));
            }
        }
    } else {
        let ret = unsafe { WSAGetLastError() };
        match ret {
            WSA_IO_PENDING => {
                println!("WSARecvFrom() return WSA_IO_PENDING");
                return Ok(0);
            }
            _ => {
                return Err(Error::new(
                    unsafe { std::mem::transmute::<i32, HRESULT>(ret) },
                    "".into(),
                ));
            }
        }
    }
}

fn sendto(
    socket: SOCKET,
    out: &mut [u8],
    numberOfBytesSend: u32,
    to: OsSocketAddr,
    overlapped: &mut OVERLAPPED,
) -> Result<usize> {
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
        println!("WSASend()'s numberofbytessent={}", numberofbytessent);
        match ret {
            WAIT_OBJECT_0 => {
                return Ok(numberofbytessent as usize);
            }
            _ => {
                return Err(Error::new(
                    unsafe { std::mem::transmute::<u32, HRESULT>(ret) },
                    "".into(),
                ));
            }
        }
    } else {
        let ret = unsafe { WSAGetLastError() };
        match ret {
            WSA_IO_PENDING => {
                println!("WSASendTo() return WSA_IO_PENDING");
                return Ok(0);
            }
            _ => {
                return Err(Error::new(
                    unsafe { std::mem::transmute::<i32, HRESULT>(ret) },
                    "".into(),
                ));
            }
        }
    }
}

fn main() -> Result<()> {
    wsa_startup()?;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 4443);
    let mut server = EchoServer::new(addr);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 4567);
    let mut server1 = EchoServer::new(addr);

    if let Err(EchoServerError::Fatal) = server.recv_quic_packets() {
        panic!("EchoServer::recv_quic_packets()");
    }
    if let Err(EchoServerError::Fatal) = server1.recv_quic_packets() {
        panic!("EchoServer::recv_quic_packets()");
    }

    loop {
        let handles: [HANDLE; 4] = [
            server.recv_overlapped.hEvent,
            server1.recv_overlapped.hEvent,
            server.send_overlapped.hEvent,
            server1.send_overlapped.hEvent,
        ];

        let timeout = [server.timeout(), server1.timeout()]
            .into_iter()
            .filter_map(|t| t)
            .min();
        let ret = if timeout.is_some() {
            println!("Wait will timeout after {} msec", timeout.unwrap().as_millis());
            unsafe {
                WaitForMultipleObjects(
                    4,
                    handles.as_ptr(),
                    false,
                    timeout.unwrap().as_millis().try_into().unwrap(),
                )
            }
        } else {
            println!("Wait will not timeout");
            unsafe { WaitForMultipleObjects(4, handles.as_ptr(), false, INFINITE) }
        };
        match ret {
            0 => {
                println!("server recv");
                if let Err(EchoServerError::Fatal) = server.recv_quic_packets() {
                    panic!("EchoServer::recv_quic_packets()");
                }
            }
            1 => {
                if let Err(EchoServerError::Fatal) = server1.recv_quic_packets() {
                    panic!("EchoServer::recv_quic_packets()");
                }
            }
            2 => {
                println!("server send finish");
                if let Err(EchoServerError::Fatal) = server.send_quic_packets_completed() {
                    panic!("EchoServer::send_quic_packets_completed()");
                }
            }
            3 => {
                println!("server1 send finish");
                if let Err(EchoServerError::Fatal) = server1.send_quic_packets_completed() {
                    panic!("EchoServer::senf_finish()");
                }
            }
            WAIT_TIMEOUT => {
                println!("timeout");
                server.on_timeout(); // XXX
                server1.on_timeout(); // XXX
            }
            _ => {
                println!("error");
                break;
            }
        }
        server.send_quic_packets();
        server.remove_closed_connections();
        server1.send_quic_packets();
        server1.remove_closed_connections();
    }

    wsa_cleanup();

    Ok(())
}
