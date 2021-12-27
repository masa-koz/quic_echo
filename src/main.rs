extern crate os_socketaddr;

use os_socketaddr::OsSocketAddr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use winapi::um::winbase::INFINITE;
use windows::{
    core::*, Win32::Foundation::*, Win32::NetworkManagement::IpHelper::*,
    Win32::Networking::WinSock::*, Win32::System::Threading::*, Win32::System::IO::*,
};

struct EchoServer {
    socket: SOCKET,
    buf: [u8; 1024],
    dest: OsSocketAddr,
    destlen: i32,
    numberOfBytesRecvd: u32,
    flagsRecvd: u32,
    overlapped: OVERLAPPED,
}

impl EchoServer {
    fn recv(&mut self) {
        unsafe {
            self.destlen = self.dest.capacity();
            let mut wsabuf = WSABUF {
                len: 1024,
                buf: PSTR(self.buf.as_mut_ptr()),
            };

            let ret = WSARecvFrom(
                self.socket,
                &mut wsabuf,
                1u32,
                &mut self.numberOfBytesRecvd,
                &mut self.flagsRecvd,
                std::mem::transmute::<*mut winapi::shared::ws2def::SOCKADDR, *mut SOCKADDR>(
                    self.dest.as_mut_ptr(),
                ),
                &mut self.destlen,
                &mut self.overlapped,
                None,
            );
        }
    }

    fn send(&mut self) {
        unsafe {
            let mut wsabuf = WSABUF {
                len: self.numberOfBytesRecvd,
                buf: PSTR(self.buf.as_mut_ptr()),
            };
            let mut numberofbytessent: u32 = 0;

            let ret = WSASendTo(
                self.socket,
                &mut wsabuf,
                1,
                &mut numberofbytessent,
                0,
                std::mem::transmute::<*const winapi::shared::ws2def::SOCKADDR, *const SOCKADDR>(
                    self.dest.as_ptr(),
                ),
                self.dest.len(),
                std::ptr::null_mut(),
                None,
            );
        }
    }

    fn new(addr: SocketAddr) -> EchoServer {
        unsafe {
            let socket = WSASocketA(
                AF_INET as i32,
                SOCK_DGRAM as i32,
                IPPROTO_UDP,
                std::ptr::null_mut(),
                0,
                WSA_FLAG_OVERLAPPED,
            );
            if socket == INVALID_SOCKET {
                panic!("WSASocket");
            }

            let addr: OsSocketAddr = addr.into();
            bind(
                socket,
                std::mem::transmute::<*const winapi::shared::ws2def::SOCKADDR, *const SOCKADDR>(
                    addr.as_ptr(),
                ),
                addr.len(),
            );

            let overlapped = OVERLAPPED {
                Anonymous: OVERLAPPED_0 {
                    Anonymous: OVERLAPPED_0_0 {
                        Offset: 9,
                        OffsetHigh: 0,
                    },
                },
                hEvent: CreateEventA(std::ptr::null_mut(), false, false, None),
                Internal: 0,
                InternalHigh: 0,
            };

            EchoServer {
                socket: socket,
                buf: std::mem::zeroed(),
                dest: OsSocketAddr::new(),
                destlen: 0,
                numberOfBytesRecvd: 0,
                flagsRecvd: 0,
                overlapped: overlapped,
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

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3456);
        let mut server = EchoServer::new(addr);
        server.overlapped.hEvent.ok()?;

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 4567);
        let mut server1 = EchoServer::new(addr);
        server1.overlapped.hEvent.ok()?;

        server.recv();
        server1.recv();

        loop {
            let handles: [HANDLE; 2] = [server.overlapped.hEvent, server1.overlapped.hEvent];

            match WaitForMultipleObjects(2, handles.as_ptr(), false, INFINITE) {
                0 => {
                    println!("server recv");
                    server.send();
                    server.recv();
                }
                1 => {
                    println!("server1 recv");
                    server1.send();
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

        WSACleanup();
    }
    println!("Hello, world!");
    Ok(())
}
