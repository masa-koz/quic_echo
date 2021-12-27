extern crate os_socketaddr;

use os_socketaddr::OsSocketAddr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use windows::{
    core::*, Win32::Foundation::*, Win32::NetworkManagement::IpHelper::*,
    Win32::Networking::WinSock::*, Win32::System::Threading::*, Win32::System::IO::*,
};
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

        let socket = WSASocketA(
            AF_INET as i32,
            SOCK_DGRAM as i32,
            IPPROTO_UDP,
            std::ptr::null_mut(),
            0,
            0,
        );
        if socket == INVALID_SOCKET {
            panic!("WSASocket");
        }

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3456);
        let addr: OsSocketAddr = addr.into();
        bind(
            socket,
            std::mem::transmute::<*const winapi::shared::ws2def::SOCKADDR, *const SOCKADDR>(
                addr.as_ptr(),
            ),
            addr.len(),
        );

        let mut dest: OsSocketAddr = addr.into();
        let mut destlen = addr.capacity();
        let mut buf: [u8; 1024] = [0; 1024];
        let mut wsabuf = WSABUF {
            len: 1024,
            buf: PSTR(buf.as_mut_ptr()),
        };
        let mut numberOfBytesRecvd: u32 = 0;
        let mut flags: u32 = 0;
        let mut numberofbytessent: u32 = 0;

        let mut overlapped = OVERLAPPED {
            Anonymous: OVERLAPPED_0 {
                Anonymous: OVERLAPPED_0_0 {
                    Offset: 9,
                    OffsetHigh: 0,
                },
            },
            hEvent: CreateEventA(std::ptr::null_mut(), true, false, None),
            Internal: 0,
            InternalHigh: 0,
        };

        overlapped.hEvent.ok()?;

        loop {
            let ret = WSARecvFrom(
                socket,
                &mut wsabuf,
                1u32,
                &mut numberOfBytesRecvd,
                &mut flags,
                std::mem::transmute::<*mut winapi::shared::ws2def::SOCKADDR, *mut SOCKADDR>(
                    dest.as_mut_ptr(),
                ),
                &mut destlen,
                &mut overlapped,
                None,
            );

            let wait_ok = WaitForSingleObject(overlapped.hEvent, 2000);
            assert!(wait_ok == WAIT_OBJECT_0);

            let ret = WSASendTo(
                socket,
                &mut wsabuf,
                1,
                &mut numberofbytessent,
                0,
                std::mem::transmute::<*const winapi::shared::ws2def::SOCKADDR, *const SOCKADDR>(
                    dest.as_ptr(),
                ),
                dest.len(),
                std::ptr::null_mut(),
                None,
            );
        }

        WSACleanup();
    }
    println!("Hello, world!");
    Ok(())
}
