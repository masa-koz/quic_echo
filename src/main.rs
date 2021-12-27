use windows::{
    core::*, Win32::Foundation::*, Win32::NetworkManagement::IpHelper::*,
    Win32::Networking::WinSock::*,
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

        let addr = SOCKADDR_IN {
            sin_family: AF_INET as u16,
            sin_port: 3456u16.to_be(),
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_un_b: IN_ADDR_0_0 {
                        s_b1: 0,
                        s_b2: 0,
                        s_b3: 0,
                        s_b4: 0
                    }
                }
            },
            sin_zero: [0; 8]
        };

        WSACleanup();
    }
    println!("Hello, world!");
    Ok(())
}
