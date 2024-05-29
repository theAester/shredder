
use std::env;
use std::thread;
use std::fs::File;
use std::io::{self, Read, Write, ErrorKind};
use std::net::{Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::channel, Arc, Mutex};
use tun::platform::linux::Device;
use pnet::packet::{Packet, ipv4::Ipv4Packet, ipv4::MutableIpv4Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket};
use pnet::util::MacAddr;

mod threadpool;

use crate::threadpool::ThreadPool;

pub fn serve_forever(config: &ConfigFile, pool: ThreadPool, dev: Device, running: AtomicBool) -> Result<(), String> {

    let mut buffer: Vec<u8> = vec![0u8, (config.mtu + 4) as usize];
    let config = Arc::new(config);
    let (mut devr, devw) = dev.split();
    let devw = Arc::new(Mutex::new(devw));
    while running.load(Ordering::SeqCst) {
        let n = match devr.read(buffer.as_mut_slice()) {
            Ok(s) => s,
            Err(e) => {
                if  e.kind() == ErrorKind::WouldBlock || 
                    e.kind() == ErrorKind::TimedOut {
                        thread::sleep(Duration::from_secs(1));
                        continue;
                } else {
                    return Err(format!("Error while reading from tun: {}", e.to_string()));
                }
            }
        };
        if n <= 0{
            return Err("Error n<=0".to_string());
        }

        let buf: Vec<u8> = buffer[0..n].iter().cloned().collect();
        let mut packet = MutableIpv4Packet::owned(buf).unwrap();

        let devwc = Arc::clone(devw);

        for (pos, app) in config.applications.iter().enumerate() {
            if app.origin.unwrap() == packet.get_source() && app.phony.unwrap() == packet.get_destination (){
                pool.schedule(move || {
                    process_packet(packet, devwc, app.clone(), true);
                }, pos);
            } else if app.phony.unwrap() == packet.get_destination() && app.dest == packet.get_source() {
                pool.schedule(move || {
                    process_packet(packet, devwc, app.clone(), false);
                }, pos);
            }
        }

        eprintln!("Packet doesnt belong to any applications");
        continue;
    }
    Ok(())
}

fn process_packet(packet: MutableTcpPacket, dev: Arc<Mutex<Device>>, target: Application, outbound: bool){
    return;
}
