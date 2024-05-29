
extern crate getopts;
extern crate config;
extern crate tun;
extern crate pnet;
extern crate signal_hook;

use std::env;
use std::fs::File;
use std::io::{self, Read, Write, ErrorKind};
use std::process::Command;
use std::net::Ipv4Addr;
use std::time::Duration;
use config::{Config, File as CFile};
use getopts::Options;
use tun::{Configuration, Device};
use pnet::packet::{Packet, ipv4::Ipv4Packet, ipv4::MutableIpv4Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::util::MacAddr;
use std::sync::Arc;
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};
use signal_hook::consts::SIGINT;
use signal_hook::iterator::Signals;

fn handle_sigint(r: Arc<AtomicBool>){
    let mut signal = Signals::new(&[SIGINT]).expect("oops2");
    thread::spawn(move ||{
        for sig in signal.forever(){
            match sig {
                SIGINT => {
                    println!("closing down");
                    r.store(false, Ordering::SeqCst);
                    break;
                },
                _ => unreachable!(),
            }
        }
    });
}

fn main(){
    let mut config = Configuration::default();
    config.name("shredder-tun");
    config.address(Ipv4Addr::new(10,1,1,1));
    config.netmask(Ipv4Addr::new(255,255,255,0));
    config.mtu(1500);
    config.up();

    let my_addr = Ipv4Addr::new(192, 168, 1, 101);
    let their_addr = Ipv4Addr::new(192, 168, 1, 135);
    let phony_addr = Ipv4Addr::new(10, 1, 1, 4);

    let mut dev = tun::create(&config).unwrap();
    dev.set_nonblock().unwrap();

    Command::new("iptables").args(&["-t", "nat", "-A", "OUTPUT", "-d", "192.168.1.135", "-j", "DNAT", "--to-destination", "10.1.1.4"]).output().expect("oops");
    //Command::new("iptables").args(&["-t", "nat", "-A", "PREROUTNG", "-d", "10.1.1.4", "-j", "DNAT", "--to-destination", "192.168.1.101"]).output().expect("oops");
    //Command::new("iptables").args(&["-t", "raw", "-A", "OUTPUT", "-d", "172.27.15.108", "-j", "NOTRACK"]);
    Command::new("iptables").args(&["-t", "nat", "-A", "POSTROUTING", "-s", "10.1.1.4", "-j", "SNAT", "--to-source", "192.168.1.101"]).output().expect("oops");

    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);
    handle_sigint(r);

    let mut buffer = [0u8; 1504];
    let mut outbound = true;
    while running.load(Ordering::SeqCst) {
        let n = match dev.read(&mut buffer) {
            Ok(s) => s,
            Err(e) => {
                if e.kind() == ErrorKind::WouldBlock {
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
                0usize
            }
        };
        if n <= 0{
            eprintln!("Error n<=0");
            break;
        }
        let mut packet = MutableIpv4Packet::new(&mut buffer[..n]).unwrap();
        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {


            println!("------------------------------");
            for &byte in packet.packet(){
                print!("{:02X} ", byte);
            }
            println!("\nPacket {:?}", packet);
            println!("------------------------------");
            
            if packet.get_source() == my_addr { // outbound
                packet.set_destination(their_addr.clone());
                packet.set_source(phony_addr.clone());
                outbound = true;
            } else if packet.get_source() == their_addr { // inbound
                packet.set_source(phony_addr.clone());
                packet.set_destination(my_addr.clone());
                outbound = false;
            } else { // what?
                panic!("what the fuck?");
            }

            let header_checksum = pnet::packet::ipv4::checksum(&packet.to_immutable());
            packet.set_checksum(header_checksum);
            println!("header checksum {}", header_checksum);
            println!("========================================");

            if let Some(mut tcp) = MutableTcpPacket::new(&mut packet.payload().to_owned()){
                if outbound {
                    let checksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &phony_addr, &their_addr);
                    tcp.set_checksum(checksum);
                } else {
                    let checksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &phony_addr, &my_addr);
                    tcp.set_checksum(checksum);
                }
                println!("Packet {:?}", packet);
                println!("n {}", n);
                println!("total length {}", packet.get_total_length());
                println!("protocol {:?}", packet.get_next_level_protocol());
                println!("TCP Packet: {:?}", tcp);
                println!("TCP Source Port: {}", tcp.get_source());
                println!("TCP Destination Port: {}", tcp.get_destination());
                println!("TCP Payload: {:?}", tcp.payload());
                packet.set_payload(tcp.packet());
            } else {
                eprintln!("packet is TCP but i couldnt parse it :(");
            }

            println!("------------------------------");
            for &byte in packet.packet(){
                print!("{:02X} ", byte);
            }
            println!("------------------------------");

            let n = dev.write(&packet.packet()).unwrap();
            println!("wrote {} bytes.", n);
        }
    }

    Command::new("iptables").args(&["-t", "nat", "-D", "POSTROUTING", "-s", "10.1.1.4", "-j", "SNAT", "--to-source", "192.168.1.101"]).output().expect("oops");
    //Command::new("iptables").args(&["-t", "raw", "-D", "OUTPUT", "-d", "172.27.15.108", "-j", "NOTRACK"]);
    //Command::new("iptables").args(&["-t", "nat", "-D", "PREROUTNG", "-d", "10.1.1.4", "-j", "DNAT", "--to-destination", "192.168.1.101"]).output().expect("oops");
    Command::new("iptables").args(&["-t", "nat", "-D", "OUTPUT", "-d", "192.168.1.135", "-j", "DNAT", "--to-destination", "10.1.1.4"]).output().expect("oops");
    println!("iptables out");
}

