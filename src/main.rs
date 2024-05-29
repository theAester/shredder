
extern crate getopts;
extern crate config;
extern crate tun;
extern crate pnet;
extern crate serde;
extern crate signal_hook;
extern crate mio;

use std::env;
use std::thread;
use std::fs::File;
use std::io::{self, Read, Write, ErrorKind};
use std::net::{Ipv4Addr};
use std::process::Command;
use std::time::Duration;
use std::sync::{mpsc::channel, Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use config::{Config, File as CFile, FileFormat};
use serde::{Deserialize, Serialize};
use getopts::Options;
use tun::{platform::linux::Device, Configuration};
use pnet::packet::{Packet, ipv4::Ipv4Packet, ipv4::MutableIpv4Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket};
use pnet::util::MacAddr;
use signal_hook::iterator::Signals;
use signal_hook::consts::TERM_SIGNALS;
use mio::{Events, Interest, Poll, Token};

mod threadpool;

use crate::threadpool::ThreadPool;

const TUN: Token= Token(0);

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Application {
    name: String,
    dest: Ipv4Addr,
    phony: Option<Ipv4Addr>,
    origin: Option<Ipv4Addr>,
    ports: Option<Vec<u16>>
}

#[derive(Debug, Serialize, Deserialize)]
struct ConfigFile {
    name: String,
    num_threads: usize,
    origin: Ipv4Addr,
    address: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    mtu: u16,
    phony_range_start: Option<u8>,
    applications: Vec<Application>,
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn read_config_file(file_path: &str) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn config_sanity_check(config: &mut ConfigFile) -> Result<(), String> {
    // num threads
    if config.num_threads > 128 {
        return Err("Seriosuly?".into());
    }


    if config.phony_range_start.is_none() {
        config.phony_range_start = Some(config.address.octets()[3] + 1);
    }

    let addr = config.address.octets();
    for pos in 0..config.applications.len() {
        if config.applications[pos].phony.is_none() {
            let phony_addr = Ipv4Addr::new(addr[0], addr[1], addr[2], config.phony_range_start.unwrap() + pos as u8);
            config.applications[pos].phony = Some(phony_addr);
        }
        if config.applications[pos].origin.is_none() {
            config.applications[pos].origin = Some(config.origin.clone())
        }
    }

    // address
    Ok(())
}

fn create_and_configure_device(config: &ConfigFile) -> Result<Device, String>{
    let mut tun_config = Configuration::default();
    tun_config.name(config.name.clone());
    tun_config.address(config.address);
    tun_config.netmask(config.subnet_mask);
    tun_config.mtu(config.mtu.into());
    tun_config.up();
    
    let mut dev = tun::create(&tun_config).unwrap();
    dev.set_nonblock().unwrap();
    let start = config.phony_range_start;

    for app in config.applications.iter() {
        let dest_addr = &app.dest.to_string()[..];
        let phony_addr = &app.phony.unwrap().to_string()[..];
        let orig_addr = &app.origin.unwrap().to_string()[..];
        Command::new("iptables").args(&["-t", "nat", "-A", "OUTPUT", "-d", dest_addr, "-j", "DNAT", "--to-destination", phony_addr]).output().expect("oops");
        Command::new("iptables").args(&["-t", "nat", "-A", "POSTROUTING", "-s", phony_addr, "-j", "SNAT", "--to-source", orig_addr]).output().expect("oops");
    }

    Ok(dev)
}

fn handle_signals(r: Arc<AtomicBool>){
    let mut signal = Signals::new(TERM_SIGNALS).expect("oops2");
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

fn run_command(config_path: &str) -> Result<(), String> {
    let mut config_builder = Config::builder()
        .add_source(CFile::new(config_path, FileFormat::Json))
        .set_default("name", "shredder-tun").unwrap()
        .set_default("mtu", 1500)
        .unwrap();

    let mut config: ConfigFile;

    match config_builder.build() {
        Ok(c) => {
            config = match c.try_deserialize() {
                Ok(s)=>s,
                Err(m) => { return Err(format!("Error while unpacking json config: {}", m.to_string())); }
            }
        },
        Err(m) => {
            return Err(format!("Error while reading config file: {}", m.to_string()));
        }
    }

    match config_sanity_check(&mut config){
        Ok(_) => {},
        Err(m) => {
            return Err(format!("{}", m.to_string()));
        }
    }

    let pool = ThreadPool::new(config.num_threads, config.applications.len());

    let mut dev = match create_and_configure_device(&config) {
        Ok(s)=>s,
        Err(m) => { return Err(format!("Error while starting tun interface: {}", m)); }
    };


    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);
    handle_signals(r);

    let mut buffer: Vec<u8> = vec![0u8; (config.mtu + 4) as usize];
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
        let mut target: Option<Application> = None;
        let mut target_ind: usize = 0;
        let mut outbound = true;
        for (pos, app) in config.applications.iter().enumerate() {
            if app.origin.unwrap() == packet.get_source() && app.phony.unwrap() == packet.get_destination (){
                outbound = true;
                target = Some(app.clone());
                target_ind = pos;
            } else if app.phony.unwrap() == packet.get_destination() && app.dest == packet.get_source() {
                outbound = false;
                target = Some(app.clone());
                target_ind = pos;
            }
        }

        if target.is_none(){
            eprintln!("packet doesnt belong to any application");
            continue;
        }

        let conf = Arc::clone(&config);
        let devwc = Arc::clone(&devw);
        pool.schedule(move || {
            if packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {

                let target = target.unwrap();

                let my_addr = target.origin.unwrap().clone();
                let phony_addr = target.phony.unwrap().clone();
                let their_addr = target.dest.clone();

                println!("------------------------------");
                for &byte in packet.packet(){
                    print!("{:02X} ", byte);
                }
                println!("\nPacket {:?}", packet);
                println!("------------------------------");

                if outbound { // outbound
                    packet.set_destination(their_addr.clone());
                    packet.set_source(phony_addr.clone());
                } else { // inbound
                    packet.set_source(phony_addr.clone());
                    packet.set_destination(my_addr.clone());
                } 

                let header_checksum = pnet::packet::ipv4::checksum(&packet.to_immutable());
                packet.set_checksum(header_checksum);
                println!("header checksum {}", header_checksum);
                println!("========================================");

                if let Some(mut tcp) = MutableTcpPacket::new(&mut packet.payload().to_owned()){

                    // this is where you can edit the packet payload

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

                let n = devwc.as_ref().lock().unwrap().write(&packet.packet()).unwrap();
                println!("wrote {} bytes.", n);
            }
        }, target_ind);
    }

    clean_up_tun(&config);

    Ok(())
}

fn clean_up_tun(config: &ConfigFile) {
    for app in config.applications.iter() {
        let dest_addr = &app.dest.to_string()[..];
        let phony_addr = &app.phony.unwrap().to_string()[..];
        let orig_addr = &app.origin.unwrap().to_string()[..];
        Command::new("iptables").args(&["-t", "nat", "-A", "OUTPUT", "-d", dest_addr, "-j", "DNAT", "--to-destination", phony_addr]).output().expect("oops");
        Command::new("iptables").args(&["-t", "nat", "-A", "POSTROUTING", "-s", phony_addr, "-j", "SNAT", "--to-source", orig_addr]).output().expect("oops");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("c", "config", "set config file path", "PATH");
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let config_path = match matches.opt_str("c") {
        Some(path) => path,
        None => {
            eprintln!("Error: Config file path is required");
            print_usage(&program, opts);
            return;
        }
    };

    match run_command(&config_path) {
        Ok(_) => (),
        Err(e) => println!("Error: {}", e),
    }
}

