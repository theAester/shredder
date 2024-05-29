
extern crate tun;


use std::net::{Ipv4Addr};
use std::io::{self, Read, Write, ErrorKind};
use std::time::Duration;
use std::process::Command;

use tun::{platform::linux::Device, Configuration};

use crate::configfile::ConfigFile;


pub fn create_and_configure_device(config: &ConfigFile) -> Result<Device, String>{
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

pub fn stop_and_clean_up_device(config: ConfigFile, _dev: Device){
    for app in config.applications.iter() {
        let dest_addr = &app.dest.to_string()[..];
        let phony_addr = &app.phony.unwrap().to_string()[..];
        let orig_addr = &app.origin.unwrap().to_string()[..];
        Command::new("iptables").args(&["-t", "nat", "-A", "OUTPUT", "-d", dest_addr, "-j", "DNAT", "--to-destination", phony_addr]).output().expect("oops");
        Command::new("iptables").args(&["-t", "nat", "-A", "POSTROUTING", "-s", phony_addr, "-j", "SNAT", "--to-source", orig_addr]).output().expect("oops");
    }
}
