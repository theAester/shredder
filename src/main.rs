
extern crate getopts;
extern crate config;
extern crate tun;
extern crate pnet;
extern crate serde;
extern crate signal_hook;
extern crate mio;

use std::env;
use std::thread;
use std::sync::{mpsc::channel, Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use getopts::Matches;
use signal_hook::iterator::Signals;
use signal_hook::consts::TERM_SIGNALS;

mod cmd;
mod configfile;
mod threadpool;
mod device;

use crate::cmd::{parse_args};
use crate::configfile::read_config_file;
use crate::device::create_and_configure_device;
use crate::threadpool::ThreadPool;

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

fn run_command(config_path: String) -> Result<(), String>{
    let config = read_config_file(config_path)?;

    let pool = ThreadPool::new(config.num_threads, config.applications.len());

    let mut dev = match create_and_configure_device(&config) {
        Ok(s)=>s,
        Err(m) => { return Err(format!("Error while starting tun interface: {}", m)); }
    };

    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);
    handle_signals(r);

    serve_forever(&config, pool, dev, running)?;

    stop_and_clean_up_device(config, dev);
}

fn perform_command(command: String, opts: Matches) -> Result<(), String> {
    if command == "run" {
        let mut config_path = String::from("./config.json");
        if opts.opt_present("c"){
            config_path = opts.opt_str("c").expect("Unexpected error");
        }
        run_command(config_path)?;
    } else {
        return Err(format!("Unknown command \"{}\"", command));
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let opts = match parse_args(args, program) {
        Ok(s)=>s,
        Err(m) => {
            eprintln!("Error while parsing the arguments: {}", m);
            return;
        }
    };

    let command = opts.free[0].clone().to_lowercase();

    match perform_command(command, opts) {
        Ok(_)=>{},
        Err(m) => {
            eprintln!("Error: {}", m);
        }
    }
}
