use getopts::{Options, HasArg, Occur, Matches};
use std::process::exit;

pub fn parse_args(args: Vec<String>, progname: String) -> Result<Matches, String> {
    let mut opts = Options::new();

    opts.opt("c", "config", "path to the configuration file", "config", HasArg::Yes, Occur::Optional);
    opts.opt("h", "help", "prints this help message", "help", HasArg::No, Occur::Optional);

    let matches = match opts.parse(&args[1..]){
        Ok(s) => s,
        Err(m) => {
            return Err(format!("Error while parsing input arguments: {}", m));
        }
    };

    if matches.free.len() == 0 {
        return Err("Command not specified".to_string());
    }

    if matches.opt_present("h") {
        print_usage(progname, opts);
        exit(0);
    }

    return Ok(matches);
}

fn print_usage(progname: String, opts: Options){
    let brief = format!("Usage: {} COMMAND [OPTIONS]", progname);
    let usage = opts.usage(&brief);
    println!("{}\nCOMMAND=\trun\n", usage);
}
