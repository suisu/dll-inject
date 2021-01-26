extern crate libc;
#[macro_use]
extern crate clap;

use std::env;
use clap::Arg;

pub mod loader;
pub mod win;

struct AppOptions {
    pid: u32,
    path_to_dll: String,
}

fn opt_parser_init() -> AppOptions {
    let app = app_from_crate!()
        .arg(
            Arg::with_name("process_id")
            .help("dll inject for target proces id")
            .short("p")
            .long("pid")
            .takes_value(true)
            .required(true),
        ).arg(
            Arg::with_name("dll_path")
            .help("Specify path of injected dll")
            .short("f")
            .long("file")
            .takes_value(true)
            .required(true),
        ).get_matches();

    AppOptions {
        pid: app
            .value_of("process_id")
            .unwrap()
            .parse::<u32>()
            .unwrap_or_default(),
        path_to_dll: app.value_of("dll_path").unwrap().to_owned(),
    }
}

fn init_app() -> AppOptions {
    opt_parser_init()
}

fn main() {
    let AppOptions { pid, path_to_dll } = init_app();
    let _result = loader::dll_attach(path_to_dll, pid)
        .map_err(|e| eprintln!("{}", e))
        .map(|_s| {
            println!("Injection was successful");
        }) ;
}
