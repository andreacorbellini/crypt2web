// Copyright 2020 Andrea Corbellini
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![warn(missing_debug_implementations)]
#![warn(unreachable_pub)]
#![warn(unused_qualifications)]

use clap::App;
use clap::Arg;
use handlebars::Handlebars;
use serde::Serialize;
use std::fmt;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::path::Path;

const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

static TEMPLATE: &str = include_str!("template.html");
static JS_LOADER: &str = include_str!("../crypt2web-wasm/pkg/crypt2web_wasm.js");
static WASM: &[u8] = include_bytes!("../crypt2web-wasm/pkg/crypt2web_wasm_bg.wasm");

static mut VERBOSE: bool = false;

macro_rules! log {
    ( $( $tt:tt )* ) => ({
        if unsafe { VERBOSE } {
            eprintln!($( $tt )*);
        }
    })
}

macro_rules! fail {
    ( $( $tt:tt )* ) => ({
        eprintln!($( $tt )*);
        std::process::exit(1)
    })
}

#[derive(Debug)]
struct Options {
    verbose: bool,
    input: Option<File>,
    output: Option<File>,
    mime_type: Option<String>,
    password: String,
    allow_prompt: bool,
    allow_fragment: bool,
}

fn parse_args() -> Options {
    let matches = App::new(NAME)
                      .version(VERSION)
                      .about(DESCRIPTION)
                      .arg(Arg::with_name("input")
                           .takes_value(true)
                           .value_name("FILE")
                           .help("Read the plaintext data to encrypt from FILE. Defaults to standard input"))
                      .arg(Arg::with_name("output")
                           .short("o")
                           .long("output")
                           .takes_value(true)
                           .value_name("FILE")
                           .help("Write the encrypted webpage to FILE. Defaults to standard output"))
                      .arg(Arg::with_name("mime-type")
                           .short("t")
                           .long("mime-type")
                           .takes_value(true)
                           .value_name("MIME")
                           .help("The MIME type of the content to encrypt"))
                      .arg(Arg::with_name("password-file")
                           .short("p")
                           .long("password-file")
                           .takes_value(true)
                           .value_name("FILE")
                           .help("Read the password from FILE. Only the first line of FILE is read. Trailing new \
                                  line characters are ignored"))
                      .arg(Arg::with_name("password-methods")
                           .short("m")
                           .long("password-methods")
                           .takes_value(true)
                           .value_name("METHOD")
                           .multiple(true)
                           .require_delimiter(true)
                           .case_insensitive(true)
                           .possible_values(&["prompt", "fragment"])
                           .help("List of accepted input password methods, comma separated"))
                      .arg(Arg::with_name("verbose")
                           .short("v")
                           .long("verbose")
                           .help("Show verbose log messages"))
                      .get_matches();

    let input = matches.value_of("input")
                       .map(open_file);

    let output = matches.value_of("output")
                        .map(create_file);

    let password = matches.value_of("password-file")
                          .map(read_password)
                          .unwrap_or_else(prompt_password);

    let mime_type = matches.value_of("mime-type")
                           .map(|s| s.to_owned());

    let methods = matches.values_of("password-methods")
                         .map(|v| v.collect::<Vec<&str>>())
                         .unwrap_or_else(Vec::new);
    let allow_all = methods.is_empty();
    let allow_prompt = allow_all || methods.contains(&"prompt");
    let allow_fragment = allow_all || methods.contains(&"fragment");

    let verbose = matches.is_present("verbose");

    Options {
        verbose,
        input,
        output,
        password,
        mime_type,
        allow_fragment,
        allow_prompt,
    }
}

fn enable_log() {
    unsafe { VERBOSE = true };
}

fn open_file<P: AsRef<Path> + fmt::Display>(path: P) -> File {
    match File::open(&path) {
        Ok(file) => file,
        Err(err) => fail!("Cannot open {}: {}", path, err),
    }
}

fn create_file<P: AsRef<Path> + fmt::Display>(path: P) -> File {
    match File::create(&path) {
        Ok(file) => file,
        Err(err) => fail!("Cannot open {}: {}", path, err),
    }
}

fn read_password<P: AsRef<Path> + fmt::Display>(path: P) -> String {
    let mut password = String::new();
    let mut file = BufReader::new(open_file(&path));
    file.read_line(&mut password)
        .unwrap_or_else(|err| fail!("Filed to read password from {}: {}", path, err));
    let password = password.trim_end_matches('\n')
                           .to_owned();
    if password.is_empty() {
        fail!("Empty password from {}", path);
    }
    password
}

fn prompt_password() -> String {
    fn prompt(prompt: &str) -> String {
        rpassword::prompt_password_stderr(prompt)
                  .unwrap_or_else(|err| fail!("Failed to read password: {}", err))
    }
    let password = prompt("Password: ");
    let repeat = prompt("Re-enter password: ");
    if password != repeat {
        fail!("Passwords don't match");
    }
    password
}

fn read_content<R: Read>(input: Option<R>) -> Vec<u8> {
    let mut buf = Vec::<u8>::new();
    let res = match input {
        Some(mut file) => file.read_to_end(&mut buf),
        None           => {
            if atty::is(atty::Stream::Stdin) {
                eprintln!("Reading from standard input");
            }
            std::io::stdin().read_to_end(&mut buf)
        },
    };
    if let Err(err) = res {
        fail!("Failed to read plaintext: {}", err);
    }
    buf
}

fn guess_mime(content: &[u8]) -> &'static str {
    tree_magic_mini::from_u8(content)
}

#[derive(Debug, Serialize)]
struct TemplateContext<'a> {
    allow_prompt: bool,
    allow_fragment: bool,
    js_loader: &'a str,
    wasm: &'a str,
    ciphertext: &'a str,
}

fn render(opts: &Options, ciphertext: &str) {
    let hb = Handlebars::new();
    let context = TemplateContext {
        allow_prompt: opts.allow_prompt,
        allow_fragment: opts.allow_fragment,
        js_loader: JS_LOADER,
        wasm: &base64::encode(WASM),
        ciphertext,
    };
    let file = opts.output.as_ref()
                          .map_or_else(|| Box::new(std::io::stdout()) as Box<dyn Write>,
                                       |file| Box::new(file) as Box<dyn Write>);
    hb.render_template_to_write(TEMPLATE, &context, file)
      .unwrap_or_else(|err| fail!("Failed to render template: {}", err))
}

fn main() {
    let opts = parse_args();
    if opts.verbose {
        enable_log();
    }

    let content = read_content(opts.input.as_ref());
    let mime_type = opts.mime_type.as_deref()
                                  .unwrap_or_else(|| guess_mime(&content));
    log!("Using MIME type: {}{}", mime_type,
         if opts.mime_type.is_some() { "" } else { " (detected)" });

    let ciphertext = crypt2web_core::encrypt(&opts.password, &content, &mime_type);
    render(&opts, &base64::encode(ciphertext));
}
