#![feature(str_from_utf16_endian)]
//! DEcompress (windows) CE images

pub mod wlan;
pub mod init_obj;
pub mod fdf;

use std::{io::{Cursor, Read}, path::PathBuf, process::Command};
use anyhow::anyhow;
use clap::{Parser, Subcommand};
use tracing::{Level};
use parse::{le_u32, take, take_n};

pub fn dec_cab(input: String, outp: String) -> anyhow::Result<()> {
    let outdir = PathBuf::from(outp);

    let _ = std::fs::create_dir(&outdir);

    let f = std::fs::read(input)?;

    let mut cabinet = cab::Cabinet::new(Cursor::new(&f[..]))?;
    let mut n = Vec::new();
    // List all files in the cabinet, with file sizes and compression types:
    for folder in cabinet.folder_entries() {
        for file in folder.file_entries() {
            n.push(file.name().to_string());
        }
    }

    for f in n {
        let mut d = cabinet.read_file(&f)?;
        let mut v = Vec::new();
        d.read_to_end(&mut v)?;


        std::fs::write(outdir.join(f.clone()), &v)?;

        if let Ok(out) = dec_b000f(&v) {
            std::fs::write(outdir.join(format!("{}.decomp", f)), &out)?;


            let h = Command::new("wine")
                .arg(".\\dece\\eimgfs\\eimgfs.exe")
                .arg("-extractall")
                .arg("-v")
                .arg(outdir.join(format!("{}.decomp", f))).spawn()?;
            h.wait_with_output()?;

            let _ = std::fs::rename("xip", outdir.join(format!("{}_xip", f)));
        }
    }

    Ok(())
}



fn dec_b000f(v: &[u8]) -> anyhow::Result<Vec<u8>> {
    let (i, _sig) = take::<7>(v);
    if _sig != [0x42, 0x30, 0x30, 0x30, 0x46, 0x46, 0xa] {
        return Err(anyhow!("Bad file sig"));
    }
    let (i, start) = le_u32(i);
    let (i, len) = le_u32(i);

    println!("[*] start = {start:x}, len = {len:x}, sig={_sig:x?}");

    let mut out = vec![0u8; len as usize];

    let mut i = i;
    loop {
        let (j, addr) = le_u32(i);
        let (j, sz) = le_u32(j);
        let (j, crc) = le_u32(j);

        println!("[*] addr = {addr:x}, sz = {sz:x}, crc = {crc:x}");

        if addr == 0 && crc == 0 {
            break;
        }

        let (j, dat) = take_n(j, sz as usize);

        // let name_end = dat.iter().position(|x| *x == 0).unwrap_or(1);
        // let name = &dat[..name_end];
        // if let Ok(name) = String::from_utf8(name.to_vec()) {
        //     println!("{name}");
        // }


        out[addr as usize - start as usize..][..sz as usize].copy_from_slice(dat);

        i = j;
    }

    Ok(out)
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Input file
    #[arg(short, long)]
    input: String,

    /// Output file
    #[arg(short, long)]
    out: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Decompress Zune HD (athwlan2_0.bin.z77) wlan firmware
    DecompressWlan {},

    /// Decompress initobj.dat
    DecompressInitObj {},

    /// Decompress default.fdf
    DecompressDefaultFdf {},

    /// Decompress update cab file
    DecompressCab {},

    DecB00F {
        p: PathBuf
    }
}

fn main() -> anyhow::Result<()>{
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    let a = Args::parse();

    match a.cmd {
        Cmd::DecompressWlan { .. } => {
            wlan::dec_wlan(a.input, a.out)?;
        }
        Cmd::DecompressInitObj { .. } => {
            init_obj::dec_init_obj(a.input, a.out)?;
        }
        Cmd::DecompressDefaultFdf { .. } => {
            fdf::dec_fdf(a.input, a.out)?;
        }
        Cmd::DecompressCab { .. } => {
            dec_cab(a.input, a.out)?;
        }
        Cmd::DecB00F { p } => {
            let x = dec_b000f(&std::fs::read(p)?)?;
            std::fs::write("xip", x.as_slice())?;
        }
    }

    Ok(())
}
