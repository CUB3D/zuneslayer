use anyhow::anyhow;
use tracing::info;
use parse::{le_u16, le_u32, take_n};

pub fn dec_fdf(input: String, outp: String) -> anyhow::Result<()> {
    let f = std::fs::read(input)?;

    let (i, sig) = le_u32(&f);
    let (i, len) = le_u32(i);

    info!("sig = {sig:x}");
    info!("dx = {len:x}");

    let mut outs = String::new();

    //https://nah6.com/~itsme/cvs-xdadevtools/romtools/fdf2reg.pl

    let mut i = i;
    while !i.is_empty() {
        let (j, ent_sz) = le_u16(i);
        let (j, ent_type) = le_u16(j);
        //println!("es = {ent_sz:x}, et = {ent_type:x}");

        let (j, ent_body) = take_n(j, ent_sz as usize);
        i = j;

        match ent_type {
            1 => {
                let h_names = ["HKEY_CLASSES_ROOT", "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "HKEY_USER"];
                let (k, hive) = le_u16(ent_body);
                let (k, pathln) = le_u16(k);
                // let (k, zero) = le_u16(k);
                let (k, path) = take_n(k, pathln as usize * 2);

                assert!(k.is_empty());

                let mut path_sane = path.chunks(2).map(|a| a[0]).collect::<Vec<u8>>();
                path_sane.pop();

                outs.push_str(&format!("path = {}:{:?}\n", h_names[hive as usize], String::from_utf8(path_sane)?));
            }
            2 => {
                let (k, valtype) = le_u16(ent_body);
                let (k, keysize) = le_u16(k);
                let (k, valsiz) = le_u16(k);
                let (k, key) = take_n(k, keysize as usize * 2 );
                let (_k, val) = take_n(k, valsiz as usize);

                let mut path_sane = key.chunks(2).map(|a| a[0]).collect::<Vec<u8>>();
                path_sane.pop();
                let key_str = String::from_utf8(path_sane)?;

                outs.push_str(&format!("    key = {:?}\n", key_str));

                match valtype {
                    1 => {
                        let mut path_sane = val.chunks(2).map(|a| a[0]).collect::<Vec<u8>>();
                        path_sane.pop();

                        outs.push_str(&format!("    val = {:?}\n", String::from_utf8(path_sane)?));
                    }
                    2 => {
                        outs.push_str("    val = empty\n");
                    }
                    3 => {
                        outs.push_str(&format!("    val = {:x?}\n", val));
                    }

                    // dword
                    4 => {
                        let d = u32::from_le_bytes(val.try_into()?);

                        let desc = if key_str == "Flags" {
                            let mut out = String::new();
                            if d & 0x10 != 0 {
                                out.push_str("DEVFLAGS_LOAD_AS_USERPROC |")
                            }
                            if d & 0x1 != 0 {
                                out.push_str("DEVFLAGS_UNLOAD |")
                            }
                            if d & 0x2 != 0 {
                                out.push_str("DEVFLAGS_LOADLIBRARY |")
                            }
                            if d & 0x4 != 0 {
                                out.push_str("DEVFLAGS_NOLOAD |")
                            }
                            if d & 0x8 != 0 {
                                out.push_str("DEVFLAGS_NAKEDENTRIES |")
                            }
                            if d & 0x1000 != 0 {
                                out.push_str("DEVFLAGS_BOOTPHASE_1 |")
                            }
                            out
                        } else {
                            "".to_string()
                        };

                        outs.push_str(&format!("    val = 0x{:x} ({})\n", d, desc));
                    }
                    7 => {
                        let str = String::from_utf16le(&val[..val.len()-4]);
                        let ext = if let Ok(s) = str {
                            format!("({})", s)
                        } else {
                            "".to_string()
                        };
                        outs.push_str(&format!("    val = wbinary, {:x?} {}\n", val, ext));
                    }
                    21 => {
                        outs.push_str(&format!("    val = unk, {:x?}\n", val));
                    }
                    _ => return Err(anyhow!("    typ == {valtype}")),
                }
            }
            _ => return Err(anyhow!("Unk ent ty {ent_type}")),
        }
    }

    std::fs::write(outp, &outs)?;

    Ok(())
}