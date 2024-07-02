use anyhow::anyhow;

pub fn dec_wlan(input: String, outp: String) -> anyhow::Result<()>{
    let f = std::fs::read(input)?;

    let mut out = Vec::new();

    let mut itr = f.iter().copied().skip(7).peekable();

    out.extend_from_slice(&[0x9f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

    while let Some(b) = itr.next() {
        if b == 0x9f {
            // sz = 0, lit
            if *itr.peek().ok_or(anyhow!("Invalid file"))? == 0 {
                itr.next().ok_or(anyhow!("Invalid file"))?;
                out.push(0x9f);
                continue;
            }

            let len = {
                let mut out = 0usize;
                loop {
                    let b = itr.next().ok_or(anyhow!("Invalid file"))? as usize;
                    out = (out << 7) | (b & 0x7f);

                    if (b & 0x80) == 0 {
                        break
                    }
                }

                out
            };

            let off = {
                let mut out = 0usize;
                loop {
                    let b = itr.next().ok_or(anyhow!("Invalid file"))? as usize;
                    out = (out << 7) | (b & 0x7f);

                    if (b & 0x80) == 0 {
                        break
                    }
                }

                out
            };

            if out.len() < off {
                panic!("bad len = {len}, off={off} l={}", out.len());

            } else {
                tracing::trace!("len = {len}, off={off} l={}", out.len());
                let b = out[out.len() - off as usize..][..len as usize].to_vec();
                out.extend_from_slice(&b);
            }
        } else {
            out.push(b);
        }
        std::fs::write("./dec.bin", &out).unwrap();
    }

    std::fs::write(outp, &out)?;

    Ok(())
}