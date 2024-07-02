pub fn dec_init_obj(input: String, outp: String)  -> anyhow::Result<()>{
    let f = std::fs::read(input)?;
    let name = f.chunks(2).map(|c| c[0]).collect::<Vec<_>>();
    let n = String::from_utf8(name.to_vec())?;
    std::fs::write(outp, n)?;

    Ok(())
}