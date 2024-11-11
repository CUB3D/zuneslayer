#![feature(str_from_utf16_endian)]
extern crate core;

use std::arch::x86_64::_rdtsc;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use serde::Serialize;

#[derive(Debug)]
struct Reg {
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    pc: u32,
    lr: u32,
    sp: u32,
}
fn getregs(tcp: &mut TcpStream, t: u32) -> Reg {
    let mut c = Vec::new();
    c.push(8u8);
    c.extend_from_slice(t.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 64];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 8);

    let r0 = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    let r1 = u32::from_le_bytes(iubu[5..][..4].try_into().unwrap());
    let r2 = u32::from_le_bytes(iubu[9..][..4].try_into().unwrap());
    let r3 = u32::from_le_bytes(iubu[13..][..4].try_into().unwrap());
    let pc = u32::from_le_bytes(iubu[17..][..4].try_into().unwrap());
    let lr = u32::from_le_bytes(iubu[21..][..4].try_into().unwrap());
    let sp = u32::from_le_bytes(iubu[25..][..4].try_into().unwrap());

    Reg {
        r0,
        r1,
        r2,
        r3,
        pc,
        lr,
        sp
    }
}

fn dbgcont(tcp: &mut TcpStream, p: u32, t: u32) {
    let mut c = Vec::new();
    c.push(7u8);
    c.extend_from_slice(p.to_le_bytes().as_slice());
    c.extend_from_slice(t.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 7);
}
fn dbgwait(tcp: &mut TcpStream) -> Option<(u32, u32, u32)> {
    let mut c = Vec::new();
    c.push(6u8);
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 6);
    let ret = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    let code = u32::from_le_bytes(iubu[5..][..4].try_into().unwrap());
    let proc = u32::from_le_bytes(iubu[9..][..4].try_into().unwrap());
    let thdr = u32::from_le_bytes(iubu[13..][..4].try_into().unwrap());

    if ret == 0 {
        None
    } else {
        Some((code, proc, thdr))
    }
}

fn dbgcon(tcp: &mut TcpStream, addr: u32) -> u32 {
    let mut c = Vec::new();
    c.push(5u8);
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 5);
    let val = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    val
}

fn pwrite32(tcp: &mut TcpStream, hdl: u32, addr: u32, v: u32) {
    let mut c = Vec::new();
    c.push(4u8);
    c.extend_from_slice(hdl.to_le_bytes().as_slice());
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.extend_from_slice(v.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 4);
    let tmp = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    let e = u32::from_le_bytes(iubu[6..][..4].try_into().unwrap());
    let ret = iubu[5];
    if ret == 0 {
        panic!();
        return;
    } else {
        assert_eq!(tmp, 4);
    }
}

fn pread32(tcp: &mut TcpStream, hdl: u32, addr: u32) -> Option<u32> {
    let mut c = Vec::new();
    c.push(3u8);
    c.extend_from_slice(hdl.to_le_bytes().as_slice());
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 3);
    let tmp = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    let val = u32::from_le_bytes(iubu[5..][..4].try_into().unwrap());
    let ret = iubu[9];
    if ret == 0 {
        return None;
    } else {
        assert_eq!(val, 4);
        return Some(tmp);
    }
}

fn openproc(tcp: &mut TcpStream, addr: u32) -> u32 {
    let mut c = Vec::new();
    c.push(2u8);
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 2);
    let val = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    val
}

fn kread_u32(tcp: &mut TcpStream, addr: u32) -> u32 {
    let mut c = Vec::new();
    c.push(1u8);
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 1);
    let val = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    val
}

fn kkill(tcp: &mut TcpStream, addr: u32) {
    let mut c = Vec::new();
    c.push(12u8);
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 12);
}

fn klistfile(tcp: &mut TcpStream, addr: u32, p: u32) -> String {
    let mut c = Vec::new();
    c.push(13u8);
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.extend_from_slice(p.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 512];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 13);
    // println!("{iubu:x?}");

    let mut s = String::new();
    let mut i = &iubu[1..];
    loop {
        let c = u16::from_le_bytes(i[..2].try_into().unwrap());
        if c == 0 {
            break;
        }
        let c = char::from_u32(c as u32).unwrap();
        s.push(c);
        i = &i[2..];
    }
    s
}

fn kreadfile(tcp: &mut TcpStream, addr: u32, p: u32) -> Vec<u8> {
    let mut c = Vec::new();
    c.push(14u8);
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.extend_from_slice(p.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    const SZ: usize = 0x100000;

    let mut iubu = [0u8; SZ + 4];
    let mut o = Vec::new();
    loop {
        let c = tcp.read(&mut iubu).unwrap();
     //   println!("c = {:x}", o.len());
        o.extend_from_slice(&iubu[..c]);
        if o.len() >= iubu.len() {
            break;
        }
    }
    let sz = u32::from_le_bytes(o[..4].try_into().unwrap());
    let o = o[4..][..sz as usize].to_vec();
    if sz as usize == SZ {
        panic!("buf too smol");
    }
    // println!("{iubu:x?}");
    o
}

fn kttttt(tcp: &mut TcpStream) {
    // let addr: u32 = 0x7000_F800; // no wrk
    // let addr: u32 = 0xD000_0000; // wrk - empty
    // let addr: u32 = 0x7000_f000;

    //irom
    // let addr: u32 = 0xFFF0_0000;
    // let offset:u32 = 0x0000_0000;
    // let sz: u32    = 0x0010_0000;

    // // iram a
    // let addr: u32  = 0x4000_0000;
    // let offset:u32 = 0x0000_0000;
    // let sz: u32    = 0x0001_0000;
    //
    // // iram b
    // let addr: u32  = 0x4001_0000;
    // let offset:u32 = 0x0000_0000;
    // let sz: u32    = 0x0001_0000;

    // iram c // no
    let addr: u32  = 0x4002_0000;
    let offset:u32 = 0x0000_0000;
    let sz: u32    = 0x0001_0000;

    // // iram d
    // let addr: u32  = 0x4003_0000;
    // let offset:u32 = 0x0000_0000;
    // let sz: u32    = 0x0001_0000;

    // let addr: u32 = 0x4000_0000;

    // kfuse
    // let addr: u32  = 0x7000_0000;
    // let offset:u32 = 0x0000_fc00;

    //secure boot
    let addr: u32  = 0x6000_0000;
    let offset:u32 = 0x0000_c200;
    let sz: u32    = 0x0001_0000;

    // clk
    // let addr: u32  = 0x6000_6000;
    // let offset:u32 = 0x0000_0000;
    // let sz: u32    = 0x0001_0000;

    // ram
    // let addr: u32  = 0x8000_0000;
    // let offset:u32 = 0x0000_0000;
    // let sz: u32    = 0x0020_0000;

    // nor
    // let addr: u32  = 0xd000_0000;
    // let offset:u32 = 0x0000_0000;
    // let sz: u32    = 0x0001_0000;

    // so far: can't change secboot or clk????, maybe we are dealing with a copy not a real phy mapping?


    let mut c = Vec::new();
    c.push(15u8);
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.extend_from_slice(offset.to_le_bytes().as_slice());
   c.extend_from_slice(sz.to_le_bytes().as_slice());


    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 1];
    let mut o = Vec::new();
    loop {
        let c = tcp.read(&mut iubu).unwrap();
       if o.len() % 0x100 == 0 {
            println!("c = {:x}", o.len());
       }
        o.extend_from_slice(&iubu[..c]);

        std::fs::write("./test.bin", &o).unwrap();

        if o.len() == sz as usize-1 {
            break;
        }
    }
}

fn kquit(tcp: &mut TcpStream) {
    let mut c = Vec::new();
    c.push(11u8);
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    // let mut iubu = [0u8; 32];
    // tcp.read(&mut iubu).unwrap();
    // assert_eq!(iubu[0], 1);
    // let val = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    // val
}

fn kread_u16(tcp: &mut TcpStream, addr: u32) -> u16 {
    (kread_u32(tcp, addr) & 0xFFFF) as u16
}

#[derive(Debug, Serialize)]
struct Proc {
    next: u32,
    last: u32,
    id: u32,
    thread_next: u32,
    thread_last: u32,
    name: String,
    base: u32,

    mods: Vec<Module>,
    thrds: Vec<Thread>,
}

#[derive(Debug, Serialize)]
struct Thread {
    next: u32,
    base: u32,
}
fn preadstr(tcp: &mut TcpStream, p: u32, addr: u32) -> String {
    let mut name = Vec::new();
    let mut off = 2;
    let mut c = (pread32(tcp, p, addr).unwrap() & 0xFF) as u16;
    while (c != 0) {
        name.push(c);
        c = (pread32(tcp, p, addr + off).unwrap() & 0xFF) as u16;
        off += 2;
    }
    let name = String::from_utf16(&name).unwrap();

    name
}

fn kreadstr(tcp: &mut TcpStream, addr: u32) -> String {
    let mut name = Vec::new();
    let mut off = 2;
    let mut c = kread_u16(tcp, addr);
    while (c != 0) {
        name.push(c);
        c = kread_u16(tcp, addr + off);
        off += 2;
    }
    let name = String::from_utf16(&name).unwrap();

    name
}

#[derive(Debug, Serialize)]
struct Module {
    next: u32,
    name: String,
}

fn read_module(tcp: &mut TcpStream, mod_ptr: u32) -> Module {
    let next = kread_u32(tcp, mod_ptr+0x0);
    let oe = mod_ptr+0x84;
    let pfn = mod_ptr+0x80;
    let zone = mod_ptr+0x7c;
    let zone2 = mod_ptr+0x78;
    let dbg = mod_ptr+0x74;
    let nname2 = kread_u32(tcp, mod_ptr+0x70);
    let name = kreadstr(tcp, nname2);
    // println!("{n}");

    // let oe_lpname = kread_u32(tcp, oe+0xc);
    // let toc = kread_u32(tcp, oe+0x0);
    // let mut name = "".to_string();
    // if oe_lpname != 0 {
    //     name = kreadstr(tcp, oe_lpname);
    // } else {
    //     let toc_Addr = kread_u32(tcp, toc+0x10);
    //     name = kreadstr(tcp, toc_Addr);
    // }
    // println!("mod = {mod_next:x}, mod2={mod_ptr:x}, oe={oe:x}, tocptr={toc:x}, name={oe_lpname:x}, oe_name={name}");

    Module{
        next,
        name
    }
}

fn read_thrd(tcp: &mut TcpStream, mod_ptr: u32) -> Thread {
    let next = kread_u32(tcp, mod_ptr+0x0);
    let base = kread_u32(tcp, mod_ptr+0x20);
    // let oe = mod_ptr+0x84;
    // let pfn = mod_ptr+0x80;
    // let zone = mod_ptr+0x7c;
    // let zone2 = mod_ptr+0x78;
    // let dbg = mod_ptr+0x74;
    // let nname2 = kread_u32(tcp, mod_ptr+0x70);
    // let name = kreadstr(tcp, nname2);
    // println!("{n}");

    // let oe_lpname = kread_u32(tcp, oe+0xc);
    // let toc = kread_u32(tcp, oe+0x0);
    // let mut name = "".to_string();
    // if oe_lpname != 0 {
    //     name = kreadstr(tcp, oe_lpname);
    // } else {
    //     let toc_Addr = kread_u32(tcp, toc+0x10);
    //     name = kreadstr(tcp, toc_Addr);
    // }
    // println!("mod = {mod_next:x}, mod2={mod_ptr:x}, oe={oe:x}, tocptr={toc:x}, name={oe_lpname:x}, oe_name={name}");

    Thread{
        next,
        base,
    }
}


fn read_proc(tcp: &mut TcpStream, proc: u32) -> Proc {
    let next = kread_u32(tcp, proc);
    let last = kread_u32(tcp, proc+4);
    let id = kread_u32(tcp, proc+0xc);
    let thread_next = kread_u32(tcp, proc+0x10);
    let thread_last = kread_u32(tcp, proc+0x14);
    let base = kread_u32(tcp, proc+0x18);
    let name_ptr = kread_u32(tcp, proc+0x20);
    let name = kreadstr(tcp, name_ptr);


    let mut thrds = Vec::new();
    let mut cur_thrd_ptr = thread_next;
loop {
    let m = read_thrd(tcp, cur_thrd_ptr);
    // println!("{m:?}");
    cur_thrd_ptr = m.next;
    thrds.push(m);
    if cur_thrd_ptr == thread_next {
        break;
    }
}

   let mod_next = kread_u32(tcp, proc+0x108); // _MODULELIST
   let mod_ptr = kread_u32(tcp, mod_next+8); // _MODULE




    let mut mods = Vec::new();

    let mut cur_mod_ptr = mod_ptr;
    loop {
        let m = read_module(tcp, cur_mod_ptr);
        println!("{m:?}");
        cur_mod_ptr = m.next;
        mods.push(m);
        if cur_mod_ptr == mod_ptr {
            break;
        }
    }




    Proc {
        next,
        last,
        id,
        name,
        thread_next,
        thread_last,
        thrds,
        base,
        mods,
    }
}

fn wait_for_proc(tcp: &mut TcpStream, proc: u32, n: &String) -> (u32, u32) {
    let mut nk = proc;
    loop {
        let next = kread_u32(tcp, nk);

        let name_ptr = kread_u32(tcp, nk + 0x20);
        let name = kreadstr(tcp, name_ptr);
        if name.contains(n) {
            let id = kread_u32(tcp, nk+0xc);
            return (nk, id);
        }
        nk = next;
    }
}

fn main() {
    let mut tcp = TcpStream::connect(("192.168.1.20", 1337)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    tcp.set_nodelay(true).unwrap();

    let mut iubu = [0u8; 8];
    tcp.read(&mut iubu).unwrap();
    println!("{:?}", String::from_utf8(iubu.to_vec()));

    let nk = kread_u32(&mut tcp, 0x80bee010);
    println!("{nk:x}");

    kttttt(&mut tcp);
    return;;

    if false {
        let mut procs = Vec::new();

        let mut proc_addr = nk;
        loop {
            let proc = read_proc(&mut tcp, proc_addr);
            println!("{proc:?}");
            proc_addr = proc.next;
            procs.push(proc);
            if proc_addr == nk {
                break;
            }
        }

        let o = serde_json::to_string_pretty(&procs).unwrap();
        std::fs::write("out.json", &o).unwrap();
    }

    // kquit(&mut tcp);


    let pa = [
        "out/",
        "out/Content",
        "out/Content/Audio",
        "out/Content/Images",
        "out/Content/Sounds",
        "out/Content/Text",
        "out/Content/Text/Strings",
        "out/Content/Fonts",
        "out/Content/UI",
        "out/Content/UI/ContactDetails",
        "out/Content/UI/ContactEditors",
        "out/Content/UI/SetupWizard",
        "out/Content/ZuneAppLib",
        "out/Content/Models",
        "out/Content/Pictures",
        "out/Content/Shaders",

    ];
    for p in 0..pa.len() {
        let pp = pa[p];
        for i in 0..100 {
            let s = klistfile(&mut tcp, i, p as u32);
            if s.contains("r: 0") {
                break;
            }
            // println!("{s}");
            let name = s[5..].split(" ").next().unwrap().to_string();
            println!("{pp}/{name}");
            if pa.iter().any(|x| x.contains(&format!("/{name}").as_str())) {
                // println!("skp");
                continue;
            }
            let d = kreadfile(&mut tcp, i, p as u32);
            let _ = std::fs::create_dir_all(pp);
            std::fs::write(&format!("{pp}/{name}"), &d).unwrap();
        }
    }

    // let gs = procs.iter().find(|p| p.name.contains("ZIE")).unwrap();
    // kkill(&mut tcp, gs.id);
    //
    // kquit(&mut tcp);
    // return;

return;

    /*

    if false {


        // let gs = procs.iter().find(|p| p.name.contains("compositor")).unwrap();
        // let (gs, id) = wait_for_proc(&mut tcp, nk, &"gemstone".to_string());
        let (gs, id) = wait_for_proc(&mut tcp, nk, &"ZIE".to_string());


        // let gs = procs.iter().find(|p| p.name.contains("ZIE")).unwrap();
        let pr = openproc(&mut tcp, id);
        let k = dbgcon(&mut tcp, id);
        if k == 0{
            kquit(&mut tcp);
            return;
        }
        println!("d = {k}");

        let bp = [
            // (0x4036dc44, 0xe1a02000, 0xe0d230b2, "wcslen", Box::new(|r: &Reg, tcp: &mut TcpStream, pr: u32| {
            //     let r0 = preadstr(tcp, pr, r.r0);
            //     println!("wsclen({r0}, {r:x?})");
            // }))

                (0x40342d48, 0xe92d4070, 0xe24dd014, "commodem", Box::new(|r: &Reg, tcp: &mut TcpStream, pr: u32| {
                panic!("WTF({r:x?})");
            }))

        ];

        loop {
            if let Some((evt, p, t)) = dbgwait(&mut tcp) {

                match evt {
                    // create proc
                    3 => {
                        // pwrite32(&mut tcp, pr, 0x40336b64, 0xe7f001f0); // file
                        // pwrite32(&mut tcp, pr, 0x403378e8, 0xe7f001f0); //regkey
                        //pwrite32(&mut tcp, pr, 0x4033773c, 0xe7f001f0); //regcreate
                        for p in &bp {
                            pwrite32(&mut tcp, pr, p.0, 0xe7f001f0);
                        }

                         pwrite32(&mut tcp, pr, 0x40eeaf14, 0xe7f001f0); // jscript!typeof_call
                         pwrite32(&mut tcp, pr, 0x4035a514, 0xe7f001f0); // core!all_args_gadget
                         pwrite32(&mut tcp, pr, 0x40332b88, 0xe7f001f0); // core!virtual_prot
                         pwrite32(&mut tcp, pr, 0x40332bb4, 0xe7f001f0); // core!virtual_prot[ret]
                         pwrite32(&mut tcp, pr, 0x40331c14, 0xe7f001f0); // core!create_proc_w
                    }
                    //exit thread
                    4 => {}
                    //bkpt / exception
                    1 => {
                        let r = getregs(&mut tcp, t);

                        if r.pc == 0x40336b64 { // open file
                            let s = preadstr(&mut tcp, pr, r.r0);
                            println!("CreateFileW({s}, {r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe92d4070);
                            // add bk on pc+4#
                            pwrite32(&mut tcp, pr, r.pc + 4, 0xe7f001f0);
                        } else if r.pc == 0x40336b64 + 4{
                            println!("cfw 2");
                            // rm bk pc +4
                            pwrite32(&mut tcp, pr, r.pc, 0xe24dd00c);
                            // add bkpt1 back
                            pwrite32(&mut tcp, pr, r.pc-4, 0xe7f001f0);
                        } else if r.pc == 0x403378e8 { // reg open
                            let s = preadstr(&mut tcp, pr, r.r1);
                            println!("RegOpenKeyEx({s}, {r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe92d4010);
                            // add bk on pc+4#
                            pwrite32(&mut tcp, pr, r.pc + 4, 0xe7f001f0);
                        } else if r.pc == 0x403378e8+4 {
                            // rm bk pc +4
                            pwrite32(&mut tcp, pr, r.pc, 0xe24dd004);
                            // add bkpt1 back
                            pwrite32(&mut tcp, pr, r.pc - 4, 0xe7f001f0);
                        } else if r.pc == 0x4033773c { // reg open
                            let s = preadstr(&mut tcp, pr, r.r1);
                            println!("RegCreateKeyExW({s}, {r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe92d41f0);
                            // add bk on pc+4#
                            pwrite32(&mut tcp, pr, r.pc + 4, 0xe7f001f0);
                        } else if r.pc == 0x4033773c+4 {
                            // rm bk pc +4
                            pwrite32(&mut tcp, pr, r.pc, 0xe24dd014);
                            // add bkpt1 back
                            pwrite32(&mut tcp, pr, r.pc-4, 0xe7f001f0);
                        } else if r.pc == 0x40332bb4 {
                            println!("VirtualProtect[ret]({r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe12fff1e);
                        //NOTE: not put back because its a LR
                        } else if r.pc == 0x40331c14 {
                            println!("CreateProcW({r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe92d41f0);
                        //NOTE: not put back because its a LR


                        } else if r.pc == 0x40332b88 {
                            println!("VirtualProtect({r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe52de004);
                            // add bk on pc+4#
                            pwrite32(&mut tcp, pr, r.pc + 4, 0xe7f001f0);
                        } else if r.pc == 0x40332b88 + 4 {
                            // rm bk pc +4
                            pwrite32(&mut tcp, pr, r.pc, 0xe24dd004);
                            // add bkpt1 back
                            pwrite32(&mut tcp, pr, r.pc - 4, 0xe7f001f0);
                        } else if r.pc == 0x4035a514 { // gadget
                            println!("magic_gadget({r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe1a0d000);
                            // add bk on pc+4#
                            pwrite32(&mut tcp, pr, r.pc + 4, 0xe7f001f0);
                        } else if r.pc == 0x4035a514 + 4 {
                            // rm bk pc +4
                            pwrite32(&mut tcp, pr, r.pc, 0xe99dffff);
                            // add bkpt1 back
                            pwrite32(&mut tcp, pr, r.pc - 4, 0xe7f001f0);
                        } else if r.pc == 0x40eeaf14 { // reg open
                            println!("typeof({r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe12fff13);
                            // add bk on pc+4#
                            pwrite32(&mut tcp, pr, r.pc + 4, 0xe7f001f0);
                        } else if r.pc == 0x40eeaf14 + 4 {
                            // rm bk pc +4
                            pwrite32(&mut tcp, pr, r.pc, 0xe3500000);
                            // add bkpt1 back
                            pwrite32(&mut tcp, pr, r.pc - 4, 0xe7f001f0);
                        } else {
                            let mut h = false;

                            for p in &bp {
                                if r.pc == p.0 {
                                    (p.4)(&r, &mut tcp, pr);

                                    // rm bk
                                    pwrite32(&mut tcp, pr, r.pc, p.1);
                                    // add bk on pc+4#
                                    pwrite32(&mut tcp, pr, r.pc + 4, 0xe7f001f0);
                                    h = true;
                                    break;
                                } else if r.pc == p.0+4 {
                                    // rm bk pc +4
                                    pwrite32(&mut tcp, pr, r.pc, p.2);
                                    // add bkpt1 back
                                    pwrite32(&mut tcp, pr, r.pc - 4, 0xe7f001f0);
                                    h = true;
                                    break;
                                }
                            }

                            if !h {
                                println!("BR not here @ {:x?}", r);
                            }
                        }
                    }
                    // load dll
                    6 => {
                    }
                    _ => {
                        println!("unk evt {evt:x} {p:x} {t:x}");
                    }
                }
                println!("[{}] dbg: {evt:x} {p:x} {t:x}", unsafe { _rdtsc()});
                dbgcont(&mut tcp, p, t);

            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    // let gs = procs.iter().find(|p| p.name.contains("gemstone")).unwrap();
    let gs = procs.iter().find(|p| p.name.contains("ZIE")).unwrap();

    let k = openproc(&mut tcp, gs.id);
    println!("k = {k:x}");

    if true {
        let mut ok = Vec::new();
        let mut start = 0;
        let mut base = 0;
        for _ in 0..2000 {
            if pread32(&mut tcp, k, base).is_none() {
                if base != start + 0x1000 && start != 0 {
                    ok.push((start, base - 0x1000));
                    start = 0;
                }
            } else {
                if start == 0 {
                    start = base;
                }
            }

            base += 0x1000;
        }
        println!("ok = {:x?}", ok);
        std::fs::write("./mem.json", serde_json::to_string_pretty(&ok).unwrap()).unwrap();


        let mut cpy = Vec::new();
        for (base, end) in ok.iter() {
            cpy.clear();
            // let base: u32 = 0xa0000;
            // let end = 0xbd000;
            let l = (end - base) / 4;
            println!("Fetching {base:x} - {end:x}: {}", l);
            let bar = progression::Bar::new(l as _, progression::Config::cargo());
            for off in 0..l {
                if let Some(k) = pread32(&mut tcp, k, base + off * 4) {
                    cpy.extend_from_slice(k.to_le_bytes().as_slice());
                } else {
                    println!("rd fail @ {:x}", base + off * 4);
                }
                bar.inc(1);
            }
            std::fs::write(&format!("./gem-{base:x}-{end:x}.bin"), &cpy).unwrap();
        }
    }

    if false {
        let mut cpy = Vec::new();
        let base = 0x140000;
        let l = 0xe000/4;
        for off in 0..l {
            if let Some(k) = pread32(&mut tcp, k, base + off*4) {
                cpy.extend_from_slice(k.to_le_bytes().as_slice());
            } else {
                println!("rd fail @ {:x}", base + off * 4);
            }
        }

        let needl = "Bootloader".encode_utf16().flat_map(|b| b.to_le_bytes()).collect::<Vec<_>>();
        if let Some(pos) = cpy.windows(needl.len()).position(|w| w == &needl) {
            println!("Boot @ {:x}", base as usize + pos);

            pwrite32(&mut tcp, k, base + pos as u32, 0x41004100);
        }
    }
*/

}

