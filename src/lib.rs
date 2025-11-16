pub mod exmaple_analysis;
pub mod instruction_db;
pub mod tools;

use std::fs;
use std::process::Command;

pub fn assemble_nasm(asm_path: &str, bin_path: &str, src: &str) {
    fs::write(asm_path, src).expect("write asm");
    let out = Command::new("nasm")
        .args(["-f", "bin", asm_path, "-o", bin_path])
        .output()
        .expect("failed to run nasm");
    assert!(out.status.success(), "nasm failed: {:?}", out);
}

#[test]
fn test_uc_init() {
    use unicorn_engine::{Arch, Mode, Unicorn};
    let _uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
}

#[test]
fn test_nasm_unicorn_registers_step() {
    use capstone::arch::x86::{ArchMode, ArchSyntax};
    use capstone::prelude::*;
    use unicorn_engine::{Arch, Mode, Prot, RegisterX86, Unicorn};
    let asm = r#"
        bits 64
        mov rax, 42
        mov rbx, 7
        add rax, rbx
        int3
    "#;

    let asm_file = "temp.asm";
    let bin_file = "temp.bin";
    assemble_nasm(asm_file, bin_file, asm);

    let code = fs::read(bin_file).expect("read bin");

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).expect("create unicorn");

    const CODE_ADDR: u64 = 0x1000;
    const CODE_SIZE: u64 = 0x10_000;
    const STACK_ADDR: u64 = 0x20000;
    const STACK_SIZE: u64 = 0x10_000;

    uc.mem_map(CODE_ADDR, CODE_SIZE, Prot::ALL)
        .expect("map code");
    uc.mem_map(STACK_ADDR, STACK_SIZE, Prot::ALL)
        .expect("map stack");

    uc.reg_write(RegisterX86::RSP, STACK_ADDR + STACK_SIZE)
        .expect("set rsp");
    uc.mem_write(CODE_ADDR, &code).expect("mem_write code");
    uc.reg_write(RegisterX86::RIP, CODE_ADDR).expect("set rip");

    // Hook every instruction: print address, first few bytes, and registers
    uc.add_code_hook(
        CODE_ADDR,
        CODE_ADDR + code.len() as u64,
        |uc, addr: u64, size: u32| {
            // read up to 8 bytes of the current instruction for display
            let mut buf = vec![0u8; 8];
            let _ = uc.mem_read(addr, &mut buf);

            let cs: Capstone = Capstone::new()
                .x86()
                .mode(ArchMode::Mode64)
                .syntax(ArchSyntax::Intel)
                .build()
                .expect("failed to create capstone");

            let mut disasm_result: String = String::new();
            match cs.disasm_count(&buf, addr, 1) {
                Ok(insns) => {
                    for i in insns.iter() {
                        disasm_result.push_str(&format!(
                            "0x{:x}: {:<12} {}",
                            i.address(),
                            i.mnemonic().unwrap_or(""),
                            i.op_str().unwrap_or("")
                        ));
                    }
                }
                Err(e) => {
                    println!("disasm error: {:?}", e);
                }
            }

            let rax = uc.reg_read(RegisterX86::RAX).unwrap_or_default();
            let rbx = uc.reg_read(RegisterX86::RBX).unwrap_or_default();

            print!("{}", disasm_result);
            for _ in 0..40 - disasm_result.len() {
                print!(" ");
            }
            println!(" -> RAX = {}, RBX = {}", rax, rbx);

            let mut b = [0u8];
            if uc.mem_read(addr, &mut b).is_ok() && b[0] == 0xCC {
                println!("Hit int3 at 0x{:x} in hook; stopping emulator.", addr);
                let _ = uc.emu_stop();
            }
        },
    )
    .expect("add_code_hook");

    let run_result = uc.emu_start(CODE_ADDR, CODE_ADDR + code.len() as u64, 0, 1_000_000);

    match run_result {
        Ok(_) => {}
        Err(e) => {
            let s = format!("{:?}", e).to_lowercase();
            // common, but expect errors
            if s.contains("int3")
                || s.contains("breakpoint")
                || s.contains("interrupt")
                || s.contains("exception")
            {
                println!(
                    "emu_start stopped with expected breakpoint/exception: {:?}",
                    e
                );
            } else {
                panic!("emu_start failed unexpectedly: {:?}", e);
            }
        }
    }

    let rax_final = uc.reg_read(RegisterX86::RAX).expect("read rax final");
    let rbx_final = uc.reg_read(RegisterX86::RBX).expect("read rbx final");
    assert_eq!(rax_final, 49u64);
    assert_eq!(rbx_final, 7u64);

    let _ = fs::remove_file(asm_file);
    let _ = fs::remove_file(bin_file);
}
