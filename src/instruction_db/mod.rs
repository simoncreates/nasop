use std::collections::HashMap;

use capstone::{
    Capstone, InsnDetail, InsnGroupId, RegId,
    arch::{self, ArchDetail, BuildsCapstone, BuildsCapstoneSyntax},
};
use serde::{Deserialize, Serialize};

pub type InstructionId = i32;
/// Register Id according to Unicorn Engine
pub type RegisterIdX86 = i32;

#[derive(Serialize, Deserialize)]
pub struct InstructionInfo {
    pub mnemonic: String,
    pub registers_read: Vec<RegisterIdX86>,
    pub registers_written: Vec<RegisterIdX86>,
    pub flags_read: Vec<u16>,
    pub flags_written: Vec<u16>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct InsDB {
    pub instructions: HashMap<InstructionId, InstructionInfo>,
}
/// Print register names
fn reg_names(cs: &Capstone, regs: &[RegId]) -> String {
    let names: Vec<String> = regs.iter().map(|&x| cs.reg_name(x).unwrap()).collect();
    names.join(", ")
}

/// Print instruction group names
fn group_names(cs: &Capstone, regs: &[InsnGroupId]) -> String {
    let names: Vec<String> = regs.iter().map(|&x| cs.group_name(x).unwrap()).collect();
    names.join(", ")
}

impl InsDB {
    pub fn analyze_bin_at_addr(&mut self, bin: &[u8], addr: u64) {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Att)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");

        let insns = cs.disasm_all(bin, addr).expect("Failed to disassemble");
        println!("Found {} instructions", insns.len());
        for i in insns.as_ref() {
            println!();
            println!("{}", i);

            let detail: InsnDetail = cs.insn_detail(i).expect("Failed to get insn detail");
            let arch_detail: ArchDetail = detail.arch_detail();
            let ops = arch_detail.operands();

            let output: &[(&str, String)] = &[
                ("insn id:", format!("{:?}", i.id().0)),
                ("bytes:", format!("{:?}", i.bytes())),
                ("read regs:", reg_names(&cs, detail.regs_read())),
                ("write regs:", reg_names(&cs, detail.regs_write())),
                ("insn groups:", group_names(&cs, detail.groups())),
            ];

            for (name, message) in output.iter() {
                println!("{:4}{:12} {}", "", name, message);
            }

            println!("{:4}operands: {}", "", ops.len());
            for op in ops {
                println!("{:8}{:?}", "", op);
            }
        }
    }
}
