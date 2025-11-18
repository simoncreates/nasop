use std::collections::HashMap;

use capstone::{
    Capstone, InsnGroupId, RegId,
    arch::{self, ArchDetail, BuildsCapstone, x86::X86OperandType},
};
use serde::{Deserialize, Serialize};

use crate::data_representation::x86_register::X86Register;

pub type InstructionId = i32;
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

fn reg_names(regs: &[RegId]) -> String {
    println!("current regs: {:?}", regs);
    regs.iter()
        .map(|&rid| {
            let internal_name = X86Register::try_from(rid).unwrap();
            internal_name.to_string()
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn group_names(cs: &Capstone, groups: &[InsnGroupId]) -> String {
    groups
        .iter()
        .map(|&gid| cs.group_name(gid).unwrap_or("<unknown>".into()))
        .collect::<Vec<_>>()
        .join(", ")
}

impl InsDB {
    pub fn analyze_bin_at_addr(&mut self, bin: &[u8], addr: u64) {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");

        let insns = cs.disasm_all(bin, addr).expect("Disassemble failed");
        println!("Found {} instructions", insns.len());

        for insn in insns.iter() {
            println!("\n{}", insn);

            let detail = cs.insn_detail(insn).expect("Failed to get detail");
            let arch_detail: ArchDetail = detail.arch_detail();
            let ops = arch_detail.operands();

            println!("    insn id:     {:?}", insn.id().0);
            println!("    bytes:       {:?}", insn.bytes());
            println!("    read regs:   {}", reg_names(detail.regs_read()));
            println!("    write regs:  {}", reg_names(detail.regs_write()));
            println!("    groups:      {}", group_names(&cs, detail.groups()));

            println!("    operands:    {}", ops.len());

            let mut read_regs = detail.regs_read().to_vec();
            let mut write_regs = detail.regs_write().to_vec();

            for op in ops {
                if let arch::ArchOperand::X86Operand(x86_op) = op
                    && let X86OperandType::Reg(r) = x86_op.op_type
                {
                    match x86_op.access.unwrap_or(capstone::RegAccessType::ReadOnly) {
                        capstone::RegAccessType::ReadOnly => read_regs.push(RegId(r.0)),
                        capstone::RegAccessType::WriteOnly => write_regs.push(RegId(r.0)),
                        capstone::RegAccessType::ReadWrite => {
                            read_regs.push(RegId(r.0));
                            write_regs.push(RegId(r.0));
                        }
                    }
                }
            }
        }
    }
}
