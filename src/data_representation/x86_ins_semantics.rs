use std::str::FromStr;

use capstone::Capstone;

use crate::data_representation::{x86_ins::X86Instruction, x86_reg::X86Register};

#[derive(Debug, Clone, Copy)]
pub enum AccessType {
    Read,
    Write,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandRole {
    DEST,
    SRC1,
    SRC2,
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryAccess {
    pub read: bool,
    pub write: bool,
    pub size_bytes: u8,
}

// todo: implement OperandAcess into InstructionSemantics
#[derive(Debug, Clone, Copy)]
pub struct OperandAccess {
    pub role: OperandRole,
    pub size_bits: u8,
    pub mem: Option<MemoryAccess>,
}

impl OperandAccess {
    pub const DEST: OperandAccess = OperandAccess {
        role: OperandRole::DEST,
        size_bits: 0,
        mem: None,
    };
    pub const SRC1: OperandAccess = OperandAccess {
        role: OperandRole::SRC1,
        size_bits: 0,
        mem: None,
    };
    pub const SRC2: OperandAccess = OperandAccess {
        role: OperandRole::SRC2,
        size_bits: 0,
        mem: None,
    };
}

/// ## Uninitialized Instruction Semantics
/// holds all the semantic information about an instruction, after being initialized from static analysis
/// later it will be converted to InsSmntcs
#[derive(Debug, Clone)]
pub struct UninInsSmntcs {
    pub operand_reads: Vec<OperandAccess>,
    pub operand_writes: Vec<OperandAccess>,
    pub operand_writes_conditional: Vec<OperandAccess>,

    pub implicit_reads: Vec<X86Register>,
    pub implicit_writes: Vec<X86Register>,
}

impl UninInsSmntcs {
    pub fn set_operand_of_role_size_bits(&mut self, role: OperandRole, size_bits: u8) {
        for op_access in &mut self
            .operand_reads
            .iter_mut()
            .chain(self.operand_writes.iter_mut())
            .chain(self.operand_writes_conditional.iter_mut())
        {
            if op_access.role == role {
                op_access.size_bits = size_bits;
            }
        }
    }
}

/// returns all the semantic information, which can be statically determined, about an instruction
/// this does not include size of memory accesses or operands
pub fn populate_semantics(ins: X86Instruction) -> UninInsSmntcs {
    match ins {
        X86Instruction::ADD => UninInsSmntcs {
            operand_reads: vec![OperandAccess::DEST, OperandAccess::SRC1],
            operand_writes: vec![OperandAccess::DEST],
            operand_writes_conditional: vec![],

            implicit_reads: Vec::new(),
            implicit_writes: vec![
                X86Register::OF,
                X86Register::SF,
                X86Register::ZF,
                X86Register::AF,
                X86Register::PF,
                X86Register::CF,
            ],
        },
        _ => UninInsSmntcs {
            operand_reads: vec![],
            operand_writes: vec![],
            operand_writes_conditional: vec![],

            implicit_reads: Vec::new(),
            implicit_writes: Vec::new(),
        },
    }
}

pub fn decode_and_populate_semantics(cs: Capstone, bytes: &[u8]) -> Option<UninInsSmntcs> {
    if let Ok(insns) = cs.disasm_all(bytes, 0x1000)
        && let Some(cs_insn) = insns.iter().next()
        && let Ok(x86_ins) = X86Instruction::try_from(cs_insn)
    {
        let mut unint_semantics = populate_semantics(x86_ins);
        let registers_used = cs_insn
            .op_str()
            .unwrap_or("")
            .split(',')
            .filter_map(|reg_str| X86Register::from_str(reg_str.trim()).ok())
            .collect::<Vec<_>>();

        // if there is a destination register, set its size bits
        if let Some(reg) = registers_used.first() {
            unint_semantics.set_operand_of_role_size_bits(OperandRole::DEST, reg.size_bits());
        }

        // same with src_1
        if let Some(reg) = registers_used.get(1) {
            unint_semantics.set_operand_of_role_size_bits(OperandRole::SRC1, reg.size_bits());
        }

        // same with src_2
        if let Some(reg) = registers_used.get(2) {
            unint_semantics.set_operand_of_role_size_bits(OperandRole::SRC2, reg.size_bits());
        }

        return Some(unint_semantics);
    }
    None
}
