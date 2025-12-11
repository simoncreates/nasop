use std::{fmt::Display, str::FromStr};

use capstone::{
    Capstone, Insn, RegAccessType,
    arch::{
        DetailsArchInsn,
        x86::{X86Operand, X86OperandType},
    },
};

use crate::data_representation::{x86_ins::X86Instruction as Ins, x86_reg::X86Register as R};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OperandRole {
    DEST,
    SRC1,
    SRC2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MemoryAccess {
    pub read: bool,
    pub write: bool,
    pub size_bytes: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccessType {
    MEM(MemoryAccess),
    REG(R),
    IMM(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OperandAccess {
    pub role: OperandRole,
    pub access_type: Option<AccessType>,
}

impl OperandAccess {
    pub const DEST: OperandAccess = OperandAccess {
        role: OperandRole::DEST,
        access_type: None,
    };
    pub const SRC1: OperandAccess = OperandAccess {
        role: OperandRole::SRC1,
        access_type: None,
    };
    pub const SRC2: OperandAccess = OperandAccess {
        role: OperandRole::SRC2,
        access_type: None,
    };
}
/// ## Uninitialized Instruction Semantics
/// holds all the semantic information about an instruction, after being initialized from static analysis
/// later it will be converted to InsSmntcs
#[derive(Debug, Clone)]
struct UninInsSmntcs {
    pub operand_reads: Vec<OperandAccess>,
    pub operand_writes: Vec<OperandAccess>,
    pub operand_writes_conditional: Vec<OperandAccess>,

    pub implicit_reads: Vec<R>,
    pub implicit_writes: Vec<R>,
}

#[derive(Debug, Clone)]
pub struct InsSmntcs {
    pub operand_reads: Vec<OperandAccess>,
    pub operand_writes: Vec<OperandAccess>,
    pub operand_writes_conditional: Vec<OperandAccess>,

    pub implicit_reads: Vec<R>,
    pub implicit_writes: Vec<R>,
}

impl From<UninInsSmntcs> for InsSmntcs {
    fn from(us: UninInsSmntcs) -> Self {
        InsSmntcs {
            operand_reads: us.operand_reads,
            operand_writes: us.operand_writes,
            operand_writes_conditional: us.operand_writes_conditional,
            implicit_reads: us.implicit_reads,
            implicit_writes: us.implicit_writes,
        }
    }
}
impl UninInsSmntcs {
    fn set_operand_access_for_role(&mut self, role: OperandRole, acc_type: Option<AccessType>) {
        for op_access in &mut self
            .operand_reads
            .iter_mut()
            .chain(self.operand_writes.iter_mut())
            .chain(self.operand_writes_conditional.iter_mut())
        {
            if op_access.role == role {
                op_access.access_type = acc_type
            }
        }
    }

    pub fn pop_smnt_for_role(&mut self, cs: &Capstone, role: OperandRole, operand: X86Operand) {
        match operand.op_type {
            X86OperandType::Reg(reg_id) => {
                if let Some(name) = cs.reg_name(reg_id)
                    && let Ok(reg) = R::from_str(&name)
                {
                    self.set_operand_access_for_role(role, Some(AccessType::REG(reg)));
                }
            }

            X86OperandType::Imm(raw_imm) => {
                self.set_operand_access_for_role(role, Some(AccessType::IMM(raw_imm as u64)));
            }

            X86OperandType::Mem(_op_mem) => {
                let mem_access = MemoryAccess {
                    read: matches!(
                        operand.access,
                        Some(RegAccessType::ReadOnly) | Some(RegAccessType::ReadWrite)
                    ),
                    write: matches!(
                        operand.access,
                        Some(RegAccessType::WriteOnly) | Some(RegAccessType::ReadWrite)
                    ),
                    size_bytes: operand.size,
                };

                self.set_operand_access_for_role(role, Some(AccessType::MEM(mem_access)));
            }

            X86OperandType::Invalid => {}
        }
    }
}

impl Display for InsSmntcs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Operand Reads:")?;
        for op in &self.operand_reads {
            writeln!(f, "role: {:?}, access type: {:?}", op.role, op.access_type)?;
        }

        writeln!(f, "Operand Writes:")?;
        for op in &self.operand_writes {
            writeln!(f, "role: {:?}, access type: {:?}", op.role, op.access_type)?;
        }

        writeln!(f, "Conditional Operand Writes:")?;
        for op in &self.operand_writes_conditional {
            writeln!(f, "role: {:?}, access type: {:?}", op.role, op.access_type)?;
        }

        writeln!(f, "implicit reads: {:?}", self.implicit_reads)?;
        writeln!(f, "implicit writes: {:?}", self.implicit_writes)?;

        Ok(())
    }
}

/// returns all the semantic information, which can be statically determined, about an instruction
/// this does not include size of memory accesses or operands
fn populate_semantics(ins: Ins) -> UninInsSmntcs {
    match ins {
        Ins::ADD => UninInsSmntcs {
            operand_reads: vec![OperandAccess::DEST, OperandAccess::SRC1],
            operand_writes: vec![OperandAccess::DEST],
            operand_writes_conditional: vec![],

            implicit_reads: Vec::new(),
            implicit_writes: vec![R::OF, R::SF, R::ZF, R::AF, R::PF, R::CF],
        },
        Ins::LEA => UninInsSmntcs {
            operand_reads: vec![OperandAccess::SRC1],
            operand_writes: vec![OperandAccess::DEST],
            operand_writes_conditional: vec![],

            implicit_reads: Vec::new(),
            implicit_writes: Vec::new(),
        },

        Ins::MOV => UninInsSmntcs {
            operand_reads: vec![OperandAccess::SRC1],
            operand_writes: vec![OperandAccess::DEST],
            operand_writes_conditional: vec![],

            implicit_reads: Vec::new(),
            implicit_writes: Vec::new(),
        },

        Ins::JMP => UninInsSmntcs {
            operand_reads: vec![OperandAccess::DEST],
            operand_writes: vec![],
            operand_writes_conditional: vec![],

            implicit_reads: Vec::new(),
            implicit_writes: vec![R::RIP],
        },
        Ins::INT3 => UninInsSmntcs {
            operand_reads: vec![],
            operand_writes: vec![],
            operand_writes_conditional: vec![],

            implicit_reads: Vec::new(),
            implicit_writes: vec![R::IF, R::TF, R::NT, R::AC, R::RF, R::VM],
        },

        Ins::JE | Ins::JNE => UninInsSmntcs {
            operand_reads: vec![OperandAccess::DEST],
            operand_writes: vec![],
            operand_writes_conditional: vec![],

            implicit_reads: vec![R::ZF],
            implicit_writes: vec![R::RIP],
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

pub fn decode_and_populate_semantics(cs: &Capstone, cs_insn: &Insn) -> Option<InsSmntcs> {
    // obtain a typed X86Instruction from the already-decoded insn
    if let Ok(x86_ins) = Ins::try_from(cs_insn) {
        let mut unint_semantics = populate_semantics(x86_ins);

        let detail = cs.insn_detail(cs_insn).ok()?;
        let arch_detail = detail.arch_detail();
        let arch = arch_detail.x86()?;
        let mut ops = arch.operands();

        let dest = ops.next();
        let src1 = ops.next();
        let src2 = ops.next();

        if let Some(op) = dest {
            unint_semantics.pop_smnt_for_role(cs, OperandRole::DEST, op);
        }
        if let Some(op) = src1 {
            unint_semantics.pop_smnt_for_role(cs, OperandRole::SRC1, op);
        }
        if let Some(op) = src2 {
            unint_semantics.pop_smnt_for_role(cs, OperandRole::SRC2, op);
        }

        return Some(InsSmntcs::from(unint_semantics));
    }
    None
}
