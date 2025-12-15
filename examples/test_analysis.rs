use capstone::arch::BuildsCapstone;
use capstone::{Capstone, arch};
use nasop::data_representation::x86_ins::X86Instruction;
use nasop::data_representation::x86_ins_semantics::{
    AccessType, InsSmntcs, OperandAccess, OperandRole, decode_and_populate_semantics,
};
use nasop::data_representation::x86_reg::X86Register;
use nasop::{assemble_nasm, exmaple_analysis::ExaDB};
use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::{collections::HashMap, fs};
pub type BlockID = u64;

#[derive(Debug, Clone)]
pub struct CfgIns {
    smnts: InsSmntcs,
    pub address: u64,
    ins: X86Instruction,
}

impl std::fmt::Display for CfgIns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.ins)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct CfgBlock {
    // holds a vec of all adresses
    ins: Vec<u64>,
    jmp_type: Option<InsJumpType>,
}

#[derive(Debug, Clone)]
pub struct AsmCfg {
    bin_dec: Vec<(u64, CfgIns)>,
    blocks: HashMap<BlockID, CfgBlock>,
    current_id: u64,
    idx_to_do: Vec<usize>,
    idx_pending: HashSet<usize>,
    idx_visited: HashSet<usize>,
}

impl AsmCfg {
    pub fn new(initial_address: u64, bin: &[u8]) -> Self {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");

        let all_ins = cs.disasm_all(bin, initial_address).unwrap();
        let mut decoded_ins = Vec::new();
        for ins in all_ins.iter() {
            let cfg_ins = CfgIns {
                address: ins.address(),
                smnts: decode_and_populate_semantics(&cs, ins).unwrap(),
                ins: X86Instruction::try_from(ins).unwrap(),
            };
            decoded_ins.push((ins.address(), cfg_ins));
        }
        let mut cfg = AsmCfg {
            bin_dec: decoded_ins,
            blocks: HashMap::new(),
            current_id: 0,
            idx_to_do: Vec::new(),
            idx_pending: HashSet::new(),
            idx_visited: HashSet::new(),
        };
        cfg.build_tree();
        cfg
    }
    /// if there is a block, that contain that address, split it up into two
    fn split_block(&mut self, addr: u64) {
        println!("attempting to split block at addr {}", addr);
        if let Some((b_id, idx)) = self.search_for_block_with_address(addr) {
            let block = self.blocks.get_mut(&b_id).unwrap();

            let tail_instructions = block.ins.split_off(idx);
            let tail_jump_type = block.jmp_type.clone();
            // create fallthrough
            block.jmp_type = None;
            self.create_block_and_mark(tail_instructions, tail_jump_type);
        }
    }

    fn enqueue_idx(&mut self, idx: usize) {
        if self.bin_dec.get(idx).is_none()
            || self.idx_pending.contains(&idx)
            || self.idx_visited.contains(&idx)
        {
            return;
        }
        self.idx_to_do.push(idx);
        self.idx_pending.insert(idx);
    }

    pub fn build_tree(&mut self) {
        // initial
        self.enqueue_idx(0);

        while let Some(current_idx) = self.idx_to_do.pop() {
            self.idx_pending.remove(&current_idx);

            // skip if already created while it was still pending
            if self.bin_dec.get(current_idx).is_none() || self.idx_visited.contains(&current_idx) {
                continue;
            }

            let mut collected_adresses: Vec<u64> = Vec::new();

            for (idx, (adress, ins)) in self.bin_dec.iter().enumerate().skip(current_idx) {
                let jmp_type = jump_type(ins);
                if let Some(jmp) = jmp_type {
                    match jmp {
                        InsJumpType::Direct(target) => {
                            collected_adresses.push(*adress);
                            self.enqueue_idx_from_adress(target); // no fallthrough, jump only

                            self.create_block_and_mark(
                                collected_adresses.clone(),
                                Some(InsJumpType::Direct(target)),
                            );
                            // a jump can land in the middle of another block,
                            // try to split that block
                            self.split_block(target);
                            collected_adresses.clear();
                            break;
                        }
                        InsJumpType::ConditionalImm(target) => {
                            // handle fallthrough
                            collected_adresses.push(*adress);
                            self.enqueue_idx(idx + 1); // fallthrough
                            self.enqueue_idx_from_adress(target);

                            self.create_block_and_mark(
                                collected_adresses.clone(),
                                Some(InsJumpType::ConditionalImm(target)),
                            );
                            self.split_block(target);
                            collected_adresses.clear();
                            break;
                        }
                        InsJumpType::ConditionalIndirect(op) => {
                            collected_adresses.push(*adress);
                            // fallthrough only
                            self.enqueue_idx(idx + 1);
                            self.create_block_and_mark(
                                collected_adresses.clone(),
                                Some(InsJumpType::ConditionalIndirect(op)),
                            );
                            collected_adresses.clear();
                            break;
                        }
                        InsJumpType::Indirect(op) => {
                            collected_adresses.push(*adress);
                            self.create_block_and_mark(
                                collected_adresses.clone(),
                                Some(InsJumpType::Indirect(op)),
                            );
                            collected_adresses.clear();
                            break;
                        }
                        InsJumpType::Terminating => {
                            collected_adresses.push(*adress);
                            self.create_block_and_mark(collected_adresses.clone(), None);
                            collected_adresses.clear();
                            break;
                        }
                    }
                }

                collected_adresses.push(*adress);
                self.idx_visited.insert(idx);
            }

            if !collected_adresses.is_empty() {
                self.create_block_and_mark(collected_adresses, None);
            }
        }
    }

    fn enqueue_idx_from_adress(&mut self, addr: u64) {
        if let Some(idx) = self.search_for_idx_with_addr(addr) {
            self.enqueue_idx(idx); // only target, no fallthrough
        }
    }

    fn create_block_and_mark(&mut self, ins: Vec<u64>, jmp_type: Option<InsJumpType>) {
        if let Some(first) = ins.first() {
            if self.search_for_adress(*first) {
                return;
            }
            self.blocks.insert(
                self.current_id,
                CfgBlock {
                    ins: ins.clone(),
                    jmp_type,
                },
            );
            self.current_id += 1;
        }
    }

    fn search_for_adress(&self, adress: u64) -> bool {
        for block in &self.blocks {
            if block.1.ins.contains(&adress) {
                return true;
            }
        }
        false
    }

    fn search_for_idx_with_addr(&self, addr: u64) -> Option<usize> {
        for (idx, (idx_address, _)) in self.bin_dec.iter().enumerate() {
            if addr == *idx_address {
                return Some(idx);
            }
        }
        None
    }

    // returns the id of the block and the index of the instruction
    fn search_for_block_with_address(&self, address: u64) -> Option<(BlockID, usize)> {
        for (block_id, block) in &self.blocks {
            if let (Some(first), Some(last)) = (block.ins.first(), block.ins.last())
                && address >= *first
                && address <= *last
            {
                if let Some((idx, _)) = block
                    .ins
                    .iter()
                    .enumerate()
                    .find(|(_, ins)| **ins == address)
                {
                    return Some((*block_id, idx));
                } else {
                    // todo: what if a instruction is split weirdly?
                    return None;
                }
            }
        }
        None
    }

    fn get_all_instruction_idx_block(&self, block_id: BlockID) -> Vec<usize> {
        let opt_block = self.blocks.get(&block_id);
        let mut ins_idx = Vec::new();
        match opt_block {
            Some(b) => {
                for addr in &b.ins {
                    if let Some(idx) = self.search_for_idx_with_addr(*addr) {
                        ins_idx.push(idx);
                    }
                }
            }
            None => {
                return Vec::new();
            }
        }
        ins_idx
    }
}

impl std::fmt::Display for AsmCfg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ASM CFG:")?;
        for (id, block) in &self.blocks {
            writeln!(f, "Block: {id}")?;
            let ins_amount = block.ins.len();
            let addr_first = if let Some(ins) = block.ins.first() {
                *ins
            } else {
                0
            };
            let addr_last = if let Some(ins) = block.ins.last() {
                *ins
            } else {
                0
            };

            writeln!(f, " - {ins_amount} instructions")?;
            for idx in &self.get_all_instruction_idx_block(*id) {
                write!(f, " - {}", self.bin_dec[*idx].1)?;
            }
            writeln!(
                f,
                "\n - adress space from: {}, to: {}",
                addr_first, addr_last
            )?;
            writeln!(f, " - jumps to: {:#?}", block.jmp_type)?;
        }
        Ok(())
    }
}

const CONDITIONAL_JUMPS: &[&str] = &[
    "ja", "jae", "jb", "jbe", "jcxz", "jecxz", "jz", "jnz", "je", "jne", "jg", "jge", "jl", "jle",
    "jo", "jno", "js", "jns", "jp", "jnp", "jpe", "jpo",
];

const TERMINATING_INS: &[&str] = &["int3", "ret"];

#[derive(Debug, Clone)]
pub enum InsJumpType {
    /// exact memory location
    Direct(u64),
    /// jumps to a location, somewhere stored in memory
    Indirect(OperandAccess),
    /// conditional jump with an immediate target
    ConditionalImm(u64),
    /// conditional jump whose target is indirect
    ConditionalIndirect(OperandAccess),
    Terminating,
}
fn jump_type(ins: &CfgIns) -> Option<InsJumpType> {
    let mnemonic = ins.ins.to_string().to_lowercase();

    if CONDITIONAL_JUMPS.contains(&mnemonic.as_str()) {
        println!("found conditional jump: {}", ins);
        let target = ins.smnts.operand_reads.iter().find_map(|acc| {
            if let Some(AccessType::IMM(v)) = acc.access_type {
                Some(v)
            } else {
                None
            }
        });
        if let Some(t) = target {
            return Some(InsJumpType::ConditionalImm(t));
        }

        // if there's no immediate, try to find an indirect operand
        let implicit_reads: Vec<OperandAccess> = ins
            .smnts
            .implicit_reads
            .iter()
            .map(|reg| OperandAccess {
                access_type: Some(AccessType::REG(*reg)),
                role: OperandRole::SRC1,
            })
            .collect();

        let indirect_op = ins
            .smnts
            .operand_reads
            .iter()
            .chain(implicit_reads.iter())
            .find(|acc| acc.role == OperandRole::SRC1)
            .or_else(|| {
                ins.smnts
                    .operand_reads
                    .iter()
                    .chain(implicit_reads.iter())
                    .find(|acc| !matches!(acc.access_type, Some(AccessType::IMM(_))))
            })
            .cloned();

        if let Some(op) = indirect_op {
            return Some(InsJumpType::ConditionalIndirect(op));
        }

        return None;
    }

    if TERMINATING_INS.contains(&mnemonic.as_str()) {
        return Some(InsJumpType::Terminating);
    }

    let is_unconditional_jump = mnemonic == "jmp";
    let is_call = mnemonic == "call";

    let implicit_writes: Vec<OperandAccess> = ins
        .smnts
        .implicit_writes
        .iter()
        .map(|reg| OperandAccess {
            access_type: Some(AccessType::REG(*reg)),
            role: OperandRole::DEST,
        })
        .collect();

    let implicit_reads: Vec<OperandAccess> = ins
        .smnts
        .implicit_reads
        .iter()
        .map(|reg| OperandAccess {
            access_type: Some(AccessType::REG(*reg)),
            role: OperandRole::SRC1,
        })
        .collect();

    let mut all_writes = ins
        .smnts
        .operand_writes
        .iter()
        .chain(implicit_writes.iter());
    let mut all_reads = ins.smnts.operand_reads.iter().chain(implicit_reads.iter());

    let writes_rip =
        all_writes.any(|acc| matches!(acc.access_type, Some(AccessType::REG(X86Register::RIP))));

    if !(writes_rip || is_unconditional_jump || is_call) {
        return None;
    }

    if let Some(imm) = all_reads.find_map(|acc| {
        if let Some(AccessType::IMM(v)) = acc.access_type {
            Some(v)
        } else {
            None
        }
    }) {
        return Some(InsJumpType::Direct(imm));
    }

    let indirect_op = ins
        .smnts
        .operand_reads
        .iter()
        .chain(implicit_reads.iter())
        .find(|acc| acc.role == OperandRole::SRC1)
        .or_else(|| {
            ins.smnts
                .operand_reads
                .iter()
                .chain(implicit_reads.iter())
                .find(|acc| !matches!(acc.access_type, Some(AccessType::IMM(_))))
        })
        .cloned();

    indirect_op.map(InsJumpType::Indirect)
}

fn main() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("nasm_test_dependent");
    let mut exa_db = ExaDB::default();
    exa_db.generate_analysis_from_folder(base);

    for ex in &exa_db.examples {
        println!("Running analysis for example: {:?}", ex.path);
        let _res: &nasop::exmaple_analysis::AnalysisResult = exa_db.get_analysis(&ex.path).unwrap();

        let asm_file = "temp.asm";
        let bin_file = "temp.bin";

        fs::write(asm_file, &ex.content).expect("Failed to write temp.asm");

        assemble_nasm(asm_file, bin_file, &ex.content);

        let bin_vec = fs::read(bin_file).expect("Failed to read temp.bin");
        let bin = bin_vec.as_slice();

        let addr = 0x1000;
        let cfg = AsmCfg::new(addr, bin);
        println!("{}", cfg)
    }
}
