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
    adress: u64,
    ins: X86Instruction,
}

impl std::fmt::Display for CfgIns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "__{}__ \n with semantics: ", self.ins)?;
        writeln!(f, "{}", self.smnts)
    }
}

#[derive(Debug, Clone)]
pub struct CfgBlock {
    ins: Vec<CfgIns>,
    jmp_type: Option<InsJumpType>,
}

#[derive(Debug, Clone, Default)]
pub struct AsmCfg {
    blocks: HashMap<BlockID, CfgBlock>,
    current_id: u64,
    adresses_to_do: Vec<u64>,
    pending: HashSet<u64>,
    visited: HashSet<u64>,
}

impl AsmCfg {
    fn enqueue_address(&mut self, addr: u64) {
        if self.search_for_adress(addr)
            || self.pending.contains(&addr)
            || self.visited.contains(&addr)
        {
            return;
        }
        self.adresses_to_do.push(addr);
        self.pending.insert(addr);
    }

    pub fn build_tree(&mut self, initial_address: u64, bin: &[u8]) {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");

        // enqueue initial address
        self.enqueue_address(initial_address);

        while let Some(current_init_adress) = self.adresses_to_do.pop() {
            self.pending.remove(&current_init_adress);

            // skip if already created while it was still pending
            if self.search_for_adress(current_init_adress)
                || self.visited.contains(&current_init_adress)
            {
                continue;
            }

            let bin_offset = current_init_adress
                .checked_sub(initial_address)
                .and_then(|ofs| usize::try_from(ofs).ok())
                .unwrap();
            if bin_offset >= bin.len() {
                return;
            }
            let instructions = match cs.disasm_all(&bin[bin_offset..], current_init_adress) {
                Ok(i) => i,
                Err(e) => panic!("{e}"),
            };
            let mut collected_cfg_ins = Vec::new();

            for ins in instructions.iter() {
                let addr = ins.address();
                let cfg_ins = CfgIns {
                    adress: addr,
                    smnts: decode_and_populate_semantics(&cs, ins).unwrap(),
                    ins: X86Instruction::try_from(ins).unwrap(),
                };

                let jmp_type = jump_type(&cfg_ins);
                if let Some(jmp) = jmp_type {
                    match jmp {
                        InsJumpType::Direct(target) => {
                            collected_cfg_ins.push(cfg_ins);
                            self.enqueue_address(target); // only target, no fallthrough
                            self.create_block_and_mark(
                                collected_cfg_ins.clone(),
                                Some(InsJumpType::Direct(target)),
                            );
                            collected_cfg_ins.clear();
                            break;
                        }
                        InsJumpType::ConditionalImm(target) => {
                            collected_cfg_ins.push(cfg_ins);
                            let next_addr = addr + ins.bytes().len() as u64; // fallthrough
                            self.enqueue_address(target);
                            self.enqueue_address(next_addr);
                            self.create_block_and_mark(
                                collected_cfg_ins.clone(),
                                Some(InsJumpType::ConditionalImm(target)),
                            );
                            collected_cfg_ins.clear();
                            break;
                        }
                        InsJumpType::ConditionalIndirect(op) => {
                            collected_cfg_ins.push(cfg_ins);
                            // fallthrough only
                            let next_addr = addr + ins.bytes().len() as u64;
                            self.enqueue_address(next_addr);
                            self.create_block_and_mark(
                                collected_cfg_ins.clone(),
                                Some(InsJumpType::ConditionalIndirect(op)),
                            );
                            collected_cfg_ins.clear();
                            break;
                        }
                        InsJumpType::Indirect(op) => {
                            collected_cfg_ins.push(cfg_ins);
                            self.create_block_and_mark(
                                collected_cfg_ins.clone(),
                                Some(InsJumpType::Indirect(op)),
                            );
                            collected_cfg_ins.clear();
                            break;
                        }
                        InsJumpType::Terminating => {
                            collected_cfg_ins.push(cfg_ins);
                            self.create_block_and_mark(collected_cfg_ins.clone(), None);
                            collected_cfg_ins.clear();
                            break;
                        }
                    }
                }

                collected_cfg_ins.push(cfg_ins);
            }

            if !collected_cfg_ins.is_empty() {
                self.create_block_and_mark(collected_cfg_ins, None);
            }
        }
    }

    fn create_block_and_mark(&mut self, ins: Vec<CfgIns>, jmp_type: Option<InsJumpType>) {
        if let Some(first) = ins.first() {
            let start_addr = first.adress;
            if self.search_for_adress(start_addr) {
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
            self.visited.insert(start_addr);
        }
    }

    fn search_for_adress(&self, adress: u64) -> bool {
        for block in &self.blocks {
            if block.1.ins.iter().any(|v| v.adress == adress) {
                return true;
            }
        }
        false
    }
}

impl std::fmt::Display for AsmCfg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ASM CFG:")?;
        for (id, block) in &self.blocks {
            writeln!(f, "Block: {id}")?;
            let ins_amount = block.ins.len();
            let addr_first = if let Some(ins) = block.ins.first() {
                ins.adress
            } else {
                0
            };
            let addr_last = if let Some(ins) = block.ins.last() {
                ins.adress
            } else {
                0
            };

            writeln!(f, " - {ins_amount} instructions")?;
            for ins in &block.ins {
                writeln!(f, "{}", ins)?;
            }
            writeln!(f, " - adress space from: {}, to: {}", addr_first, addr_last)?;
            writeln!(f, " - jumps to: {:#?}", block.jmp_type)?;
        }
        Ok(())
    }
}

const CONDITIONAL_JUMPS: &[&str] = &[
    "ja", "jae", "jb", "jbe", "jc", "jcxz", "jecxz", "jz", "jnz", "je", "jne", "jg", "jge", "jl",
    "jle", "jo", "jno", "js", "jns", "jp", "jnp", "jpe", "jpo",
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
    let mnemonic = ins.ins.to_string().to_ascii_lowercase();

    if CONDITIONAL_JUMPS.contains(&mnemonic.as_str()) {
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

        // if there's no immediate, try to find an indirect operand (e.g. memory/reg)
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
        let path_str = ex.path.to_string_lossy();
        if !path_str.contains("jump") {
            continue;
        }
        println!("Running analysis for example: {:?}", ex.path);
        let _res: &nasop::exmaple_analysis::AnalysisResult = exa_db.get_analysis(&ex.path).unwrap();

        let asm_file = "temp.asm";
        let bin_file = "temp.bin";

        fs::write(asm_file, &ex.content).expect("Failed to write temp.asm");

        assemble_nasm(asm_file, bin_file, &ex.content);

        let bin_vec = fs::read(bin_file).expect("Failed to read temp.bin");
        let bin = bin_vec.as_slice();

        let addr = 0x1000;
        let mut cfg = AsmCfg::default();
        cfg.build_tree(addr, bin);
        println!("{}", cfg)
    }
}
