use capstone::arch::BuildsCapstone;
use capstone::{Capstone, arch};
use nasop::data_representation::x86_ins::X86Instruction;
use nasop::data_representation::x86_ins_semantics::{
    AccessType, InsSmntcs, OperandAccess, OperandRole, decode_and_populate_semantics,
};
use nasop::data_representation::x86_reg::X86Register;
use nasop::{assemble_nasm, exmaple_analysis::ExaDB};
use std::path::PathBuf;
use std::{collections::HashMap, fs};
pub type BlockID = u32;

pub struct CfgIns {
    smnts: InsSmntcs,
    ins: X86Instruction,
}

pub struct AsmCfg {
    blocks: HashMap<BlockID, Vec<CfgIns>>,
}
const CONDITIONAL_JUMPS: &[&str] = &[
    "ja", "jae", "jb", "jbe", "jc", "jcxz", "jecxz", "jz", "jnz", "je", "jne", "jg", "jge", "jl",
    "jle", "jo", "jno", "js", "jns", "jp", "jnp", "jpe", "jpo",
];

pub enum InsJumpType {
    /// exact memory location
    Direct(i64),
    /// jumps to a location, somewhere stored in memory
    Indirect(OperandAccess),
    Conditional(i64),
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
            return Some(InsJumpType::Conditional(t));
        }
    }

    // implicit jumping
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

    if !writes_rip {
        return None;
    }

    // direct jump
    if let Some(imm) = all_reads.find_map(|acc| {
        if let Some(AccessType::IMM(v)) = acc.access_type {
            Some(v)
        } else {
            None
        }
    }) {
        return Some(InsJumpType::Direct(imm));
    }

    //indirect
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
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");

        let insns: capstone::Instructions<'_> =
            cs.disasm_all(bin, addr).expect("Disassemble failed");

        for insn in insns.iter() {
            println!("\n{}", insn);

            let opt_smnt = decode_and_populate_semantics(&cs, insn.bytes());

            match opt_smnt {
                None => println!("failed to parse semantics"),
                Some(smts) => {
                    println!("{smts}")
                }
            }
        }
    }
}
