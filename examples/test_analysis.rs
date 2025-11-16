use std::fs;
use std::path::PathBuf;

use nasop::{assemble_nasm, exmaple_analysis::ExaDB, instruction_db::InsDB};

fn main() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("nasm_test_dependent");
    let mut exa_db = ExaDB::default();
    exa_db.generate_analysis_from_folder(base);

    let mut ins_db = InsDB::default();

    for ex in &exa_db.examples {
        println!("Running analysis for example: {:?}", ex.path);
        let res = exa_db.get_analysis(&ex.path).unwrap();

        // Prepare temporary ASM and BIN files
        let asm_file = "temp.asm";
        let bin_file = "temp.bin";

        // Write the content to temp.asm
        fs::write(asm_file, &ex.content).expect("Failed to write temp.asm");

        // Assemble NASM code to binary
        assemble_nasm(asm_file, bin_file, &ex.content);

        // Read the binary bytes
        let bin = fs::read(bin_file).expect("Failed to read temp.bin");

        // Choose a base address (can be arbitrary)
        let addr = 0x1000;

        // Analyze the binary
        ins_db.analyze_bin_at_addr(&bin, addr);
    }
}
