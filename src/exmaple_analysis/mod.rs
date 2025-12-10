use serde::Deserialize;
use std::{collections::HashMap, fs, path::PathBuf};
use unicorn_engine::{Arch, Mode, Prot, Unicorn};

use crate::{
    assemble_nasm,
    data_representation::x86_reg::{UCX86Register, X86Register},
    tools::get_registers,
};

#[derive(Debug, Clone, Copy)]
pub enum DisplayFormat {
    SignedInt,
    UnsignedInt,
    Hex,
    Binary,
}

#[derive(Default, Debug, Clone)]
pub struct RegisterState {
    pub registers: std::collections::HashMap<X86Register, u64>,
}

#[derive(Debug, Clone)]
pub enum DisplayAccuracy {
    Exact,
    Approximate,
}

// a list of all main important regisers for approximate analysis
pub const APPROXIMATE_REGISTERS: &[X86Register] = &[
    X86Register::EAX,
    X86Register::EBX,
    X86Register::ECX,
    X86Register::EDX,
    X86Register::ESI,
];

impl RegisterState {
    fn format_value(value: u64, format: DisplayFormat) -> String {
        match format {
            DisplayFormat::SignedInt => format!("{}", value as i64),
            DisplayFormat::UnsignedInt => format!("{}", value),
            DisplayFormat::Hex => format!("{:#x}", value),
            DisplayFormat::Binary => format!("{:#b}", value),
        }
    }

    pub fn simple_display(&self, accuracy: DisplayAccuracy, format: DisplayFormat) -> String {
        let mut result = String::new();
        let keys: Vec<_> = self.registers.keys().collect();
        for key in keys {
            if APPROXIMATE_REGISTERS.contains(key) || matches!(accuracy, DisplayAccuracy::Exact) {
                if !result.is_empty() {
                    result.push_str(", ");
                }
                let value = Self::format_value(self.registers[key], format);
                result.push_str(&format!("{:?}={}", key, value))
            }
        }
        result
    }

    pub fn column_display(&self, accuracy: DisplayAccuracy, format: DisplayFormat) -> String {
        let mut result = String::new();
        let keys: Vec<&X86Register> = self.registers.keys().collect();

        for key in keys {
            if APPROXIMATE_REGISTERS.contains(key) || matches!(accuracy, DisplayAccuracy::Exact) {
                let value = Self::format_value(self.registers[key], format);
                result.push_str(&format!("{:?}: {}\n", key, value));
            }
        }
        result
    }

    pub fn display_register(&self, reg: X86Register, format: DisplayFormat) -> String {
        if let Some(value) = self.registers.get(&reg) {
            let formatted = Self::format_value(*value, format);
            format!("{:?}: {}", reg, formatted)
        } else {
            format!("{:?}: <unavailable>", reg)
        }
    }
}

pub struct AnalysisResult {
    pub initial_registers: RegisterState,
    pub final_registers: RegisterState,
}

#[derive(Deserialize)]
pub struct IncomingTestMetadata {
    pub input: Option<HashMap<String, u64>>,
    pub expect: Option<HashMap<String, u64>>,
}

pub enum TestMetadata {
    None,

    Full {
        input: RegisterState,
        expect: RegisterState,
    },
}

impl From<IncomingTestMetadata> for TestMetadata {
    fn from(value: IncomingTestMetadata) -> Self {
        let input = if let Some(input_map) = value.input {
            let mut registers = HashMap::new();
            for (reg_str, val) in input_map {
                if let Ok(reg) = reg_str.parse() {
                    registers.insert(reg, val);
                }
            }
            RegisterState { registers }
        } else {
            RegisterState::default()
        };

        let expect = if let Some(expect_map) = value.expect {
            let mut registers = HashMap::new();
            for (reg_str, val) in expect_map {
                if let Ok(reg) = reg_str.parse() {
                    registers.insert(reg, val);
                }
            }
            RegisterState { registers }
        } else {
            RegisterState::default()
        };

        TestMetadata::Full { input, expect }
    }
}

pub struct ExaFData {
    pub path: PathBuf,
    pub metadata: TestMetadata,
    pub content: String,
}

#[derive(Default)]
pub struct ExaDB {
    pub analysis_results: HashMap<PathBuf, AnalysisResult>,
    pub examples: Vec<ExaFData>,
}

impl ExaDB {
    pub fn add_example(&mut self, data: ExaFData, analysis: AnalysisResult) {
        self.analysis_results.insert(data.path.clone(), analysis);
        self.examples.push(data);
    }
    pub fn get_analysis(&self, path: &PathBuf) -> Option<&AnalysisResult> {
        self.analysis_results.get(path)
    }

    pub fn generate_analysis_from_folder(&mut self, folder: PathBuf) {
        let mut examples = Vec::new();
        let paths: fs::ReadDir = fs::read_dir(folder).unwrap();

        for path in paths {
            let path = path.unwrap().path();

            if path.extension().and_then(|s| s.to_str()) == Some("asm")
                && let Ok(text) = fs::read_to_string(&path)
            {
                let toml_path = path.with_extension("toml");

                let meta_data = if toml_path.exists() {
                    // read TOML if the file exists
                    let toml_text = fs::read_to_string(&toml_path).unwrap();
                    let incomingmetadata: IncomingTestMetadata =
                        toml::from_str(&toml_text).unwrap();
                    TestMetadata::from(incomingmetadata)
                } else {
                    TestMetadata::None
                };

                examples.push(ExaFData {
                    path: path.clone(),
                    content: text,
                    metadata: meta_data,
                })
            }
        }

        for example in examples {
            let analysis_result = self.analyze_file_data(&example);
            let path = example.path.clone();
            self.add_example(example, analysis_result);
            println!("analyzed: {:?}", path);
            println!(
                "intitial: \n{}",
                self.get_analysis(&path)
                    .unwrap()
                    .initial_registers
                    .column_display(DisplayAccuracy::Approximate, DisplayFormat::UnsignedInt)
            );
            println!(
                "final: \n{}",
                self.get_analysis(&path)
                    .unwrap()
                    .final_registers
                    .column_display(DisplayAccuracy::Approximate, DisplayFormat::UnsignedInt)
            );
        }
    }
    pub fn analyze_file_data(&self, data: &ExaFData) -> AnalysisResult {
        let asm_file = "temp.asm";
        let bin_file = "temp.bin";
        assemble_nasm(asm_file, bin_file, &data.content);

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

        uc.reg_write(
            unicorn_engine::RegisterX86::RSP,
            STACK_ADDR + STACK_SIZE / 2,
        )
        .expect("set rsp");
        uc.mem_write(CODE_ADDR, &code).expect("mem_write code");
        uc.reg_write(unicorn_engine::RegisterX86::RIP, CODE_ADDR)
            .expect("set rip");

        set_metadata_registers(&mut uc, &data.metadata);
        let initial_regs = get_registers(&uc);
        let run_result = uc.emu_start(CODE_ADDR, CODE_ADDR + code.len() as u64, 0, 1_000_000);

        match run_result {
            Ok(_) => {}
            Err(e) => {
                let s = format!("{:?}", e).to_lowercase();
                if s.contains("int3")
                    || s.contains("breakpoint")
                    || s.contains("interrupt")
                    || s.contains("exception")
                {
                    // expected termination
                } else {
                    panic!("emu_start failed unexpectedly: {:?}", e);
                }
            }
        }

        let final_regs: RegisterState = get_registers(&uc);
        check_for_expected_registers(&final_regs, &data.metadata).unwrap();

        let _ = fs::remove_file(asm_file);
        let _ = fs::remove_file(bin_file);

        AnalysisResult {
            initial_registers: initial_regs,
            final_registers: final_regs,
        }
    }
}

fn set_metadata_registers(uc: &mut Unicorn<()>, metadata: &TestMetadata) {
    match metadata {
        TestMetadata::Full { input, expect: _ } => {
            for (reg, val) in &input.registers {
                uc.reg_write(*UCX86Register::from(reg), *val)
                    .expect("set metadata register");
            }
        }
        TestMetadata::None => {}
    }
}

fn check_for_expected_registers(
    final_regs: &RegisterState,
    metadata: &TestMetadata,
) -> Result<(), String> {
    match metadata {
        TestMetadata::Full { input: _, expect } => {
            for (reg, val) in &expect.registers {
                let reg_val = final_regs.registers.get(reg).ok_or_else(|| {
                    format!(
                        "Expected register {:?} to be {}, but it is unavailable",
                        reg, val
                    )
                })?;

                if reg_val != val {
                    return Err(format!(
                        "Expected register {:?} to be {}, but got {}",
                        reg, val, reg_val
                    ));
                }
            }
        }
        TestMetadata::None => {}
    }
    Ok(())
}
