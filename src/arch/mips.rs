use super::{imm, mem, reg, Kind, Op, HIGH_HALF_SHIFT, IMM16_MASK};
use crate::load::{dyn_val, sym_name};
use capstone::arch::mips::MipsReg;
use goblin::elf::Elf;
use std::collections::HashMap;

const DT_PLTGOT: u64 = 3;
const DT_MIPS_LOCAL_GOTNO: u64 = 0x7000_000a;
const DT_MIPS_SYMTABNO: u64 = 0x7000_0011;
const DT_MIPS_GOTSYM: u64 = 0x7000_0013;
const GP_BIAS: u64 = 0x7ff0;

pub const ARG_REGS: [u16; 4] = [
    MipsReg::MIPS_REG_A0 as u16,
    MipsReg::MIPS_REG_A1 as u16,
    MipsReg::MIPS_REG_A2 as u16,
    MipsReg::MIPS_REG_A3 as u16,
];

pub const SP: u16 = MipsReg::MIPS_REG_SP as u16;
pub const GP: u16 = MipsReg::MIPS_REG_GP as u16;
pub const V0: u16 = MipsReg::MIPS_REG_V0 as u16;

pub fn decode(mnemonic: &str, o: &[Op; 3]) -> Option<Kind> {
    match mnemonic {
        "jal" | "bal" | "jals" => Some(Kind::Call(imm(o, 0)? as u64)),
        "jalr" => Some(Kind::CallInd { reg: reg(o, 0)? }),
        "jr" => (reg(o, 0)? == MipsReg::MIPS_REG_RA as u16).then_some(Kind::Ret),
        "lui" => {
            let high_half = ((imm(o, 1)? as u64) & IMM16_MASK) << HIGH_HALF_SHIFT;
            Some(Kind::SetConst {
                dst: reg(o, 0)?,
                val: high_half,
            })
        }
        "lw" => {
            let (base, disp) = mem(o, 1)?;
            Some(Kind::Load {
                dst: reg(o, 0)?,
                base,
                disp,
            })
        }
        "addiu" | "addi" | "ori" => Some(Kind::AddImm {
            dst: reg(o, 0)?,
            base: reg(o, 1)?,
            imm: imm(o, 2)?,
        }),
        "move" => Some(Kind::Mov {
            dst: reg(o, 0)?,
            src: reg(o, 1)?,
        }),
        _ => None,
    }
}

pub fn resolve_got(elf: &Elf, got2sym: &mut HashMap<u64, String>) -> Option<u64> {
    let got = dyn_val(elf, DT_PLTGOT)?;
    let gp = got.wrapping_add(GP_BIAS);

    let (Some(local_gotno), Some(gotsym), Some(symtabno)) = (
        dyn_val(elf, DT_MIPS_LOCAL_GOTNO),
        dyn_val(elf, DT_MIPS_GOTSYM),
        dyn_val(elf, DT_MIPS_SYMTABNO),
    ) else {
        return Some(gp);
    };
    let entry_size = if elf.is_64 { 8 } else { 4 };
    let last_dynsym = symtabno.min(elf.dynsyms.len() as u64);
    for sym_index in gotsym..last_dynsym {
        let got_entry = local_gotno
            .wrapping_add(sym_index - gotsym)
            .wrapping_mul(entry_size);
        let slot = got.wrapping_add(got_entry);
        let Some(sym) = elf.dynsyms.get(sym_index as usize) else {
            continue;
        };
        if let Some(name) = sym_name(&elf.dynstrtab, sym.st_name) {
            got2sym.entry(slot).or_insert(name);
        }
    }
    Some(gp)
}
