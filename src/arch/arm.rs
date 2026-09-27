use super::{imm, mem, reg, Kind, Op, HIGH_HALF_SHIFT, IMM16_MASK};
use crate::load::Binary;
use capstone::arch::arm::ArmReg;

const PC_BIAS: u64 = 8;
const WORD: usize = 4;

pub const ARG_REGS: [u16; 4] = [
    ArmReg::ARM_REG_R0 as u16,
    ArmReg::ARM_REG_R1 as u16,
    ArmReg::ARM_REG_R2 as u16,
    ArmReg::ARM_REG_R3 as u16,
];

pub const SP: u16 = ArmReg::ARM_REG_SP as u16;

fn pc_relative(addr: u64, disp: i64) -> u64 {
    addr.wrapping_add(PC_BIAS).wrapping_add(disp as u64)
}

fn literal(addr: u64, disp: i64, bin: &Binary) -> Option<u64> {
    let pool = pc_relative(addr, disp);
    let word: [u8; WORD] = bin.read_vaddr(pool, WORD)?.try_into().ok()?;
    Some(if bin.little {
        u32::from_le_bytes(word) as u64
    } else {
        u32::from_be_bytes(word) as u64
    })
}

pub fn decode(mnemonic: &str, o: &[Op; 3], addr: u64, bin: &Binary) -> Option<Kind> {
    match mnemonic {
        "bl" | "blx" => match o[0] {
            Op::Imm(target) => Some(Kind::Call(target as u64)),
            Op::Reg(r) => Some(Kind::CallInd { reg: r }),
            _ => None,
        },
        "bx" => Some(Kind::Ret),
        "movw" => {
            let low_half = (imm(o, 1)? as u64) & IMM16_MASK;
            Some(Kind::SetConst {
                dst: reg(o, 0)?,
                val: low_half,
            })
        }
        "movt" => {
            let high_half = ((imm(o, 1)? as u64) << HIGH_HALF_SHIFT) as i64;
            Some(Kind::AddImm {
                dst: reg(o, 0)?,
                base: reg(o, 0)?,
                imm: high_half,
            })
        }
        "ldr" => {
            let (base, disp) = mem(o, 1)?;
            let dst = reg(o, 0)?;
            if base == ArmReg::ARM_REG_PC as u16 {
                Some(Kind::PcVal {
                    dst,
                    val: literal(addr, disp, bin)?,
                })
            } else {
                Some(Kind::Load { dst, base, disp })
            }
        }
        "add" => {
            let (dst, base) = (reg(o, 0)?, reg(o, 1)?);
            if base == ArmReg::ARM_REG_PC as u16 {
                Some(Kind::SetConst {
                    dst,
                    val: pc_relative(addr, imm(o, 2)?),
                })
            } else {
                Some(Kind::AddImm {
                    dst,
                    base,
                    imm: imm(o, 2)?,
                })
            }
        }
        "sub" => {
            let (dst, base) = (reg(o, 0)?, reg(o, 1)?);
            if base == ArmReg::ARM_REG_PC as u16 {
                Some(Kind::SetConst {
                    dst,
                    val: pc_relative(addr, -imm(o, 2)?),
                })
            } else {
                Some(Kind::AddImm {
                    dst,
                    base,
                    imm: -imm(o, 2)?,
                })
            }
        }
        "mov" => match o[1] {
            Op::Imm(val) => Some(Kind::SetConst {
                dst: reg(o, 0)?,
                val: val as u64,
            }),
            _ => Some(Kind::Mov {
                dst: reg(o, 0)?,
                src: reg(o, 1)?,
            }),
        },
        _ => None,
    }
}
