use super::{imm, mem, reg, Kind, Op};
use capstone::arch::arm64::Arm64Reg;

pub const ARG_REGS: [u16; 8] = [
    Arm64Reg::ARM64_REG_X0 as u16,
    Arm64Reg::ARM64_REG_X1 as u16,
    Arm64Reg::ARM64_REG_X2 as u16,
    Arm64Reg::ARM64_REG_X3 as u16,
    Arm64Reg::ARM64_REG_X4 as u16,
    Arm64Reg::ARM64_REG_X5 as u16,
    Arm64Reg::ARM64_REG_X6 as u16,
    Arm64Reg::ARM64_REG_X7 as u16,
];

pub const SP: u16 = Arm64Reg::ARM64_REG_SP as u16;

pub fn wide(r: u16) -> u16 {
    const W0: u16 = Arm64Reg::ARM64_REG_W0 as u16;
    const W28: u16 = Arm64Reg::ARM64_REG_W28 as u16;
    const X0: u16 = Arm64Reg::ARM64_REG_X0 as u16;
    match r {
        W0..=W28 => X0 + (r - W0),
        r if r == Arm64Reg::ARM64_REG_W29 as u16 => Arm64Reg::ARM64_REG_X29 as u16,
        r if r == Arm64Reg::ARM64_REG_W30 as u16 => Arm64Reg::ARM64_REG_X30 as u16,
        r => r,
    }
}

pub fn decode(mnemonic: &str, o: &[Op; 3]) -> Option<Kind> {
    match mnemonic {
        "bl" => Some(Kind::Call(imm(o, 0)? as u64)),
        "blr" => Some(Kind::CallInd { reg: reg(o, 0)? }),
        "ret" => Some(Kind::Ret),
        "adrp" | "adr" => Some(Kind::SetConst {
            dst: reg(o, 0)?,
            val: imm(o, 1)? as u64,
        }),
        "ldr" => {
            let (base, disp) = mem(o, 1)?;
            Some(Kind::Load {
                dst: reg(o, 0)?,
                base,
                disp,
            })
        }
        "add" => Some(Kind::AddImm {
            dst: reg(o, 0)?,
            base: reg(o, 1)?,
            imm: imm(o, 2)?,
        }),
        "movk" => Some(Kind::AddImm {
            dst: reg(o, 0)?,
            base: reg(o, 0)?,
            imm: imm(o, 1)?,
        }),
        "sxtw" | "uxtw" => Some(Kind::Mov {
            dst: reg(o, 0)?,
            src: reg(o, 1)?,
        }),
        "sub" => Some(Kind::AddImm {
            dst: reg(o, 0)?,
            base: reg(o, 1)?,
            imm: -imm(o, 2)?,
        }),
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
