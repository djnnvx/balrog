pub mod aarch64;
pub mod arm;
pub mod mips;

use crate::load::Binary;
use anyhow::Result;
use capstone::arch::arm::ArmOperandType;
use capstone::arch::arm64::{Arm64OperandType, Arm64Shift};
use capstone::arch::mips::MipsOperand;
use capstone::arch::ArchOperand;
use capstone::prelude::*;
use capstone::{Endian, Insn as CsInsn};
use std::collections::HashMap;

const IMM16_MASK: u64 = 0xffff;
const HIGH_HALF_SHIFT: u32 = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
pub enum Arch {
    Arm,
    Aarch64,
    Mips,
    X86,
    X86_64,
}

pub const ANALYZABLE_ARCHES: &str = "mips, arm, aarch64";

impl Arch {
    pub fn align(self) -> u64 {
        match self {
            Arch::X86 | Arch::X86_64 => 1,
            _ => 4,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Arch::Arm => "arm",
            Arch::Aarch64 => "aarch64",
            Arch::Mips => "mips",
            Arch::X86 => "x86",
            Arch::X86_64 => "x86_64",
        }
    }
    pub fn analyzable(self) -> bool {
        matches!(self, Arch::Arm | Arch::Aarch64 | Arch::Mips)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Call(u64),
    CallInd { reg: u16 },
    SetConst { dst: u16, val: u64 },
    Load { dst: u16, base: u16, disp: i64 },
    AddImm { dst: u16, base: u16, imm: i64 },
    PcVal { dst: u16, val: u64 },
    Mov { dst: u16, src: u16 },
    Ret,
    Other,
}

pub struct Ins {
    pub addr: u64,
    pub kind: Kind,
}

pub fn build(arch: Arch, little: bool) -> Result<Capstone> {
    let endian = if little { Endian::Little } else { Endian::Big };
    let cs = match arch {
        Arch::Arm => Capstone::new()
            .arm()
            .mode(capstone::arch::arm::ArchMode::Arm)
            .endian(endian)
            .detail(true)
            .build(),
        Arch::Aarch64 => Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .endian(endian)
            .detail(true)
            .build(),
        Arch::Mips => Capstone::new()
            .mips()
            .mode(capstone::arch::mips::ArchMode::Mips32)
            .endian(endian)
            .detail(true)
            .build(),
        Arch::X86 => Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode32)
            .detail(true)
            .build(),
        Arch::X86_64 => Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build(),
    }?;
    Ok(cs)
}

const SWEEP_CHUNK: usize = 8192;

pub fn sweep(cs: &Capstone, bin: &Binary) -> Vec<Ins> {
    let align = bin.arch.align();
    let mut out = Vec::new();
    for seg in bin.segs.iter().filter(|seg| seg.exec) {
        let start = seg.off as usize;
        let end = ((seg.off + seg.filesz) as usize).min(bin.data.len());
        if start >= end {
            continue;
        }
        let code = &bin.data[start..end];
        let mut pos: u64 = 0;
        let len = (end - start) as u64;
        while pos < len {
            let Ok(insns) = cs.disasm_all(&code[pos as usize..], seg.vaddr + pos) else {
                pos += align;
                continue;
            };
            if insns.is_empty() {
                pos += align;
                continue;
            }
            let mut last_end = pos;
            for insn in insns.iter() {
                out.push(lower(cs, bin, insn));
                last_end = (insn.address() - seg.vaddr) + insn.len() as u64;
            }
            pos = last_end.max(pos + align);
        }
    }
    out.sort_by_key(|ins| ins.addr);
    out.dedup_by_key(|ins| ins.addr);
    out
}

fn lower(cs: &Capstone, bin: &Binary, insn: &CsInsn) -> Ins {
    Ins {
        addr: insn.address(),
        kind: classify(cs, bin, insn).unwrap_or(Kind::Other),
    }
}

#[derive(Clone, Copy)]
pub enum Op {
    Reg(u16),
    Imm(i64),
    Mem(u16, i64),
    None,
}

fn operands(ops: &[ArchOperand]) -> [Op; 3] {
    std::array::from_fn(|n| match ops.get(n) {
        Some(ArchOperand::MipsOperand(MipsOperand::Reg(r))) => Op::Reg(r.0),
        Some(ArchOperand::MipsOperand(MipsOperand::Imm(v))) => Op::Imm(*v),
        Some(ArchOperand::MipsOperand(MipsOperand::Mem(m))) => Op::Mem(m.base().0, m.disp()),
        Some(ArchOperand::ArmOperand(o)) => match o.op_type {
            ArmOperandType::Reg(r) => Op::Reg(r.0),
            ArmOperandType::Imm(v) => Op::Imm(v as i64),
            ArmOperandType::Mem(m) => Op::Mem(m.base().0, m.disp() as i64),
            _ => Op::None,
        },
        Some(ArchOperand::Arm64Operand(o)) => match o.op_type {
            Arm64OperandType::Reg(r) => Op::Reg(aarch64::wide(r.0)),
            Arm64OperandType::Imm(v) => match o.shift {
                Arm64Shift::Lsl(n) => Op::Imm(v << n),
                _ => Op::Imm(v),
            },
            Arm64OperandType::Mem(m) => Op::Mem(m.base().0, m.disp() as i64),
            _ => Op::None,
        },
        _ => Op::None,
    })
}

fn reg(o: &[Op; 3], n: usize) -> Option<u16> {
    match o[n] {
        Op::Reg(r) => Some(r),
        _ => None,
    }
}

fn imm(o: &[Op; 3], n: usize) -> Option<i64> {
    match o[n] {
        Op::Imm(v) => Some(v),
        _ => None,
    }
}

fn mem(o: &[Op; 3], n: usize) -> Option<(u16, i64)> {
    match o[n] {
        Op::Mem(b, d) => Some((b, d)),
        _ => None,
    }
}

fn classify(cs: &Capstone, bin: &Binary, insn: &CsInsn) -> Option<Kind> {
    let detail = cs.insn_detail(insn).ok()?;
    let ops = operands(&detail.arch_detail().operands());
    let mnemonic = insn.mnemonic()?;
    match bin.arch {
        Arch::Mips => mips::decode(mnemonic, &ops),
        Arch::Aarch64 => aarch64::decode(mnemonic, &ops),
        Arch::Arm => arm::decode(mnemonic, &ops, insn.address(), bin),
        _ => None,
    }
}

fn arg_regs(arch: Arch) -> &'static [u16] {
    match arch {
        Arch::Mips => &mips::ARG_REGS,
        Arch::Aarch64 => &aarch64::ARG_REGS,
        Arch::Arm => &arm::ARG_REGS,
        _ => &[],
    }
}

pub fn arg_reg(arch: Arch, n: usize) -> Option<u16> {
    arg_regs(arch).get(n).copied()
}

pub fn arg_count(arch: Arch) -> usize {
    arg_regs(arch).len()
}

pub fn gp_reg(arch: Arch) -> Option<u16> {
    match arch {
        Arch::Mips => Some(mips::GP),
        _ => None,
    }
}

pub fn sp_reg(arch: Arch) -> u16 {
    match arch {
        Arch::Mips => mips::SP,
        Arch::Aarch64 => aarch64::SP,
        Arch::Arm => arm::SP,
        _ => 0,
    }
}

pub fn resolve_stubs(bin: &Binary, insns: &[Ins]) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    for (name, addr) in &bin.undef_stub {
        out.insert(*addr, name.clone());
    }
    let mut tracked: HashMap<u16, (u64, u64)> = HashMap::new();
    for ins in insns {
        match ins.kind {
            Kind::SetConst { dst, val } => {
                tracked.insert(dst, (ins.addr, val));
            }
            Kind::AddImm { dst, base, imm } => {
                if let Some(&(origin, value)) = tracked.get(&base) {
                    tracked.insert(dst, (origin, value.wrapping_add(imm as u64)));
                } else {
                    tracked.remove(&dst);
                }
            }
            Kind::Load { dst, base, disp } => {
                if let Some(&(origin, value)) = tracked.get(&base) {
                    let slot = value.wrapping_add(disp as u64);
                    if let Some(name) = bin.got2sym.get(&slot) {
                        out.insert(origin, name.clone());
                    }
                }
                tracked.remove(&dst);
            }
            Kind::PcVal { dst, val } => {
                tracked.insert(dst, (ins.addr, val));
            }
            Kind::Mov { dst, src } => {
                if let Some(&origin_value) = tracked.get(&src) {
                    tracked.insert(dst, origin_value);
                } else {
                    tracked.remove(&dst);
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;

    fn dummy(arch: Arch, little: bool) -> Binary {
        Binary {
            path: PathBuf::new(),
            data: vec![],
            arch,
            little,
            entry: 0,
            segs: vec![],
            got2sym: HashMap::new(),
            undef_stub: vec![],
            imports: HashSet::new(),
            exports: vec![],
            locals: vec![],
            gp: None,
        }
    }

    fn decode_one(arch: Arch, bytes: &[u8], addr: u64, want_mnem: &str) -> Kind {
        let bin = dummy(arch, true);
        let cs = build(arch, true).unwrap();
        let insns = cs.disasm_count(bytes, addr, 1).unwrap();
        let insn = insns.iter().next().expect("no instruction decoded");
        assert_eq!(insn.mnemonic(), Some(want_mnem));
        classify(&cs, &bin, insn).expect("classify returned None")
    }

    #[test]
    fn aarch64_add_lsl12_scales_imm() {
        let k = decode_one(Arch::Aarch64, &[0xbe, 0x07, 0x40, 0x11], 0, "add");
        match k {
            Kind::AddImm { imm, .. } => assert_eq!(imm, 0x1000),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn aarch64_mov_imm_recovers_const() {
        let k = decode_one(Arch::Aarch64, &[0xe1, 0xff, 0x9f, 0x52], 0, "mov");
        match k {
            Kind::SetConst { dst, val } => {
                assert_eq!(dst, aarch64::ARG_REGS[1], "w1 must alias x1");
                assert_eq!(val, 0xffff)
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn arm_mov_imm_recovers_const() {
        let k = decode_one(Arch::Arm, &[0x07, 0x30, 0xa0, 0xe3], 0, "mov");
        match k {
            Kind::SetConst { val, .. } => assert_eq!(val, 7),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn arm_sub_pc_is_pc_resolved() {
        let addr = 0u64;
        let k = decode_one(Arch::Arm, &[0x04, 0x00, 0x4f, 0xe2], addr, "sub");
        match k {
            Kind::SetConst { val, .. } => assert_eq!(val, addr + 8 - 4),
            other => panic!("got {other:?}"),
        }
    }
}
