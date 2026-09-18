use crate::arch::Arch;
use anyhow::{bail, Result};
use goblin::elf::Elf;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const SHN_UNDEF: usize = 0;
const MAX_CSTR_LEN: usize = 512;

fn is_text_byte(byte: u8) -> bool {
    matches!(byte, 0x09..=0x0d | 0x20..=0x7e)
}

pub struct Seg {
    pub vaddr: u64,
    pub off: u64,
    pub filesz: u64,
    pub exec: bool,
}

pub struct Binary {
    pub path: PathBuf,
    pub data: Vec<u8>,
    pub arch: Arch,
    pub little: bool,
    pub entry: u64,
    pub segs: Vec<Seg>,
    pub got2sym: HashMap<u64, String>,
    pub undef_stub: Vec<(String, u64)>,
    pub imports: HashSet<String>,
    pub exports: Vec<(String, u64)>,
    pub locals: Vec<(String, u64)>,
    pub gp: Option<u64>,
}

fn machine(elf: &Elf) -> Result<Arch> {
    Ok(match elf.header.e_machine {
        goblin::elf::header::EM_ARM => Arch::Arm,
        goblin::elf::header::EM_AARCH64 => Arch::Aarch64,
        goblin::elf::header::EM_MIPS => Arch::Mips,
        goblin::elf::header::EM_386 => Arch::X86,
        goblin::elf::header::EM_X86_64 => Arch::X86_64,
        m => bail!("unsupported machine {m}"),
    })
}

pub(crate) fn sym_name(tab: &goblin::strtab::Strtab, idx: usize) -> Option<String> {
    tab.get_at(idx)
        .filter(|n| !n.is_empty())
        .map(str::to_string)
}

fn segments(elf: &Elf) -> Vec<Seg> {
    elf.program_headers
        .iter()
        .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
        .map(|p| Seg {
            vaddr: p.p_vaddr,
            off: p.p_offset,
            filesz: p.p_filesz,
            exec: p.is_executable(),
        })
        .collect()
}

fn plt_imports(elf: &Elf) -> HashMap<u64, String> {
    let mut got2sym = HashMap::new();
    for reloc in elf.pltrelocs.iter() {
        let Some(sym) = elf.dynsyms.get(reloc.r_sym) else {
            continue;
        };
        if let Some(name) = sym_name(&elf.dynstrtab, sym.st_name) {
            got2sym.insert(reloc.r_offset, name);
        }
    }
    got2sym
}

#[derive(Default)]
struct DynSyms {
    imports: HashSet<String>,
    undef_stub: Vec<(String, u64)>,
    exports: Vec<(String, u64)>,
}

fn dyn_symbols(elf: &Elf) -> DynSyms {
    let mut syms = DynSyms::default();
    for sym in elf.dynsyms.iter() {
        let Some(name) = sym_name(&elf.dynstrtab, sym.st_name) else {
            continue;
        };
        if sym.st_shndx == SHN_UNDEF {
            if sym.st_value != 0 {
                syms.undef_stub.push((name.clone(), sym.st_value));
            }
            syms.imports.insert(name);
        } else if sym.st_value != 0 && sym.is_function() {
            syms.exports.push((name, sym.st_value));
        }
    }
    syms
}

fn local_funcs(elf: &Elf) -> Vec<(String, u64)> {
    elf.syms
        .iter()
        .filter(|sym| sym.is_function() && sym.st_value != 0)
        .filter_map(|sym| sym_name(&elf.strtab, sym.st_name).map(|name| (name, sym.st_value)))
        .collect()
}

pub(crate) fn dyn_val(elf: &Elf, tag: u64) -> Option<u64> {
    let dynamic = elf.dynamic.as_ref()?;
    let entry = dynamic.dyns.iter().find(|entry| entry.d_tag == tag)?;
    Some(entry.d_val)
}

impl Binary {
    pub fn load(path: &Path) -> Result<Binary> {
        let data = std::fs::read(path)?;
        let elf = Elf::parse(&data)?;
        let arch = machine(&elf)?;
        let little = elf.little_endian;
        let entry = elf.header.e_entry;
        let segs = segments(&elf);
        let mut got2sym = plt_imports(&elf);
        let syms = dyn_symbols(&elf);
        let gp = match arch {
            Arch::Mips => crate::arch::mips::resolve_got(&elf, &mut got2sym),
            _ => None,
        };
        let locals = local_funcs(&elf);
        drop(elf);

        Ok(Binary {
            path: path.to_path_buf(),
            data,
            arch,
            little,
            entry,
            segs,
            got2sym,
            undef_stub: syms.undef_stub,
            imports: syms.imports,
            exports: syms.exports,
            locals,
            gp,
        })
    }

    pub fn read_vaddr(&self, va: u64, len: usize) -> Option<&[u8]> {
        let seg = self
            .segs
            .iter()
            .find(|seg| (seg.vaddr..seg.vaddr + seg.filesz).contains(&va))?;
        let start = (seg.off + (va - seg.vaddr)) as usize;
        if start >= self.data.len() {
            return None;
        }
        let seg_end = (seg.off + seg.filesz) as usize;
        let end = (start + len).min(seg_end).min(self.data.len());
        Some(&self.data[start..end])
    }

    pub fn cstr_at(&self, va: u64) -> Option<String> {
        let window = self.read_vaddr(va, MAX_CSTR_LEN)?;
        let nul = window.iter().position(|&byte| byte == 0)?;
        let text = &window[..nul];
        if text.is_empty() || !text.iter().all(|&byte| is_text_byte(byte)) {
            return None;
        }
        Some(String::from_utf8_lossy(text).into_owned())
    }

    pub fn name(&self) -> String {
        self.path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}
