use crate::arch::{self, Ins, Kind};
use crate::load::Binary;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Val {
    Num(u64),
    Stack(i64),
    Import(u64),
}

pub struct CallSite {
    pub site: u64,
    pub func: u64,
    pub import: Option<String>,
    pub target: u64,
    pub args: Vec<Option<Val>>,
}

pub struct Graph {
    pub names: HashMap<u64, String>,
    pub sites: Vec<CallSite>,
    pub edges: HashMap<u64, HashSet<u64>>,
    pub strings: HashMap<u64, Vec<String>>,
    pub addr_taken: HashSet<u64>,
}

fn function_starts(bin: &Binary, insns: &[Ins], stubs: &HashMap<u64, String>) -> Vec<u64> {
    let decoded: HashSet<u64> = insns.iter().map(|ins| ins.addr).collect();
    let mut starts: HashSet<u64> = HashSet::new();
    if decoded.contains(&bin.entry) {
        starts.insert(bin.entry);
    }
    for (_, addr) in bin.locals.iter().chain(bin.exports.iter()) {
        if decoded.contains(addr) {
            starts.insert(*addr);
        }
    }
    for ins in insns {
        if let Kind::Call(target) = ins.kind {
            if !stubs.contains_key(&target) && decoded.contains(&target) {
                starts.insert(target);
            }
        }
    }
    for addr in stubs.keys() {
        starts.remove(addr);
    }
    let mut starts: Vec<u64> = starts.into_iter().collect();
    starts.sort_unstable();
    starts
}

fn function_names(bin: &Binary) -> HashMap<u64, String> {
    let mut names = HashMap::new();
    for (name, addr) in bin.locals.iter().chain(bin.exports.iter()) {
        names.entry(*addr).or_insert_with(|| name.clone());
    }
    names
}

struct Regs<'a> {
    bin: &'a Binary,
    sp: u16,
    gp: Option<u16>,
    nargs: usize,
    vals: HashMap<u16, Val>,
}

impl<'a> Regs<'a> {
    fn new(bin: &'a Binary) -> Regs<'a> {
        Regs {
            bin,
            sp: arch::sp_reg(bin.arch),
            gp: arch::gp_reg(bin.arch),
            nargs: arch::arg_count(bin.arch),
            vals: HashMap::new(),
        }
    }

    fn enter(&mut self) {
        self.vals.clear();
        self.vals.insert(self.sp, Val::Stack(0));
        self.pin_gp();
    }

    fn pin_gp(&mut self) {
        if let (Some(g), Some(r)) = (self.bin.gp, self.gp) {
            self.vals.insert(r, Val::Num(g));
        }
    }

    fn set(&mut self, dst: u16, v: Option<Val>) -> Option<Val> {
        match v {
            Some(v) => self.vals.insert(dst, v),
            None => self.vals.remove(&dst),
        };
        v
    }

    fn got_slot(&self, base: u16, disp: i64) -> Option<u64> {
        match self.vals.get(&base) {
            Some(Val::Num(addr)) => Some(addr.wrapping_add(disp as u64)),
            _ => None,
        }
    }

    fn step(&mut self, kind: Kind) -> Option<Val> {
        let wrote = match kind {
            Kind::SetConst { dst, val } | Kind::PcVal { dst, val } => {
                self.set(dst, Some(Val::Num(val)))
            }
            Kind::AddImm { dst, base, imm } => {
                let sum = match self.vals.get(&base) {
                    Some(Val::Num(addr)) => Some(Val::Num(addr.wrapping_add(imm as u64))),
                    Some(Val::Stack(offset)) => Some(Val::Stack(offset + imm)),
                    _ => None,
                };
                self.set(dst, sum)
            }
            Kind::Mov { dst, src } => {
                let moved = self.vals.get(&src).copied();
                self.set(dst, moved)
            }
            Kind::Load { dst, base, disp } => {
                let import = self
                    .got_slot(base, disp)
                    .filter(|slot| self.bin.got2sym.contains_key(slot))
                    .map(Val::Import);
                self.set(dst, import)
            }
            _ => None,
        };
        self.pin_gp();
        wrote
    }

    fn arg_value(&self, index: usize) -> Option<Val> {
        let reg = arch::arg_reg(self.bin.arch, index)?;
        let value = self.vals.get(&reg).copied()?;
        if matches!(value, Val::Import(_)) {
            return None;
        }
        Some(value)
    }

    fn args(&self) -> Vec<Option<Val>> {
        (0..self.nargs).map(|index| self.arg_value(index)).collect()
    }

    fn import_at(&self, reg: u16) -> Option<&String> {
        match self.vals.get(&reg) {
            Some(Val::Import(slot)) => self.bin.got2sym.get(slot),
            _ => None,
        }
    }

    fn clobber_args(&mut self) {
        for n in 0..self.nargs {
            if let Some(r) = arch::arg_reg(self.bin.arch, n) {
                self.vals.remove(&r);
            }
        }
    }
}

const MAX_STRINGS_PER_FUNC: usize = 24;
const MIN_STRING_LEN: usize = 4;

fn record_constant(bin: &Binary, func: u64, value: u64, starts: &[u64], out: &mut Graph) {
    if starts.binary_search(&value).is_ok() {
        out.addr_taken.insert(value);
        return;
    }
    let Some(text) = bin.cstr_at(value) else {
        return;
    };
    if text.len() < MIN_STRING_LEN {
        return;
    }
    let strings = out.strings.entry(func).or_default();
    if strings.len() < MAX_STRINGS_PER_FUNC && !strings.contains(&text) {
        strings.push(text);
    }
}

fn first_arg_is_constant(site: &CallSite) -> bool {
    matches!(site.args.first(), Some(Some(Val::Num(_))))
}

impl Graph {
    pub fn build(bin: &Binary, insns: &[Ins], stubs: HashMap<u64, String>) -> Graph {
        let starts = function_starts(bin, insns, &stubs);
        let mut g = Graph {
            names: function_names(bin),
            sites: Vec::new(),
            edges: HashMap::new(),
            strings: HashMap::new(),
            addr_taken: HashSet::new(),
        };
        let mut regs = Regs::new(bin);
        let mut cur_func: u64 = starts.first().copied().unwrap_or(0);

        for ins in insns {
            if starts.binary_search(&ins.addr).is_ok() {
                cur_func = ins.addr;
                regs.enter();
            }
            let wrote = regs.step(ins.kind);
            match ins.kind {
                Kind::Call(target) => {
                    let import = stubs.get(&target).cloned();
                    if import.is_none() && starts.binary_search(&target).is_ok() {
                        g.edges.entry(cur_func).or_default().insert(target);
                    }
                    g.sites.push(CallSite {
                        site: ins.addr,
                        func: cur_func,
                        import,
                        target,
                        args: regs.args(),
                    });
                    regs.clobber_args();
                }
                Kind::CallInd { reg } => {
                    if let Some(name) = regs.import_at(reg).cloned() {
                        g.sites.push(CallSite {
                            site: ins.addr,
                            func: cur_func,
                            import: Some(name),
                            target: 0,
                            args: regs.args(),
                        });
                    }
                    regs.clobber_args();
                }
                _ => {}
            }
            if let Some(Val::Num(value)) = wrote {
                record_constant(bin, cur_func, value, &starts, &mut g);
            }
        }
        g
    }

    pub fn func_name(&self, addr: u64) -> String {
        self.names
            .get(&addr)
            .cloned()
            .unwrap_or_else(|| format!("sub_{addr:x}"))
    }

    pub fn reach_from(&self, inputs: &[&str]) -> HashMap<u64, u32> {
        let mut dist: HashMap<u64, u32> = HashMap::new();
        let mut queue = VecDeque::new();
        for site in &self.sites {
            let Some(import) = &site.import else { continue };
            if inputs.contains(&import.as_str()) {
                dist.insert(site.func, 0);
                queue.push_back(site.func);
            }
        }
        while let Some(func) = queue.pop_front() {
            let depth = dist[&func];
            let Some(callees) = self.edges.get(&func) else {
                continue;
            };
            for &callee in callees {
                if let Entry::Vacant(slot) = dist.entry(callee) {
                    slot.insert(depth + 1);
                    queue.push_back(callee);
                }
            }
        }
        dist
    }

    pub fn shell_equivalent(&self, seeds: &[&str]) -> HashSet<u64> {
        let mut tainted: HashSet<u64> = HashSet::new();
        for site in &self.sites {
            let Some(import) = &site.import else { continue };
            if seeds.contains(&import.as_str()) && !first_arg_is_constant(site) {
                tainted.insert(site.func);
            }
        }
        loop {
            let before = tainted.len();
            for site in &self.sites {
                if site.import.is_none()
                    && tainted.contains(&site.target)
                    && !first_arg_is_constant(site)
                {
                    tainted.insert(site.func);
                }
            }
            if tainted.len() == before {
                break;
            }
        }
        tainted
    }
}
