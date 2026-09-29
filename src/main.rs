mod arch;
mod graph;
mod load;
mod rules;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use rayon::prelude::*;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const STUB_PREVIEW: usize = 12;

#[derive(Parser)]
#[command(
    name = "balrog",
    version,
    about = "risky-call and reachability triage for firmware ELF trees"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(about = "rank risky calls in a binary or a whole extracted tree")]
    Scan(ScanArgs),
    #[command(about = "resolve imports and their PLT/lazy-binding stubs")]
    Imports { path: PathBuf },
}

#[derive(Args)]
struct ScanArgs {
    #[arg(
        required = true,
        help = "one or more binaries or trees. Firmware has tiers: rootfs and app bundles are separate trees and both need triaging"
    )]
    paths: Vec<PathBuf>,
    #[arg(short, long)]
    json: bool,
    #[arg(short = 'n', long = "top", default_value_t = 15)]
    per_class_limit: usize,
    #[arg(long = "min", default_value_t = 40, help = "minimum score to report")]
    min_score: i32,
    #[arg(
        long = "per-bin",
        default_value_t = 2,
        help = "at most this many findings per class per binary"
    )]
    max_per_binary: usize,
    #[arg(long = "class", value_enum, help = "only report this class")]
    only_class: Option<rules::Class>,
}

fn is_elf(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    use std::io::Read;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).is_ok() && magic == ELF_MAGIC
}

fn collect_elf_files(root: &Path) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    let mut elf_files = Vec::new();
    let mut unvisited_dirs = vec![root.to_path_buf()];
    while let Some(dir) = unvisited_dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => unvisited_dirs.push(path),
                Ok(kind) if kind.is_file() && is_elf(&path) => elf_files.push(path),
                _ => {}
            }
        }
    }
    elf_files.sort();
    elf_files
}

fn decode(path: &Path) -> Result<(load::Binary, Vec<arch::Ins>, HashMap<u64, String>)> {
    let bin = load::Binary::load(path)?;
    let cs = arch::build(bin.arch, bin.little)?;
    let insns = arch::sweep(&cs, &bin);
    let stubs = arch::resolve_stubs(&bin, &insns);
    Ok((bin, insns, stubs))
}

enum Skipped {
    UnsupportedArch(&'static str),
    Undecodable(anyhow::Error),
}

impl std::fmt::Display for Skipped {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Skipped::UnsupportedArch(arch) => {
                write!(
                    f,
                    "{arch}, balrog only analyzes {}",
                    arch::ANALYZABLE_ARCHES
                )
            }
            Skipped::Undecodable(err) => write!(f, "{err}"),
        }
    }
}

fn scan(path: &Path) -> Result<Vec<rules::Finding>, Skipped> {
    let (bin, insns, stubs) = decode(path).map_err(Skipped::Undecodable)?;
    if !bin.arch.analyzable() {
        return Err(Skipped::UnsupportedArch(bin.arch.name()));
    }
    if insns.is_empty() {
        return Ok(Vec::new());
    }
    let callgraph = graph::Graph::build(&bin, &insns, stubs);
    Ok(rules::analyze(&bin, &callgraph))
}

fn passes_filters(
    finding: &rules::Finding,
    min_score: i32,
    only_class: Option<rules::Class>,
) -> bool {
    finding.score >= min_score && only_class.is_none_or(|class| finding.class == class)
}

fn scan_and_filter(
    binaries: &[PathBuf],
    min_score: i32,
    only_class: Option<rules::Class>,
) -> Vec<rules::Finding> {
    let scan_results: Vec<Result<Vec<rules::Finding>, Skipped>> =
        binaries.par_iter().map(|binary| scan(binary)).collect();
    let mut findings = Vec::new();
    for (path, result) in binaries.iter().zip(scan_results) {
        match result {
            Ok(found) => findings.extend(
                found
                    .into_iter()
                    .filter(|finding| passes_filters(finding, min_score, only_class)),
            ),
            Err(skipped) => eprintln!("warning: {}: {skipped}", path.display()),
        }
    }
    findings
}

fn dedup_templates(findings: &mut Vec<rules::Finding>) {
    let mut seen = HashSet::new();
    findings.retain(|finding| {
        let Some(template) = finding
            .evidence
            .iter()
            .map(|line| &line.text)
            .find(|text| text.starts_with("format ") || text.starts_with("command template"))
            .cloned()
        else {
            return true;
        };
        seen.insert((
            finding.bin.clone(),
            finding.risky_call.clone(),
            finding.class,
            template,
        ))
    });
}

fn cap_per_binary(findings: &mut Vec<rules::Finding>, max_per_binary: usize) {
    let mut kept_so_far = HashMap::new();
    findings.retain(|finding| {
        let kept = kept_so_far
            .entry((finding.bin.clone(), finding.class))
            .or_insert(0usize);
        *kept += 1;
        *kept <= max_per_binary
    });
}

fn by_score(a: &rules::Finding, b: &rules::Finding) -> Ordering {
    b.score
        .cmp(&a.score)
        .then(a.bin.cmp(&b.bin))
        .then(a.site.cmp(&b.site))
        .then(a.risky_call.cmp(&b.risky_call))
}

fn by_class_then_score(a: &rules::Finding, b: &rules::Finding) -> Ordering {
    a.class.cmp(&b.class).then(by_score(a, b))
}

fn rank(mut findings: Vec<rules::Finding>, max_per_binary: usize) -> Vec<rules::Finding> {
    findings.sort_by(by_score);
    dedup_templates(&mut findings);
    cap_per_binary(&mut findings, max_per_binary);
    findings.sort_by(by_class_then_score);
    findings
}

fn print_finding(out: &mut impl Write, finding: &rules::Finding) -> io::Result<()> {
    writeln!(
        out,
        "\n[{:>3}] {}  {}+{:#x}  {}",
        finding.score, finding.risky_call, finding.bin, finding.site, finding.func
    )?;
    for line in &finding.evidence {
        match line.points {
            0 => writeln!(out, "       - {}", line.text)?,
            p => writeln!(out, "       - ({p:+}) {}", line.text)?,
        }
    }
    Ok(())
}

fn report(
    out: &mut impl Write,
    findings: &[rules::Finding],
    elf_count: usize,
    per_class_limit: usize,
) -> io::Result<()> {
    writeln!(out, "{elf_count} ELF, {} leads", findings.len())?;
    for class in rules::ORDER {
        let in_class: Vec<&rules::Finding> = findings
            .iter()
            .filter(|finding| finding.class == *class)
            .collect();
        if in_class.is_empty() {
            continue;
        }
        writeln!(
            out,
            "\n== {} ({} of {})",
            class.tag().to_uppercase(),
            in_class.len().min(per_class_limit),
            in_class.len()
        )?;
        for finding in in_class.iter().take(per_class_limit) {
            print_finding(out, finding)?;
        }
    }
    Ok(())
}

fn ignore_broken_pipe(r: io::Result<()>) -> Result<()> {
    match r {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => Ok(other?),
    }
}

fn run_scan(args: ScanArgs) -> Result<()> {
    let binaries: Vec<PathBuf> = args
        .paths
        .iter()
        .flat_map(|root| collect_elf_files(root))
        .collect();
    let findings = scan_and_filter(&binaries, args.min_score, args.only_class);
    let ranked = rank(findings, args.max_per_binary);

    let mut out = BufWriter::new(io::stdout().lock());
    let written = if args.json {
        writeln!(out, "{}", serde_json::to_string_pretty(&ranked)?)
    } else {
        report(&mut out, &ranked, binaries.len(), args.per_class_limit)
    };
    ignore_broken_pipe(written.and_then(|_| out.flush()))
}

fn run_imports(path: &Path) -> Result<()> {
    let (bin, insns, stubs) = decode(path)?;
    if !bin.arch.analyzable() {
        anyhow::bail!(
            "{} is {}, balrog only analyzes {}",
            path.display(),
            bin.arch.name(),
            arch::ANALYZABLE_ARCHES
        );
    }
    println!(
        "{} {} {} insns={} jmprel={} undef={} stubs={}",
        bin.name(),
        bin.arch.name(),
        if bin.little { "LE" } else { "BE" },
        insns.len(),
        bin.got2sym.len(),
        bin.imports.len(),
        stubs.len()
    );
    let mut sorted_stubs: Vec<_> = stubs.iter().collect();
    sorted_stubs.sort();
    for (addr, name) in sorted_stubs.iter().take(STUB_PREVIEW) {
        println!("  {addr:#x} {name}");
    }
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Scan(args) => run_scan(args),
        Cmd::Imports { path } => run_imports(&path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rules::{Class, Evidence, Finding};

    fn templated(call: &str, template: &str) -> Finding {
        Finding {
            bin: "b".into(),
            class: Class::Exec,
            risky_call: call.into(),
            site: 0x10,
            func: "f".into(),
            reach: None,
            evidence: vec![Evidence {
                points: 0,
                text: format!("command template {template:?}"),
            }],
            score: 100,
        }
    }

    #[test]
    fn dedup_collapses_identical_templates_keeps_distinct() {
        let mut v = vec![
            templated("system", "%s"),
            templated("system", "%s"),
            templated("system", "%d"),
        ];
        dedup_templates(&mut v);
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn dedup_keeps_findings_without_a_template() {
        let mut v = vec![templated("system", "%s"), templated("system", "%s")];
        v[0].evidence.clear();
        v[1].evidence.clear();
        dedup_templates(&mut v);
        assert_eq!(v.len(), 2);
    }
}
