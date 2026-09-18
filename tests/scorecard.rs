use std::process::Command;

fn run(bin: &str, class: &str) -> String {
    let exe = env!("CARGO_BIN_EXE_balrog");
    let out = Command::new(exe)
        .args([
            "scan",
            bin,
            "--class",
            class,
            "--min=0",
            "--per-bin=99",
            "-n",
            "10",
        ])
        .output()
        .expect("balrog runs");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn expect(var: &str, class: &str, proofs: &[&str]) {
    let Ok(path) = std::env::var(var) else {
        eprintln!("skip {var}: not set");
        return;
    };
    let out = run(&path, class);
    for p in proofs {
        assert!(out.contains(p), "{var}: missing evidence {p:?} in:\n{out}");
    }
}

#[test]
fn proftpd_efmlog_stack_overflow() {
    expect(
        "BALROG_PROFTPD",
        "mem",
        &[
            "sprintf",
            "\"%s(%s)\"",
            "destination is a stack buffer",
            "unbounded write",
        ],
    );
}

#[test]
fn easydisc_udp_command_injection() {
    expect(
        "BALROG_EASYDISC",
        "exec",
        &[
            "system",
            "dev_sta set -m esw_networkId_merge",
            "same function as a network/env input",
        ],
    );
}

#[test]
fn porter_unauthenticated_root_socket() {
    expect(
        "BALROG_PORTER",
        "ipc",
        &[
            "bind",
            "/tmp/porter.sock",
            "no SO_PEERCRED",
            "qid_sys_execute_update_script",
        ],
    );
}
