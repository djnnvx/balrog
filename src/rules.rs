use crate::graph::{CallSite, Graph, Val};
use crate::load::Binary;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    Exec,
    Ipc,
    Tls,
    Fmt,
    Mem,
    Auth,
    Priv,
    Path,
    Wdt,
}

pub const ORDER: &[Class] = &[
    Class::Exec,
    Class::Ipc,
    Class::Tls,
    Class::Fmt,
    Class::Mem,
    Class::Auth,
    Class::Priv,
    Class::Path,
    Class::Wdt,
];

impl Class {
    fn base(self) -> i32 {
        match self {
            Class::Exec => 50,
            Class::Ipc => 45,
            Class::Tls => 45,
            Class::Fmt => 45,
            Class::Mem => 35,
            Class::Auth => 30,
            Class::Priv => 30,
            Class::Path => 20,
            Class::Wdt => 25,
        }
    }
    pub fn tag(self) -> &'static str {
        match self {
            Class::Exec => "exec",
            Class::Ipc => "ipc",
            Class::Tls => "tls",
            Class::Fmt => "fmt",
            Class::Mem => "mem",
            Class::Auth => "auth",
            Class::Priv => "priv",
            Class::Path => "path",
            Class::Wdt => "wdt",
        }
    }
}

pub const SHELL: &[&str] = &[
    "system",
    "popen",
    "wordexp",
    "twsystem",
    "CsteSystem",
    "bstar_system",
    "___system",
    "doShell",
    "cgi_deal_popen",
    "ExeCmd",
    "ExecShell",
    "exec_shell_popen",
    "exec_shell_popen_str",
    "exec_shell_async",
    "exec_shell_sync",
    "exec_shell_sync2",
    "execFormatCmd",
    "exec_cmd",
    "tp_systemEx",
    "pegaSystem",
    "SLIBCSystem",
    "SLIBCExec",
    "SLIBCExecv",
    "SLIBCPopen",
    "smbrun",
    "smbrun_no_sanitize",
    "smbrunsecret",
    "afprun",
    "popen_utf8",
    "do_system",
    "safe_system",
    "_backexec",
    "execRoot_bg2",
    "ugs_execRoot_shell",
    "prctl_runCommandInShellWithTimeout",
    "safe_popen",
    "qid_sys_execute_update_script",
];
pub const SHELL_ARG1: &[&str] = &["SLIBCExecl"];
pub const EVAL: &[&str] = &[
    "zend_eval_string",
    "zend_eval_stringl",
    "zend_eval_string_ex",
    "PyRun_SimpleString",
    "PyRun_SimpleStringFlags",
    "PyRun_String",
    "PyRun_StringFlags",
    "Py_CompileString",
    "PyEval_EvalCode",
];
pub const PRINTF_EXEC: &[&str] = &["doSystem", "doSystemCmd", "sysprintf", "lxmldbc_system"];
pub const ARGV_EXEC: &[&str] = &[
    "execl",
    "execlp",
    "execle",
    "execv",
    "execvp",
    "execvpe",
    "execve",
    "posix_spawn",
    "posix_spawnp",
    "_eval",
    "_cpu_eval",
    "_cpu_mask_eval",
    "fm_exec",
];
pub const UNBOUNDED: &[(&str, usize, Option<usize>)] = &[
    ("strcpy", 0, None),
    ("strcat", 0, None),
    ("stpcpy", 0, None),
    ("sprintf", 0, Some(1)),
    ("vsprintf", 0, Some(1)),
    ("gets", 0, None),
    ("wcscpy", 0, None),
    ("wcscat", 0, None),
    ("getwd", 0, None),
    ("__sprintf_chk", 0, Some(3)),
    ("__vsprintf_chk", 0, Some(3)),
    ("__strcpy_chk", 0, None),
    ("__strcat_chk", 0, None),
];
pub const SIZED: &[(&str, usize)] = &[
    ("memcpy", 2),
    ("memmove", 2),
    ("strncpy", 2),
    ("strncat", 2),
    ("bcopy", 2),
    ("mempcpy", 2),
    ("stpncpy", 2),
    ("wcsncpy", 2),
    ("wmemcpy", 2),
    ("strlcpy", 2),
    ("strlcat", 2),
    ("__memcpy_chk", 2),
    ("__memmove_chk", 2),
];
pub const FORTIFY_BOUND: &[(&str, usize)] = &[
    ("__sprintf_chk", 2),
    ("__vsprintf_chk", 2),
    ("__strcpy_chk", 2),
    ("__strcat_chk", 2),
    ("__memcpy_chk", 3),
    ("__memmove_chk", 3),
    ("__snprintf_chk", 3),
    ("__vsnprintf_chk", 3),
];
pub const FORMAT: &[(&str, usize)] = &[
    ("printf", 0),
    ("syslog", 1),
    ("fprintf", 1),
    ("vsyslog", 1),
    ("asprintf", 1),
    ("vasprintf", 1),
    ("vprintf", 0),
    ("vfprintf", 1),
    ("snprintf", 2),
    ("vsnprintf", 2),
    ("dprintf", 1),
    ("vdprintf", 1),
    ("g_strdup_printf", 0),
    ("setproctitle", 0),
    ("err", 1),
    ("errx", 1),
    ("verr", 1),
    ("verrx", 1),
    ("warn", 0),
    ("warnx", 0),
    ("vwarn", 0),
    ("vwarnx", 0),
    ("__printf_chk", 1),
    ("__fprintf_chk", 2),
    ("__syslog_chk", 2),
    ("__snprintf_chk", 4),
    ("__vsnprintf_chk", 4),
];
pub const SCANF: &[(&str, usize)] = &[
    ("scanf", 0),
    ("fscanf", 1),
    ("sscanf", 1),
    ("__isoc99_scanf", 0),
    ("__isoc99_fscanf", 1),
    ("__isoc99_sscanf", 1),
    ("vscanf", 0),
    ("vfscanf", 1),
    ("vsscanf", 1),
];
pub const PRIVOPS: &[&str] = &[
    "setuid",
    "setgid",
    "seteuid",
    "setegid",
    "setresuid",
    "setresgid",
    "setreuid",
    "setregid",
    "setfsuid",
    "setfsgid",
    "setgroups",
    "initgroups",
    "umask",
];
pub const TEMPFILE: &[&str] = &["mktemp", "tmpnam", "tmpnam_r", "tempnam"];
pub const WEAK_RANDOM: &[&str] = &[
    "rand",
    "random",
    "rand_r",
    "drand48",
    "lrand48",
    "mrand48",
    "RAND_pseudo_bytes",
];
pub const SEED: &[&str] = &["srand", "srandom", "srand48", "seed48"];
pub const WEAK_CRYPTO: &[&str] = &[
    "MD5",
    "MD5_Init",
    "MD4",
    "SHA1_Init",
    "EVP_md5",
    "EVP_md4",
    "EVP_sha1",
    "mbedtls_md5",
    "mbedtls_sha1",
    "RC4",
    "RC4_set_key",
    "EVP_rc4",
    "EVP_des_cbc",
    "EVP_des_ecb",
    "DES_set_key",
    "DES_ecb_encrypt",
    "EVP_rc2_cbc",
    "EVP_bf_cbc",
    "mbedtls_des_setkey_enc",
    "EVP_aes_128_ecb",
    "EVP_aes_192_ecb",
    "EVP_aes_256_ecb",
];
pub const OLD_TLS: &[&str] = &[
    "SSLv2_method",
    "SSLv3_method",
    "SSLv3_client_method",
    "SSLv3_server_method",
    "TLSv1_method",
    "TLSv1_client_method",
    "TLSv1_1_method",
];
pub const VERIFY_MODE: &[&str] = &[
    "SSL_CTX_set_verify",
    "SSL_set_verify",
    "wolfSSL_CTX_set_verify",
    "wolfSSL_set_verify",
];
pub const DESER: &[&str] = &[
    "soap_get",
    "soap_serve",
    "soap_begin_recv",
    "xmlReadMemory",
    "xmlParseMemory",
    "xmlReadDoc",
    "XML_Parse",
    "d2i_X509",
    "PEM_read_bio_X509",
];
pub const UNTRUSTED_INPUTS: &[&str] = &[
    "recv",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    "read",
    "accept",
    "accept4",
    "getenv",
    "fgets",
    "getline",
    "__getdelim",
    "fread",
    "SSL_read",
    "BIO_read",
    "json_tokener_parse",
    "json_tokener_parse_ex",
    "json_object_from_file",
    "cJSON_Parse",
    "cJSON_ParseWithLength",
    "blobmsg_data",
    "blobmsg_parse",
    "soap_get",
    "websGetVar",
    "websDecodeUrl",
    "FCGX_GetParam",
    "hdf_get_value",
    "config_get",
    "find_val",
    "get_cgi",
    "httpGetEnv",
    "nvram_get",
    "nvram_safe_get",
    "_nvram_get",
    "nvram_get_int",
    "nvram_get_buf",
    "nvram_bufget",
    "nvram_getf",
    "nvram_get_adv",
    "envram_get",
    "envram_getf",
    "apmib_get",
    "artblock_get",
    "artblock_safe_get",
    "acosNvramConfig_get",
    "acos_nvram_get",
    "WAN_ith_CONFIG_GET",
    "uci_lookup_option_string",
    "uci_lookup_option",
    "Uci_Get_Str",
    "GetValue",
    "acosNvramConfig_read",
    "bcm_nvram_get",
    "wlcsm_nvram_get",
    "dni_nvram_get",
    "PTI_nvram_get",
    "CGI_Find_Parameter",
    "getcgivars",
    "getcgi",
    "mg_get_var",
    "webGetVar",
    "websGetVarString",
    "cmsObj_get",
    "cJSON_GetObjectItem",
    "cJSON_GetObjectItemCaseSensitive",
];
pub const PEERCRED: &[&str] = &["getsockopt", "getpeereid", "getpeername", "SO_PEERCRED"];

pub const SANITIZERS: &[&str] = &[
    "canonicalize_file_name",
    "strtol",
    "strtoul",
    "strtoll",
    "strtoull",
    "strtoimax",
    "strtoumax",
    "inet_pton",
    "inet_aton",
    "inet_ntop",
    "fnmatch",
    "g_shell_quote",
    "quote_for_shell",
    "secure_getenv",
];
pub const BOUNDED: &[&str] = &[
    "snprintf",
    "vsnprintf",
    "strlcpy",
    "strlcat",
    "strncpy",
    "strncat",
    "strnlen",
    "stpecpy",
    "strscpy",
    "__snprintf_chk",
    "__strcpy_chk",
    "__memcpy_chk",
];
pub const CT_COMPARE: &[&str] = &[
    "CRYPTO_memcmp",
    "timingsafe_bcmp",
    "timingsafe_memcmp",
    "sodium_memcmp",
    "mbedtls_ct_memcmp",
];
pub const CSPRNG: &[&str] = &[
    "getrandom",
    "arc4random",
    "arc4random_buf",
    "arc4random_uniform",
    "RAND_bytes",
    "mbedtls_ctr_drbg_random",
];
pub const HOSTNAME_CHECK: &[&str] = &[
    "X509_check_host",
    "X509_check_ip",
    "X509_check_ip_asc",
    "SSL_set1_host",
    "SSL_add1_host",
    "X509_VERIFY_PARAM_set1_host",
];
pub const SIGVERIFY: &[&str] = &[
    "RSA_verify",
    "EVP_VerifyFinal",
    "EVP_DigestVerifyFinal",
    "ECDSA_verify",
    "mbedtls_pk_verify",
];

const CURL_VERIFY_OPTS: &[(u64, &str)] = &[
    (64, "CURLOPT_SSL_VERIFYPEER"),
    (81, "CURLOPT_SSL_VERIFYHOST"),
    (248, "CURLOPT_PROXY_SSL_VERIFYPEER"),
    (249, "CURLOPT_PROXY_SSL_VERIFYHOST"),
];
const WRDE_NOCMD: u64 = 4;
const WDIOC_SETOPTIONS: u64 = 0x8004_5704;
const WDIOC_SETOPTIONS_MIPS: u64 = 0x4004_5704;
const WDIOC_SETTIMEOUT: u64 = 0xc004_5706;
const LENGTH_NOT_WRITTEN: &[&str] = &["snprintf", "vsnprintf", "strlcpy", "strlcat"];
const BOUNDS_LENGTH: &[&str] = &["strnlen", "wcsnlen"];
const BOUND_NAMES: &[&str] = &["clamp", "bound", "limit", "min"];
const MBEDTLS_VERIFY_NONE: u64 = 0;
const MBEDTLS_VERIFY_OPTIONAL: u64 = 1;
const PROT_WRITE_EXEC: u64 = 0o6;
const VERIFY_OFF_BONUS: i32 = 30;
const FORTIFY_OFF_BONUS: i32 = 40;
const FORTIFY_OFF_NOTE: &str = "FORTIFY bound is -1: the size check is disabled";
const SHELL_TEMPLATE_BONUS: i32 = 25;
const SHELL_INJECTION_BONUS: i32 = 20;
const SHELL_META: &[&str] = &[">", "|", ";", "`", "$("];
const DIGEST_LENGTHS: &[u64] = &[16, 20, 32, 48, 64];
const MAX_TEMPLATES: usize = 3;
const MAX_SOCKET_PATHS: usize = 2;
const MAX_EXEC_NOTES: usize = 3;
const MAX_CONTEXT_STRINGS: usize = 2;
const MIN_CONTEXT_STRING: usize = 8;
const CGI_VARS: &[&str] = &[
    "QUERY_STRING",
    "REQUEST_URI",
    "CONTENT_LENGTH",
    "HTTP_COOKIE",
];
const SEARCH_PATH_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PATH",
    "IFS",
    "SHELL",
    "PHPRC",
    "PERL5LIB",
    "PYTHONSTARTUP",
];
const PRIV_DROP: &[&str] = &[
    "setuid",
    "setgid",
    "seteuid",
    "setegid",
    "setresuid",
    "setresgid",
    "setreuid",
    "setregid",
    "setfsuid",
    "setfsgid",
];

const CMD_HEADS: &[&str] = &[
    "cp ",
    "mv ",
    "rm ",
    "cat ",
    "tar ",
    "chmod ",
    "chown ",
    "wget ",
    "curl ",
    "tftp ",
    "ping ",
    "traceroute ",
    "iwpriv ",
    "ifconfig ",
    "route ",
    "killall ",
    "iptables ",
    "nvram ",
    "sed ",
    "mount ",
    "umount ",
    "dd ",
    "mtd ",
    "echo ",
    "touch ",
    "mkdir ",
    "insmod ",
    "modprobe ",
    "reboot",
    "sh ",
];

#[derive(Serialize)]
pub struct Finding {
    pub bin: String,
    pub class: Class,
    pub risky_call: String,
    #[serde(serialize_with = "hex")]
    pub site: u64,
    pub func: String,
    pub reach: Option<u32>,
    pub evidence: Vec<Evidence>,
    pub score: i32,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub shell_injection: bool,
}

#[derive(Serialize)]
pub struct Evidence {
    pub points: i32,
    pub text: String,
}

impl Evidence {
    fn new(points: i32, text: impl Into<String>) -> Evidence {
        Evidence {
            points,
            text: text.into(),
        }
    }
}

fn hex<S: serde::Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("{v:#x}"))
}

fn stack_off(k: i64) -> String {
    if k < 0 {
        format!("sp-{:#x}", -k)
    } else {
        format!("sp+{k:#x}")
    }
}

fn looks_shell(s: &str) -> bool {
    if !(s.contains("%s") || s.contains("%d")) {
        return false;
    }
    let meta = [
        " -",
        ";",
        "|",
        "&&",
        "`",
        "$(",
        ">",
        "${IFS}",
        "2>&1",
        "/bin/",
        "/sbin/",
        "/usr/bin/",
    ];
    if meta.iter().any(|m| s.contains(m)) {
        return true;
    }
    let trimmed = s.trim_start();
    CMD_HEADS.iter().any(|head| trimmed.starts_with(head))
}

fn is_neutered(v: u64) -> bool {
    v == u64::MAX || v == 0xffff_ffff
}

fn unbounded_scan(fmt: &str) -> bool {
    let chars: Vec<char> = fmt.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '%' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        if j < chars.len() && chars[j] == '%' {
            i = j + 1;
            continue;
        }
        let suppressed = j < chars.len() && chars[j] == '*';
        if suppressed {
            j += 1;
        }
        let had_width = j < chars.len() && chars[j].is_ascii_digit();
        while j < chars.len() && chars[j].is_ascii_digit() {
            j += 1;
        }
        if j < chars.len() && (chars[j] == 's' || chars[j] == '[') && !had_width && !suppressed {
            return true;
        }
        i = j + 1;
    }
    false
}

// unquoted %s plus a metacharacter only a shell interprets => injection, not an inert arg
fn shell_injection(t: &str) -> bool {
    unbounded_scan(t) && SHELL_META.iter().any(|m| t.contains(m))
}

fn mode_note(m: u64) -> Option<String> {
    if m & 0o4000 != 0 {
        Some(format!("setuid bit in mode {m:#o}"))
    } else if m & 0o2000 != 0 {
        Some(format!("setgid bit in mode {m:#o}"))
    } else if m & 0o2 != 0 {
        Some(format!("world-writable mode {m:#o}"))
    } else {
        None
    }
}

struct Hit {
    class: Class,
    score: i32,
    evidence: Vec<Evidence>,
    shell_injection: bool,
}

impl Hit {
    fn new(class: Class, adjust: i32) -> Hit {
        let score = class.base() + adjust;
        let why = format!("{} base {}, rule {adjust:+}", class.tag(), class.base());
        Hit {
            class,
            score,
            evidence: vec![Evidence::new(score, why)],
            shell_injection: false,
        }
    }
    fn note(&mut self, ev: impl Into<String>) {
        self.evidence.push(Evidence::new(0, ev));
    }
    fn bump(&mut self, delta: i32, ev: impl Into<String>) {
        self.score += delta;
        self.evidence.push(Evidence::new(delta, ev));
    }
}

struct Scan<'a> {
    bin: &'a Binary,
    graph: &'a Graph,
    name: String,
    reach: HashMap<u64, u32>,
    wrappers: HashSet<u64>,
    calls: HashMap<u64, Vec<&'a str>>,
    unix_paths: Vec<String>,
    exec_imports: Vec<&'a str>,
    tokenish: bool,
    no_peercred: bool,
    drops_privilege: bool,
}

fn call_index(g: &Graph) -> HashMap<u64, Vec<&str>> {
    let mut m: HashMap<u64, Vec<&str>> = HashMap::new();
    for s in &g.sites {
        if let Some(n) = s.import.as_deref() {
            m.entry(s.func).or_default().push(n);
        }
    }
    for v in m.values_mut() {
        v.sort_unstable();
        v.dedup();
    }
    m
}

fn is_unix_socket_path(text: &str) -> bool {
    text.contains(".sock") && text.starts_with('/')
}

fn socket_paths(g: &Graph) -> Vec<String> {
    let mut paths: Vec<String> = g
        .strings
        .values()
        .flatten()
        .filter(|text| is_unix_socket_path(text))
        .cloned()
        .collect();
    paths.sort_unstable();
    paths.dedup();
    paths
}

fn is_exec_primitive(import: &str) -> bool {
    SHELL.contains(&import) || PRINTF_EXEC.contains(&import) || ARGV_EXEC.contains(&import)
}

fn exec_imports(bin: &Binary) -> Vec<&str> {
    let mut exec_like: Vec<&str> = bin
        .imports
        .iter()
        .map(String::as_str)
        .filter(|import| is_exec_primitive(import))
        .collect();
    exec_like.sort_unstable();
    exec_like
}

fn names_credential(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("token") || lower.contains("session") || lower.contains("cookie")
}

fn mentions_session_token(g: &Graph) -> bool {
    g.strings
        .values()
        .flatten()
        .any(|text| names_credential(text))
}

impl<'a> Scan<'a> {
    fn new(bin: &'a Binary, graph: &'a Graph) -> Scan<'a> {
        let mut seeds: Vec<&str> = SHELL.to_vec();
        seeds.extend_from_slice(PRINTF_EXEC);
        Scan {
            bin,
            graph,
            name: bin.path.to_string_lossy().into_owned(),
            reach: graph.reach_from(UNTRUSTED_INPUTS),
            wrappers: graph.shell_equivalent(&seeds),
            calls: call_index(graph),
            unix_paths: socket_paths(graph),
            exec_imports: exec_imports(bin),
            tokenish: mentions_session_token(graph),
            no_peercred: !PEERCRED.iter().any(|n| bin.imports.contains(*n)),
            drops_privilege: PRIV_DROP.iter().any(|n| bin.imports.contains(*n)),
        }
    }
    fn has(&self, n: &str) -> bool {
        self.bin.imports.contains(n)
    }
    fn any(&self, v: &[&str]) -> bool {
        v.iter().any(|n| self.has(n))
    }
}

struct Site<'a> {
    scan: &'a Scan<'a>,
    call: &'a CallSite,
    imp: &'a str,
    reach: Option<u32>,
}

impl Site<'_> {
    fn text(&self, n: usize) -> Option<String> {
        match self.call.args.get(n) {
            Some(Some(Val::Num(a))) => self.scan.bin.cstr_at(*a),
            _ => None,
        }
    }
    fn num(&self, n: usize) -> Option<u64> {
        match self.call.args.get(n) {
            Some(Some(Val::Num(v))) => Some(*v),
            _ => None,
        }
    }
    fn stack(&self, n: usize) -> Option<i64> {
        match self.call.args.get(n) {
            Some(Some(Val::Stack(k))) => Some(*k),
            _ => None,
        }
    }
    fn unknown(&self, n: usize) -> bool {
        matches!(self.call.args.get(n), Some(None | Some(Val::Ret(_))))
    }
    fn source(&self, n: usize) -> Option<&str> {
        let Some(Some(Val::Ret(i))) = self.call.args.get(n) else {
            return None;
        };
        let producer = self.scan.graph.sites.get(*i)?;
        producer.import.as_deref().or_else(|| {
            self.scan
                .graph
                .names
                .get(&producer.target)
                .map(String::as_str)
        })
    }
    fn tainted(&self, n: usize) -> bool {
        self.source(n)
            .is_some_and(|f| UNTRUSTED_INPUTS.contains(&f))
    }
    fn visible(&self, n: usize) -> bool {
        n < self.call.args.len()
    }
    fn calls(&self) -> &[&str] {
        self.scan
            .calls
            .get(&self.call.func)
            .map_or(&[], Vec::as_slice)
    }
    fn strings(&self) -> &[String] {
        self.scan
            .graph
            .strings
            .get(&self.call.func)
            .map_or(&[], Vec::as_slice)
    }
    fn has(&self, n: &str) -> bool {
        self.scan.has(n)
    }
    fn any(&self, v: &[&str]) -> bool {
        self.scan.any(v)
    }
}

fn shell(s: &Site) -> Option<Hit> {
    let mut h = Hit::new(Class::Exec, 0);
    let cmd_arg = if SHELL_ARG1.contains(&s.imp) { 1 } else { 0 };
    if PRINTF_EXEC.contains(&s.imp) {
        h.note(format!(
            "{} takes a printf format, not a finished command",
            s.imp
        ));
    }
    match s.text(cmd_arg) {
        Some(t) if t.contains('%') => {
            h.bump(25, format!("command template {t:?}"));
            if shell_injection(&t) {
                h.shell_injection = true;
                h.bump(
                    SHELL_INJECTION_BONUS,
                    "shell injection: unquoted %s with a shell metacharacter",
                );
            }
        }
        Some(t) => h.bump(-30, format!("constant command {t:?}")),
        None if s.num(cmd_arg).is_some() => {
            h.bump(-10, "argument is a constant that is not readable text")
        }
        None => h.bump(15, "argument not a compile-time constant"),
    }
    if s.imp == "wordexp" {
        match s.num(2) {
            Some(f) if f & WRDE_NOCMD != 0 => {
                h.bump(-25, "WRDE_NOCMD set, command substitution refused")
            }
            _ => h.bump(25, "no WRDE_NOCMD: `$(...)` in the input is executed"),
        }
    }
    let templates: Vec<&String> = s.strings().iter().filter(|t| looks_shell(t)).collect();
    for t in templates.iter().take(MAX_TEMPLATES) {
        h.note(format!("command template {t:?}"));
    }
    if !templates.is_empty() {
        h.bump(
            SHELL_TEMPLATE_BONUS,
            "shell-looking strings in the same function",
        );
    }
    Some(h)
}

fn script_eval(s: &Site) -> Option<Hit> {
    let mut h = Hit::new(Class::Exec, -5);
    h.note(format!("{} evaluates a script at runtime", s.imp));
    if s.text(0).is_none() {
        h.bump(20, "the evaluated string is not a compile-time constant");
    }
    Some(h)
}

fn argv_exec(s: &Site) -> Option<Hit> {
    let mut h = Hit::new(Class::Exec, -25);
    h.note("argv exec, metacharacters are inert");
    let path_relative = !matches!(s.text(0), Some(t) if t.starts_with('/'));
    if (s.imp == "execvp" || s.imp == "execlp") && path_relative {
        h.bump(
            25,
            "execvp/execlp resolves through $PATH, not an absolute path",
        );
    }
    Some(h)
}

fn dynamic_load(s: &Site) -> Option<Hit> {
    let mut h = Hit::new(Class::Exec, -20);
    match s.text(0) {
        Some(t) if t.starts_with("/lib") || t.starts_with("/usr/lib") => return None,
        Some(t) => h.note(format!("loads library from {t:?}")),
        None => {
            h.note("library path is not a compile-time constant");
            if !s.calls().contains(&"strchr") {
                h.bump(20, "no strchr guard on the name: no '/' rejection");
            }
        }
    }
    Some(h)
}

fn env_hijack(s: &Site) -> Option<Hit> {
    let name = s.text(0)?;
    if !SEARCH_PATH_VARS.iter().any(|v| name.starts_with(v)) {
        return None;
    }
    let mut h = Hit::new(Class::Exec, -15);
    h.note(format!(
        "sets {name:?}, a search-path primitive for any child"
    ));
    Some(h)
}

fn curl_verify(s: &Site) -> Option<Hit> {
    let (opt, val) = (s.num(1)?, s.num(2)?);
    let (_, name) = CURL_VERIFY_OPTS.iter().find(|(o, _)| *o == opt)?;
    if val != 0 {
        return None;
    }
    let mut h = Hit::new(Class::Tls, VERIFY_OFF_BONUS);
    h.note(format!("{name} set to 0: certificate check disabled"));
    h.note("DNS-hijack MITM works without a valid certificate");
    Some(h)
}

fn verify_mode(s: &Site) -> Option<Hit> {
    if s.num(1) != Some(0) {
        return None;
    }
    let mut h = Hit::new(Class::Tls, VERIFY_OFF_BONUS);
    h.note("verify mode 0 (VERIFY_NONE): peer certificate not checked");
    if s.has("SSL_get_verify_result") {
        h.bump(
            -20,
            "SSL_get_verify_result present, the result may still be inspected",
        );
    }
    Some(h)
}

fn mbedtls_authmode(s: &Site) -> Option<Hit> {
    let (adjust, note) = match s.num(1)? {
        MBEDTLS_VERIFY_NONE => (
            VERIFY_OFF_BONUS,
            "MBEDTLS_SSL_VERIFY_NONE: peer certificate not checked",
        ),
        MBEDTLS_VERIFY_OPTIONAL => (
            0,
            "MBEDTLS_SSL_VERIFY_OPTIONAL: handshake continues on failure",
        ),
        _ => return None,
    };
    let mut h = Hit::new(Class::Tls, adjust);
    h.note(note);
    Some(h)
}

fn unbounded_write(s: &Site, dest: usize, fmt: Option<usize>) -> Option<Hit> {
    let mut h = Hit::new(Class::Mem, 0);
    let stack_dest = s.stack(dest);
    if let Some(k) = stack_dest {
        h.bump(
            20,
            format!("destination is a stack buffer at {}", stack_off(k)),
        );
    }
    let mut conversions = 0;
    if let Some(fmt) = fmt {
        match s.text(fmt) {
            Some(t) => {
                conversions = t.matches("%s").count();
                h.bump(10 * conversions as i32, format!("format {t:?}"));
            }
            None if s.num(fmt).is_some() => h.note("format not a readable literal"),
            None => h.bump(25, "format argument is not a literal (format string bug)"),
        }
    }
    if stack_dest.is_some() && (conversions > 0 || fmt.is_none()) {
        h.bump(
            35,
            "unbounded write of a variable-length value into a fixed stack buffer",
        );
    }
    fortify_note(s, &mut h);
    Some(h)
}

fn fortify_bound(s: &Site) -> Option<u64> {
    let (_, bound) = FORTIFY_BOUND.iter().find(|(n, _)| *n == s.imp)?;
    s.num(*bound)
}

fn fortify_note(s: &Site, h: &mut Hit) {
    match fortify_bound(s) {
        Some(v) if is_neutered(v) => h.bump(FORTIFY_OFF_BONUS, FORTIFY_OFF_NOTE),
        Some(_) => h.bump(-30, "FORTIFY bound is a real constant, overflow aborts"),
        None => {}
    }
}

fn measures_input(s: &Site) -> bool {
    s.calls().contains(&"strlen") || s.calls().contains(&"strspn")
}

fn sized_write(s: &Site, len: usize) -> Option<Hit> {
    if s.num(len) == Some(0) {
        let mut h = Hit::new(Class::Mem, -10);
        h.note("length 0 turns this into a no-op, usually an underflow artefact");
        return Some(h);
    }
    let fortify_disabled = fortify_bound(s).is_some_and(is_neutered);
    let dest = if s.imp == "bcopy" { 1 } else { 0 };
    let stack_dest = s.stack(dest);
    let measures_reachable_input = measures_input(s) && s.reach == Some(0);
    let suspicious =
        stack_dest.is_some() || fortify_disabled || measures_reachable_input || s.tainted(len);
    if !s.unknown(len) || !suspicious {
        return None;
    }
    let mut h = Hit::new(Class::Mem, 0);
    if let Some(k) = stack_dest {
        h.note(format!(
            "non-constant length into a stack buffer at {}",
            stack_off(k)
        ));
    }
    if fortify_disabled {
        h.bump(FORTIFY_OFF_BONUS, FORTIFY_OFF_NOTE);
    }
    if measures_input(s) {
        h.bump(
            20,
            "strlen/strspn in the same function: size may be derived from the \
             input length, not the destination size",
        );
    }
    Some(h)
}

fn stack_alloc(s: &Site) -> Option<Hit> {
    let mut h = Hit::new(Class::Mem, -5);
    match s.num(0) {
        Some(v) => h.bump(-20, format!("alloca of a constant {v:#x}")),
        None => h.note("alloca with a non-constant size: stack clash"),
    }
    Some(h)
}

fn unbounded_read(s: &Site, fmt: usize) -> Option<Hit> {
    if !s.visible(fmt) {
        return None;
    }
    let f = s.text(fmt)?;
    if !unbounded_scan(&f) {
        return None;
    }
    let mut h = Hit::new(Class::Mem, 10);
    h.note(format!("format {f:?} has a %s or %[ with no field width"));
    Some(h)
}

fn format_string(s: &Site, fmt: usize) -> Option<Hit> {
    if !s.visible(fmt) || s.text(fmt).is_some() {
        return None;
    }
    let mut h = Hit::new(Class::Fmt, 0);
    h.note("format argument is not a readable literal");
    Some(h)
}

fn writable_executable(s: &Site) -> Option<Hit> {
    let prot = s.num(2)?;
    if prot & PROT_WRITE_EXEC != PROT_WRITE_EXEC {
        return None;
    }
    let mut h = Hit::new(Class::Mem, 5);
    h.note(format!(
        "prot {prot:#x} is PROT_WRITE|PROT_EXEC: writable and executable at once"
    ));
    Some(h)
}

fn des_crypt(s: &Site) -> Option<Hit> {
    let salt = s.text(1)?;
    if salt.starts_with('$') {
        return None;
    }
    let mut h = Hit::new(Class::Auth, 15);
    h.note(format!(
        "salt {salt:?} selects traditional DES crypt, key truncated to 8 characters"
    ));
    Some(h)
}

fn weak_random(s: &Site) -> Option<Hit> {
    let mut h = Hit::new(Class::Auth, -15);
    h.note(format!("{} is not a CSPRNG", s.imp));
    if !s.any(CSPRNG) {
        h.bump(
            15,
            "no getrandom/arc4random/RAND_bytes anywhere in this binary",
        );
    }
    if s.scan.tokenish {
        h.bump(20, "binary references token/session/cookie strings");
    }
    Some(h)
}

fn predictable_seed(s: &Site) -> Option<Hit> {
    let mut h = Hit::new(Class::Auth, -10);
    match s.num(0) {
        Some(v) => h.note(format!("seeded with the constant {v:#x}")),
        None if s.calls().iter().any(|c| *c == "time" || *c == "getpid") => {
            h.note("seeded from time()/getpid() in the same function")
        }
        None => return None,
    }
    Some(h)
}

fn mac_compare(s: &Site) -> Option<Hit> {
    let len = s.num(2)?;
    if !DIGEST_LENGTHS.contains(&len) {
        return None;
    }
    let beside_mac = s.calls().iter().any(|c| {
        c.contains("HMAC") || c.contains("MD5") || c.contains("SHA") || c.contains("CMAC")
    });
    if !beside_mac {
        return None;
    }
    let mut h = Hit::new(Class::Auth, 0);
    h.note(format!(
        "memcmp of {len} bytes beside a MAC/hash call: not constant time"
    ));
    if s.any(CT_COMPARE) {
        h.bump(-20, "a constant-time compare exists in this binary");
    }
    Some(h)
}

fn privilege_op(s: &Site) -> Option<Hit> {
    let mut h = Hit::new(Class::Priv, -10);
    match (s.imp, s.num(0)) {
        ("umask", Some(mode)) => {
            let masks_world_write = mode != 0 && mode & 0o2 != 0;
            if masks_world_write {
                return None;
            }
            h.bump(
                25,
                format!("umask({mode:#o}) leaves later creations group- or world-writable"),
            );
        }
        (_, Some(v)) => h.note(format!("argument {v:#x}")),
        _ => {}
    }
    if s.imp == "setuid" && !s.has("setgroups") && !s.has("initgroups") {
        h.bump(
            20,
            "no setgroups/initgroups anywhere: setuid keeps the supplementary groups",
        );
    }
    Some(h)
}

fn chroot_escape(s: &Site) -> Option<Hit> {
    if s.calls().contains(&"chdir") {
        return None;
    }
    let mut h = Hit::new(Class::Priv, 20);
    h.note("no chdir in the same function: `../` walks out of the jail");
    Some(h)
}

fn permissive_mode(s: &Site) -> Option<Hit> {
    let note = mode_note(s.num(1)?)?;
    let mut h = Hit::new(Class::Path, 20);
    h.note(note);
    if let Some(p) = s.text(0) {
        h.note(format!("path {p:?}"));
    }
    Some(h)
}

fn temp_file(s: &Site) -> Option<Hit> {
    let mut h = Hit::new(Class::Path, 10);
    h.note(format!(
        "{} names a temp file without creating it atomically",
        s.imp
    ));
    if let Some(p) = s.text(0) {
        h.note(format!("template {p:?}"));
    }
    Some(h)
}

fn unix_listener(s: &Site) -> Option<Hit> {
    let mut h = Hit::new(Class::Ipc, 0);
    for p in s.scan.unix_paths.iter().take(MAX_SOCKET_PATHS) {
        h.note(format!("socket path {p:?}"));
    }
    if s.scan.no_peercred && !s.scan.unix_paths.is_empty() {
        h.bump(30, "no SO_PEERCRED / getpeereid anywhere in this binary");
    }
    let execs = &s.scan.exec_imports;
    for e in execs.iter().take(MAX_EXEC_NOTES) {
        h.note(format!("exec reachable via {e}"));
    }
    if !execs.is_empty() {
        h.bump(20, "this binary can exec");
    }
    if !s.scan.drops_privilege && !execs.is_empty() {
        h.bump(
            15,
            "no setuid/setgid anywhere: this listener never drops privilege",
        );
    }
    Some(h)
}

fn classify(s: &Site) -> Option<Hit> {
    let imp = s.imp;
    if SHELL.contains(&imp) || PRINTF_EXEC.contains(&imp) || SHELL_ARG1.contains(&imp) {
        shell(s)
    } else if EVAL.contains(&imp) {
        script_eval(s)
    } else if ARGV_EXEC.contains(&imp) {
        argv_exec(s)
    } else if imp == "dlopen" {
        dynamic_load(s)
    } else if imp == "setenv" || imp == "putenv" {
        env_hijack(s)
    } else if imp == "curl_easy_setopt" {
        curl_verify(s)
    } else if VERIFY_MODE.contains(&imp) {
        verify_mode(s)
    } else if imp == "mbedtls_ssl_conf_authmode" {
        mbedtls_authmode(s)
    } else if OLD_TLS.contains(&imp) {
        obsolete_tls(s)
    } else if let Some((_, dest, fmt)) = UNBOUNDED.iter().find(|(n, _, _)| *n == imp) {
        unbounded_write(s, *dest, *fmt)
    } else if let Some((_, len)) = SIZED.iter().find(|(n, _)| *n == imp) {
        sized_write(s, *len)
    } else if imp == "alloca" {
        stack_alloc(s)
    } else if let Some((_, fmt)) = SCANF.iter().find(|(n, _)| *n == imp) {
        unbounded_read(s, *fmt)
    } else if let Some((_, fmt)) = FORMAT.iter().find(|(n, _)| *n == imp) {
        format_string(s, *fmt)
    } else if imp == "mmap" || imp == "mprotect" {
        writable_executable(s)
    } else if imp == "crypt" || imp == "crypt_r" {
        des_crypt(s)
    } else if WEAK_CRYPTO.contains(&imp) {
        weak_crypto(s)
    } else if WEAK_RANDOM.contains(&imp) {
        weak_random(s)
    } else if SEED.contains(&imp) {
        predictable_seed(s)
    } else if imp == "memcmp" {
        mac_compare(s)
    } else if DESER.contains(&imp) {
        parses_document(s)
    } else if PRIVOPS.contains(&imp) {
        privilege_op(s)
    } else if imp == "chroot" {
        chroot_escape(s)
    } else if imp == "chmod" || imp == "fchmod" || imp == "mkdir" {
        permissive_mode(s)
    } else if TEMPFILE.contains(&imp) {
        temp_file(s)
    } else if imp == "bind" {
        unix_listener(s)
    } else if imp == "ioctl" {
        watchdog_ioctl(s)
    } else if imp == "write" {
        watchdog_magic_close(s)
    } else {
        None
    }
}

fn watchdog_ioctl(s: &Site) -> Option<Hit> {
    let setoptions = match s.scan.bin.arch {
        crate::arch::Arch::Mips => WDIOC_SETOPTIONS_MIPS,
        _ => WDIOC_SETOPTIONS,
    };
    let (adjust, why) = match s.num(1)? {
        n if n == setoptions => (
            15,
            "WDIOC_SETOPTIONS: WDIOS_DISABLECARD disarms the watchdog",
        ),
        WDIOC_SETTIMEOUT => (5, "WDIOC_SETTIMEOUT: a huge timeout is a disarmed watchdog"),
        _ => return None,
    };
    let mut h = Hit::new(Class::Wdt, adjust);
    h.note(why);
    Some(h)
}

fn watchdog_magic_close(s: &Site) -> Option<Hit> {
    if s.text(1).as_deref() != Some("V") {
        return None;
    }
    let mut h = Hit::new(Class::Wdt, 10);
    h.note("magic close: writing 'V' disarms the watchdog when this fd closes (unless nowayout)");
    Some(h)
}

fn is_bound_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    BOUND_NAMES.iter().any(|k| name.contains(k))
}

fn note_provenance(s: &Site, h: &mut Hit) {
    for n in 0..s.call.args.len() {
        let Some(src) = s.source(n) else { continue };
        if UNTRUSTED_INPUTS.contains(&src) {
            h.bump(15, format!("arg {n} is the raw return of {src}()"));
        } else if LENGTH_NOT_WRITTEN.contains(&src) {
            h.bump(
                15,
                format!(
                    "arg {n} is the return of {src}(): the untruncated length, not bytes written"
                ),
            );
        } else if BOUNDS_LENGTH.contains(&src) || is_bound_name(src) {
            h.bump(-20, format!("arg {n} is bounded by {src}()"));
        }
    }
}

fn note_sanitizers(s: &Site, h: &mut Hit) {
    if matches!(h.class, Class::Ipc | Class::Tls) {
        return;
    }
    let sanitizers_in_function: Vec<&str> = s
        .calls()
        .iter()
        .copied()
        .filter(|name| SANITIZERS.contains(name))
        .collect();
    if sanitizers_in_function.is_empty() {
        return;
    }
    h.bump(
        -20,
        format!(
            "value may be normalized first: {} in the same function",
            sanitizers_in_function.join(", ")
        ),
    );
}

fn note_function_strings(s: &Site, h: &mut Hit) {
    if !matches!(h.class, Class::Mem | Class::Fmt) {
        return;
    }
    let context_strings = s
        .strings()
        .iter()
        .filter(|text| text.len() >= MIN_CONTEXT_STRING)
        .take(MAX_CONTEXT_STRINGS);
    for text in context_strings {
        h.note(format!("function references {text:?}"));
    }
}

fn obsolete_tls(s: &Site) -> Option<Hit> {
    let mut h = Hit::new(Class::Tls, -15);
    h.note(format!("{} pins an obsolete protocol version", s.imp));
    Some(h)
}

fn weak_crypto(s: &Site) -> Option<Hit> {
    let mut h = Hit::new(Class::Auth, -10);
    h.note(format!("{}: broken or ECB-mode primitive", s.imp));
    Some(h)
}

fn parses_document(s: &Site) -> Option<Hit> {
    let mut h = Hit::new(Class::Mem, -10);
    h.note(format!("{} parses an attacker-supplied document", s.imp));
    Some(h)
}

fn is_cgi_variable(text: &str) -> bool {
    text.starts_with("HTTP_") || CGI_VARS.contains(&text)
}

fn note_cgi_variable(s: &Site, h: &mut Hit) {
    let Some(var) = s.strings().iter().find(|text| is_cgi_variable(text)) else {
        return;
    };
    h.bump(
        20,
        format!("reads the CGI variable {var:?}, a raw client header"),
    );
}

fn note_reachability(s: &Site, h: &mut Hit) {
    match s.reach {
        Some(0) => h.bump(40, "same function as a network/env input"),
        Some(d) if d <= 2 => h.bump(25, format!("{d} hop(s) from a network/env input")),
        Some(d) if d <= 5 => h.bump(10, format!("{d} hops from a network/env input")),
        Some(_) => {}
        None if s.scan.graph.addr_taken.contains(&s.call.func) => {
            h.note("address-taken: reached by indirect dispatch, not a direct call")
        }
        None => h.bump(-20, "no path from any network or environment input"),
    }
}

fn adjust(s: &Site, h: &mut Hit) {
    note_sanitizers(s, h);
    note_function_strings(s, h);
    note_cgi_variable(s, h);
    note_provenance(s, h);
    if s.scan.wrappers.contains(&s.call.func) && h.class != Class::Exec {
        h.bump(10, "inside a shell-equivalent wrapper");
    }
    note_reachability(s, h);
}

pub fn analyze(bin: &Binary, graph: &Graph) -> Vec<Finding> {
    let scan = Scan::new(bin, graph);
    let mut out = Vec::new();
    for call in &graph.sites {
        let Some(imp) = call.import.as_deref() else {
            continue;
        };
        let s = Site {
            scan: &scan,
            call,
            imp,
            reach: scan.reach.get(&call.func).copied(),
        };
        let Some(mut h) = classify(&s) else { continue };
        adjust(&s, &mut h);
        out.push(Finding {
            bin: scan.name.clone(),
            class: h.class,
            risky_call: imp.to_string(),
            site: call.site,
            func: graph.func_name(call.func),
            reach: s.reach,
            evidence: h.evidence,
            score: h.score,
            shell_injection: h.shell_injection,
        });
    }
    out.extend(absences(&scan));
    out.sort_by(|a, b| b.score.cmp(&a.score).then(a.site.cmp(&b.site)));
    out
}

struct Absence {
    present: &'static [&'static str],
    absent: &'static [&'static str],
    class: Class,
    risky_call: &'static str,
    score: i32,
    evidence: &'static [&'static str],
}

const SSL_CLIENT: &[&str] = &["SSL_connect", "SSL_CTX_new"];

const ABSENT: &[Absence] = &[
    Absence {
        present: SSL_CLIENT,
        absent: &["SSL_CTX_set_verify", "SSL_set_verify"],
        class: Class::Tls,
        risky_call: "(no verify mode set)",
        score: 75,
        evidence: &[
            "SSL_CTX_new/SSL_connect present but no verify mode is ever configured",
            "OpenSSL's documented default is SSL_VERIFY_NONE, so the handshake completes regardless of the certificate",
        ],
    },
    Absence {
        present: SSL_CLIENT,
        absent: HOSTNAME_CHECK,
        class: Class::Tls,
        risky_call: "(no hostname check)",
        score: 65,
        evidence: &[
            "no X509_check_host / SSL_set1_host / X509_VERIFY_PARAM_set1_host",
            "OpenSSL does not bind a chain to a hostname on its own, so any CA-signed certificate for any name is accepted",
        ],
    },
    Absence {
        present: SSL_CLIENT,
        absent: &["SSL_CTX_load_verify_locations", "SSL_CTX_set_default_verify_paths"],
        class: Class::Tls,
        risky_call: "(no trust store)",
        score: 55,
        evidence: &["no CA store is ever loaded, so chain verification cannot succeed"],
    },
    Absence {
        present: &["mbedtls_ssl_handshake"],
        absent: &["mbedtls_ssl_set_hostname"],
        class: Class::Tls,
        risky_call: "(no mbedtls hostname)",
        score: 65,
        evidence: &["mbedtls_ssl_set_hostname is never called, so CN/SAN matching is skipped"],
    },
    Absence {
        present: &["chroot"],
        absent: &["chdir"],
        class: Class::Priv,
        risky_call: "(chroot without chdir)",
        score: 55,
        evidence: &["chroot imported but chdir is not, so the jail is trivially escaped"],
    },
    Absence {
        present: TEMPFILE,
        absent: &["mkstemp", "mkostemp", "mkdtemp"],
        class: Class::Path,
        risky_call: "(no atomic temp file)",
        score: 45,
        evidence: &["mktemp/tmpnam used and no mkstemp/mkdtemp is linked at all"],
    },
];

fn is_unbounded_write(import: &str) -> bool {
    UNBOUNDED.iter().any(|(name, _, _)| *name == import)
}

fn uses_unbounded_write(g: &Graph) -> bool {
    let mut imports = g.sites.iter().filter_map(|site| site.import.as_deref());
    imports.any(is_unbounded_write)
}

fn names_flash_target(text: &str) -> bool {
    text.contains("sysupgrade") || text.starts_with("mtd ") || text.contains("/dev/mtd")
}

fn flashes_firmware(g: &Graph) -> bool {
    g.strings
        .values()
        .flatten()
        .any(|text| names_flash_target(text))
}

fn absences(sc: &Scan) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut push = |class: Class, risky_call: &str, score: i32, ev: &[&str]| {
        out.push(Finding {
            bin: sc.name.clone(),
            class,
            risky_call: risky_call.to_string(),
            site: 0,
            func: "(whole binary)".into(),
            reach: None,
            evidence: ev
                .iter()
                .enumerate()
                .map(|(i, e)| Evidence::new(if i == 0 { score } else { 0 }, *e))
                .collect(),
            score,
            shell_injection: false,
        })
    };

    let unbounded = uses_unbounded_write(sc.graph);
    if unbounded && !sc.has("__stack_chk_fail") {
        push(
            Class::Mem,
            "(no stack canary)",
            60,
            &[
                "no __stack_chk_fail import: built without -fstack-protector",
                "every stack overflow here reaches the saved return address directly",
            ],
        );
    }
    if unbounded && !sc.any(BOUNDED) {
        push(
            Class::Mem,
            "(no bounded copy)",
            55,
            &[
                "no snprintf/strlcpy/strncpy/strncat anywhere in this binary",
                "every string operation it performs is unbounded",
            ],
        );
    }
    for a in ABSENT {
        if sc.any(a.present) && !sc.any(a.absent) {
            push(a.class, a.risky_call, a.score, a.evidence);
        }
    }
    if flashes_firmware(sc.graph) && (sc.has("system") || sc.has("popen")) && !sc.any(SIGVERIFY) {
        push(
            Class::Exec,
            "(unsigned update path)",
            60,
            &[
                "references mtd/sysupgrade and shells out, but links no RSA/ECDSA verify",
                "check whether the update image is authenticated at all",
            ],
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbounded_scan_flags_widthless_conversions() {
        assert!(unbounded_scan("%s"));
        assert!(unbounded_scan("%[abc]"));
        assert!(unbounded_scan("%d %s"));
    }

    #[test]
    fn unbounded_scan_respects_field_width() {
        assert!(!unbounded_scan("%10s"));
        assert!(!unbounded_scan("%31[^\n]"));
    }

    #[test]
    fn unbounded_scan_ignores_literal_percent() {
        assert!(!unbounded_scan("%%s"));
        assert!(!unbounded_scan("hello world"));
    }

    #[test]
    fn unbounded_scan_ignores_suppressed_star() {
        assert!(!unbounded_scan("%*s"));
        assert!(!unbounded_scan("%*[^\n]"));
    }

    #[test]
    fn looks_shell_detects_command_templates() {
        assert!(looks_shell("cp %s /tmp"));
        assert!(looks_shell("ping %s"));
    }

    #[test]
    fn looks_shell_ignores_benign_formats() {
        assert!(!looks_shell("value=%d"));
        assert!(!looks_shell("hello"));
    }

    #[test]
    fn shell_injection_flags_redirect_and_pipe() {
        assert!(shell_injection("ping %s -s 56 -c 3 >%s"));
        assert!(shell_injection("echo %s | sh"));
        assert!(!shell_injection("value=%d")); // no %s
        assert!(!shell_injection("cp %s /tmp")); // %s but no proving metachar
    }

    #[test]
    fn is_neutered_matches_all_ones() {
        assert!(is_neutered(u64::MAX));
        assert!(is_neutered(0xffff_ffff));
        assert!(!is_neutered(0));
        assert!(!is_neutered(0x10));
    }

    #[test]
    fn stack_off_formats_sign() {
        assert_eq!(stack_off(-16), "sp-0x10");
        assert_eq!(stack_off(32), "sp+0x20");
    }

    #[test]
    fn mode_note_precedence() {
        assert_eq!(
            mode_note(0o4755),
            Some("setuid bit in mode 0o4755".to_string())
        );
        assert_eq!(
            mode_note(0o2755),
            Some("setgid bit in mode 0o2755".to_string())
        );
        assert_eq!(
            mode_note(0o0666),
            Some("world-writable mode 0o666".to_string())
        );
        assert_eq!(mode_note(0o0755), None);
    }

    fn bin(arch: crate::arch::Arch, imports: &[&str]) -> Binary {
        Binary {
            path: "/rootfs/bin/foo".into(),
            data: vec![],
            arch,
            little: true,
            entry: 0,
            segs: vec![],
            got2sym: HashMap::new(),
            undef_stub: vec![],
            imports: imports.iter().map(|s| s.to_string()).collect(),
            exports: vec![],
            locals: vec![],
            gp: None,
        }
    }

    fn graph(sites: Vec<CallSite>, strings: HashMap<u64, Vec<String>>) -> Graph {
        Graph {
            names: HashMap::new(),
            sites,
            edges: HashMap::new(),
            strings,
            addr_taken: HashSet::new(),
        }
    }

    fn site(import: &str, args: Vec<Option<Val>>) -> CallSite {
        CallSite {
            site: 0x1000,
            func: 0,
            import: Some(import.into()),
            target: 0,
            args,
        }
    }

    #[test]
    fn is_exec_primitive_rejects_substrings() {
        assert!(!is_exec_primitive("regexec"));
        assert!(!is_exec_primitive("sqlite3_exec"));
        assert!(!is_exec_primitive("pcre_exec"));
        assert!(is_exec_primitive("system"));
        assert!(is_exec_primitive("qid_sys_execute_update_script"));
    }

    #[test]
    fn finding_bin_carries_full_path_not_basename() {
        let b = bin(crate::arch::Arch::Aarch64, &[]);
        let g = graph(vec![site("system", vec![None])], HashMap::new());
        let findings = analyze(&b, &g);
        assert!(findings.iter().any(|f| f.bin == "/rootfs/bin/foo"));
        assert!(!findings.iter().any(|f| f.bin == "foo"));
    }

    #[test]
    fn bind_tcp_without_socket_evidence_omits_peercred_bonus() {
        let b = bin(crate::arch::Arch::Aarch64, &[]);
        let g = graph(vec![site("bind", vec![])], HashMap::new());
        let findings = analyze(&b, &g);
        assert!(!findings
            .iter()
            .any(|f| f.evidence.iter().any(|e| e.text.contains("no SO_PEERCRED"))));
    }

    #[test]
    fn bind_unix_socket_fires_peercred_bonus() {
        let b = bin(crate::arch::Arch::Aarch64, &[]);
        let mut strings = HashMap::new();
        strings.insert(0x1000u64, vec!["/tmp/foo.sock".to_string()]);
        let g = graph(vec![site("bind", vec![])], strings);
        let findings = analyze(&b, &g);
        assert!(findings
            .iter()
            .any(|f| f.evidence.iter().any(|e| e.text.contains("no SO_PEERCRED"))));
    }

    #[test]
    fn bcopy_destination_is_arg1() {
        let b = bin(crate::arch::Arch::Aarch64, &[]);
        let args = vec![None, Some(Val::Stack(-0x10)), None];
        let g = graph(vec![site("bcopy", args)], HashMap::new());
        let findings = analyze(&b, &g);
        assert!(findings
            .iter()
            .any(|f| f.evidence.iter().any(|e| e.text.contains("stack buffer"))));
    }

    fn at(import: &str, site: u64, args: Vec<Option<Val>>) -> CallSite {
        CallSite {
            site,
            func: 0,
            import: Some(import.into()),
            target: 0,
            args,
        }
    }

    fn scan(b: &Binary, sites: Vec<CallSite>, sink: &str) -> Vec<Finding> {
        let g = graph(sites, HashMap::new());
        analyze(b, &g)
            .into_iter()
            .filter(|f| f.risky_call == sink)
            .collect()
    }

    fn says(f: &Finding, text: &str) -> bool {
        f.evidence.iter().any(|e| e.text.contains(text))
    }

    fn memcpy_len_from(producer: &str) -> Vec<Finding> {
        let b = bin(crate::arch::Arch::Arm, &[]);
        let sites = vec![
            at(producer, 0x1000, vec![]),
            at("memcpy", 0x1010, vec![None, None, Some(Val::Ret(0))]),
        ];
        scan(&b, sites, "memcpy")
    }

    #[test]
    fn breakdown_adds_up_to_score() {
        let b = bin(crate::arch::Arch::Aarch64, &["system", "recv"]);
        let mut strings = HashMap::new();
        strings.insert(
            0u64,
            vec!["ping -c 1 %s".to_string(), "/tmp/x.sock".to_string()],
        );
        let sites = vec![
            at("recv", 0x1000, vec![]),
            at("system", 0x1010, vec![None]),
            at("bind", 0x1020, vec![]),
            at(
                "memcpy",
                0x1030,
                vec![Some(Val::Stack(-0x40)), None, Some(Val::Ret(0))],
            ),
        ];
        let findings = analyze(&b, &graph(sites, strings));
        let calls: HashSet<&str> = findings.iter().map(|f| f.risky_call.as_str()).collect();
        assert_eq!(calls, HashSet::from(["system", "bind", "memcpy"]));
        for f in &findings {
            let sum: i32 = f.evidence.iter().map(|e| e.points).sum();
            assert_eq!(
                sum,
                f.score,
                "{} {:?}",
                f.risky_call,
                f.evidence.iter().map(|e| &e.text).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn heap_memcpy_sized_by_recv_is_reported() {
        let f = memcpy_len_from("recv");
        assert!(says(&f[0], "raw return of recv()"));
    }

    #[test]
    fn heap_memcpy_with_opaque_length_stays_silent() {
        let b = bin(crate::arch::Arch::Arm, &[]);
        assert!(scan(
            &b,
            vec![at("memcpy", 0x1010, vec![None, None, None])],
            "memcpy"
        )
        .is_empty());
    }

    #[test]
    fn provenance_splits_sibling_sinks() {
        let b = bin(crate::arch::Arch::Arm, &[]);
        let sites = vec![
            at("recv", 0x1000, vec![]),
            at("strnlen", 0x1004, vec![]),
            at(
                "memcpy",
                0x1008,
                vec![Some(Val::Stack(-0x40)), None, Some(Val::Ret(0))],
            ),
            at(
                "memcpy",
                0x100c,
                vec![Some(Val::Stack(-0x40)), None, Some(Val::Ret(1))],
            ),
        ];
        let f = scan(&b, sites, "memcpy");
        let score = |site| f.iter().find(|f| f.site == site).unwrap().score;
        assert_eq!(score(0x1008) - score(0x100c), 35);
    }

    #[test]
    fn snprintf_return_as_length_is_up_ranked() {
        let b = bin(crate::arch::Arch::Arm, &[]);
        let sites = vec![
            at("snprintf", 0x1000, vec![]),
            at(
                "memcpy",
                0x1010,
                vec![Some(Val::Stack(-0x40)), None, Some(Val::Ret(0))],
            ),
        ];
        assert!(says(&scan(&b, sites, "memcpy")[0], "untruncated length"));
    }

    #[test]
    fn local_clamp_bounds_the_length() {
        let b = bin(crate::arch::Arch::Arm, &[]);
        let mut clamp = at("x", 0x1000, vec![]);
        clamp.import = None;
        clamp.target = 0x4000;
        let sites = vec![
            clamp,
            at(
                "memcpy",
                0x1010,
                vec![Some(Val::Stack(-0x40)), None, Some(Val::Ret(0))],
            ),
        ];
        let mut g = graph(sites, HashMap::new());
        g.names.insert(0x4000, "len_clamp".into());
        let f: Vec<Finding> = analyze(&b, &g)
            .into_iter()
            .filter(|f| f.risky_call == "memcpy")
            .collect();
        assert!(says(&f[0], "bounded by len_clamp()"));
        assert!(f[0]
            .evidence
            .iter()
            .any(|e| e.text.contains("bounded by len_clamp") && e.points == -20));
    }

    #[test]
    fn watchdog_setoptions_uses_arch_encoding() {
        let arm = bin(crate::arch::Arch::Arm, &[]);
        let mips = bin(crate::arch::Arch::Mips, &[]);
        let ioctl = |req| vec![at("ioctl", 0x1000, vec![None, Some(Val::Num(req)), None])];
        assert_eq!(scan(&arm, ioctl(0x8004_5704), "ioctl")[0].class, Class::Wdt);
        assert_eq!(
            scan(&mips, ioctl(0x4004_5704), "ioctl")[0].class,
            Class::Wdt
        );
        assert!(scan(&arm, ioctl(0x4004_5704), "ioctl").is_empty());
        assert!(scan(&arm, ioctl(0x5401), "ioctl").is_empty());
    }

    #[test]
    fn watchdog_magic_close() {
        let mut b = bin(crate::arch::Arch::Arm, &[]);
        b.data = b"V\0V?\0".to_vec();
        b.segs = vec![crate::load::Seg {
            vaddr: 0x2000,
            off: 0,
            filesz: 5,
            exec: false,
        }];
        let write = |buf| {
            vec![at(
                "write",
                0x1000,
                vec![None, Some(Val::Num(buf)), Some(Val::Num(1))],
            )]
        };
        assert_eq!(scan(&b, write(0x2000), "write")[0].class, Class::Wdt);
        assert!(scan(&b, write(0x2002), "write").is_empty());
    }

    #[test]
    fn watchdog_settimeout_flagged_on_all_arches_and_note_only_sums() {
        let ioctl = |req| vec![at("ioctl", 0x1000, vec![None, Some(Val::Num(req)), None])];
        for arch in [crate::arch::Arch::Arm, crate::arch::Arch::Mips] {
            let b = bin(arch, &[]);
            let f = &scan(&b, ioctl(0xc004_5706), "ioctl")[0];
            assert_eq!(f.class, Class::Wdt);
            assert!(says(f, "SETTIMEOUT"));
            let sum: i32 = f.evidence.iter().map(|e| e.points).sum();
            assert_eq!(sum, f.score);
        }
    }
}
