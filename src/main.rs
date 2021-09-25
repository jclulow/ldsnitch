use std::process::Command;
use std::io::{Write, Read};
use anyhow::Result;
use std::sync::{mpsc, Mutex};
use std::os::unix::process::ExitStatusExt;

enum Act {
    WatcherStarted(u32),
    WatcherFail,
    Stopped(u32, String),
    Failed(u32, String),
    ExitStats(u64, u64),
    LdStatus(i32),
    LdFailure(String),
}

struct Log {
    file: Mutex<std::fs::File>,
}

impl Log {
    fn m(&self, msg: &str) {
        let mut f = self.file.lock().unwrap();

        let filemsg = format!("[{}] {}\n", std::process::id(), msg);
        f.write_all(filemsg.as_bytes()).ok();
        f.flush().ok();

        eprintln!("LDSNITCH: {}", msg);
    }

    fn new() -> Result<Log> {
        let file = Mutex::new(std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open("/tmp/ldsnitch.log")?);

        Ok(Log { file, })
    }
}

fn main() -> Result<()> {
    let log = Log::new()?;

    let (tx0, rx) = mpsc::channel::<Act>();

    let tx = tx0.clone();
    std::thread::spawn(move || {
        /*
         * First, start a DTrace script that will watch for the creation of an
         * ld child process and pause it.
         */
        let mut cmd = Command::new("/usr/bin/pfexec")
            .arg("/usr/sbin/dtrace")
            .arg("-w")
            .arg("-q")
            .arg("-n")
            .arg("
                BEGIN
                {
                    printf(\"started\\n\");
                }
                proc:::exec
                /progenyof($1) && args[0] == \"/usr/bin/amd64/ld\"/
                {
                    self->track = args[0];
                }
                proc:::exec-success
                /self->track != 0/
                {
                    raise(SIGSTOP);
                    printf(\"stopped %d %s\\n\", pid, self->track);
                    self->track = 0;
                }
                proc:::exec-failure
                /self->track != 0/
                {
                    printf(\"failed %d %s\\n\", pid, self->track);
                    self->track = 0;
                }
                ")
            .arg(std::process::id().to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap();

        let pid = cmd.id();

        let stdout = cmd.stdout.take().unwrap();
        let mut bytes = stdout.bytes();
        loop {
            let mut eof = false;
            let mut s = String::new();
            loop {
                let b = bytes.next().transpose().unwrap();

                if let Some(b) = b {
                    if b == b'\n' {
                        break;
                    } else if b.is_ascii() {
                        s.push(b as char);
                    }
                } else {
                    eof = true;
                    break;
                }
            }

            if s.starts_with("started") {
                tx.send(Act::WatcherStarted(pid)).unwrap();
            } else {
                let t = s.split(' ').map(|s| s.trim()).collect::<Vec<_>>();
                match t[0] {
                    "stopped" => {
                        tx.send(Act::Stopped(
                            t[1].parse().unwrap(), t[2].to_string()))
                            .unwrap();
                    }
                    "failed" => {
                        tx.send(Act::Failed(
                            t[1].parse().unwrap(), t[2].to_string()))
                            .unwrap();
                    }
                    _ => {}
                }
            }

            if eof {
                break;
            }
        }

        tx.send(Act::WatcherFail).unwrap();
        cmd.kill().ok();
    });

    let mut cleanup = Vec::new();

    let mut ld_pid = None;
    let mut ld_sz = None;
    let mut ld_rss = None;
    let mut ld_code = None;

    fn exit(code: i32, cleanup: &[u32]) {
        for pid in cleanup.iter() {
            Command::new("/usr/bin/pfexec")
                .arg("/usr/bin/kill")
                .arg(pid.to_string())
                .status()
                .ok();
        }
        std::process::exit(code);
    }

    fn check(
        log: &Log,
        sz: &Option<u64>,
        rss: &Option<u64>,
        code: &Option<i32>,
        cleanup: &[u32],
    ) {
        match (sz, rss, code) {
            (Some(sz), Some(rss), Some(code)) => {
                let args = std::env::args()
                    .collect::<Vec<_>>()
                    .join(" ");
                log.m(&format!("ld rss {} sz {} code {} args {}", rss, sz, code,
                    args));
                exit(*code, cleanup);
            }
            _ => {}
        }
    }

    loop {
        match rx.recv().unwrap() {
            Act::WatcherStarted(pid) => {
                log.m(&format!("DTrace watcher started, pid {}", pid));
                cleanup.push(pid);

                let tx = tx0.clone();
                std::thread::spawn(move || {
                    /*
                     * Invoke ld with our intended arguments.
                     */
                    let res = Command::new("/usr/bin/ld")
                        .env_remove("LD_ALTEXEC")
                        .args(std::env::args().skip(1))
                        .status()
                        .unwrap();

                    if let Some(code) = res.code() {
                        tx.send(Act::LdStatus(code)).unwrap();
                    } else {
                        if let Some(sig) = res.signal() {
                            tx.send(Act::LdFailure(format!("signal {}", sig)))
                                .unwrap();
                        } else {
                            tx.send(Act::LdFailure(format!("{:?}", res)))
                                .unwrap();
                        }
                    };
                });
            }
            Act::WatcherFail => {
                log.m("DTrace watcher failed");
                exit(99, &cleanup);
            }
            Act::Stopped(pid, cmd) => {
                if let Some(pid) = &ld_pid {
                    log.m(&format!("second ld started (pid {})?!", pid));
                    exit(99, &cleanup);
                } else {
                    ld_pid = Some(pid);
                }
                log.m(&format!("Stopped {} {}", pid, cmd));

                /*
                 * Start the DTrace process that will use the pid provider on
                 * our specific ld child to catch the final memory usage.
                 */
                let tx = tx0.clone();
                std::thread::spawn(move || {
                    let res = Command::new("/usr/bin/pfexec")
                        .arg("/usr/sbin/dtrace")
                        .arg("-w")
                        .arg("-q")
                        /*
                         * The pid$target::exit:entry probe does not appear to
                         * resolve at the early point at which we are able to
                         * stop the process, but it _does_ then fire later on.
                         * Ignore the missing probe at startup:
                         */
                        .arg("-Z")
                        .arg("-p")
                        .arg(pid.to_string())
                        .arg("-n")
                        .arg("
                            BEGIN
                            {
                                system(\"prun %d\\n\", $target);
                            }
                            pid$target::exit:entry
                            {
                                raise(SIGSTOP);
                                system(\"ps -o osz,rss -p %d; prun %d\",
                                  pid, pid);
                            }
                            ")
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::inherit())
                        .output()
                        .unwrap();

                    let stats = String::from_utf8_lossy(&res.stdout);
                    let x = stats
                        .lines()
                        .nth(1)
                        .unwrap()
                        .trim()
                        .split_whitespace()
                        .map(|n| n.trim().parse::<u64>().unwrap())
                        .collect::<Vec<_>>();

                    let sz = x[0] * 4096;
                    let rss = x[0] * 1024;

                    tx.send(Act::ExitStats(sz, rss)).unwrap();
                });
            }
            Act::ExitStats(sz, rss) => {
                ld_sz = Some(sz);
                ld_rss = Some(rss);
                check(&log, &ld_sz, &ld_rss, &ld_code, &cleanup);
            }
            Act::Failed(pid, cmd) => {
                log.m(&format!("Saw Command That Failed: {} {}", pid, cmd));
            }
            Act::LdStatus(code) => {
                ld_code = Some(code);
                check(&log, &ld_sz, &ld_rss, &ld_code, &cleanup);
            }
            Act::LdFailure(info) => {
                log.m(&format!("Ld Failed Weirdly: {}", info));
                exit(99, &cleanup);
            }
        }
    }
}
