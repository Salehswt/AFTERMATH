# Scenarios — the intrusions to investigate

This host (or hosts) has already been compromised. Below is what you're told,
same as a real ticket. No spoilers here — answers are in `SOLUTIONS.md`.

For each scenario, produce a short writeup: initial access, what ran,
persistence (if any), and the C2 / exfil destination. Provide the Kibana
queries you used.

> **About the dates.** The intrusions are backdated relative to *your* install,
> not to fixed calendar days, so a briefing saying "about three days ago" means
> three days before you built the lab. Set the Kibana time picker to **Last 30
> days** to see everything, then narrow down from there.

---

## Scenario 01 — Phishing to persistence (Windows victim)
*Only present if you built the optional Windows VM.*

About five days ago, the Windows workstation WKSTN-01 generated unexpected
outbound connections during business hours. A user reported a spreadsheet that
"asked to enable content." Reconstruct what happened: how they got in, what they
ran, how they stayed, and where the traffic went.

*Pivot on the host name (`host.name: wkstn-01`), not an IP — the workstation's
address depends on your hypervisor.*

---

## Scenario 02 — SSH brute force to foothold (Linux victim)
*Default build.*

WKSTN-LNX (172.30.0.50) showed a burst of failed SSH logins about three days
ago, followed by a successful one and outbound HTTP to an unfamiliar host.
Reconstruct: how they got in, which account, and where it called out to.

---

## Scenario 03 — Web attack against DVWA
*Default build.*

About two days ago, the DVWA web app behind the WAF (host :8081) logged a burst
of requests from a single source: scanner-style path probing, then SQL injection
and command injection against the app's parameters. Reconstruct who it was, what
they tried, and what the WAF did. The evidence is in the WAF audit log
(`lab-edge-modsecurity-*`) and the edge sensor — and the real client IP is in
`X-Forwarded-For`, not the WAF's immediate client.

---

## Scenario 04 — Data exfiltration over HTTP (Linux) · *default build*
wkstn-lnx (172.30.0.50) archived system files and pushed a large outbound POST to
an unfamiliar host off-hours. What did they collect, and where did it go?

## Scenario 05 — Rogue account persistence (Linux) · *default build*
A new sudo-capable local account with a service-like name appeared on wkstn-lnx,
unauthorised. How was it created, and from where?

## Scenario 06 — Beaconing implant (Linux) · *default build*
wkstn-lnx makes a short outbound HTTP request to the same host at a fixed
interval, around the clock. Find the callback, the destination, and how it
survives reboots.

## Scenario 07 — SQL injection data theft (DVWA) · *default build*
The DVWA app (host :8081) took a run of SQL-laden requests against one parameter —
boolean, UNION and time-based. Who, which parameter, and did the WAF hold?

## Scenario 08 — Local file inclusion / traversal (DVWA) · *default build*
Requests to DVWA's file-inclusion page tried to walk out of the web root to read
server files. Find the source, the target file, and whether it succeeded.

## Scenario 09 — OS command injection to callback (DVWA) · *default build*
DVWA's "ping" page received shell metacharacters chained onto the IP field,
including one that tried to connect back out. Reconstruct the payloads and the
callback target.

## Scenario 10 — Cross-site scripting campaign (DVWA) · *default build*
Several DVWA inputs received `<script>` payloads — reflected, stored and DOM —
some aimed at stealing cookies. Which sinks, and what was the intent?

## Scenario 11 — Automated web vulnerability scan (edge) · *default build*
The web edge saw a rapid sweep from one source: admin panels, backup files,
`.git`, `.env`, phpinfo, webshell names, plus injection probes. Automated, not
human. What was it hunting for?

## Scenario 12 — Privilege escalation via sudo (Linux) · *default build*
After the jdoe foothold, the account spawned root shells and acted as root. jdoe
shouldn't need that. How did the escalation happen, and what was done with root?

## Scenario 13 — Post-exploitation credential access (Linux) · *default build*
With root on wkstn-lnx, the attacker read the shadow file, SSH keys and shell
history. Which credential stores were read, so you know what to rotate?

## Scenario 14 — Privilege escalation on the workstation (Windows) · *needs the VM*
After the WKSTN-01 foothold, the attacker escalated — a known UAC bypass and a
token-impersonation trick. Reconstruct the techniques from Sysmon.

## Scenario 15 — Credential dumping & discovery (Windows) · *needs the VM*
With elevated access on WKSTN-01, the attacker dumped LSASS and enumerated the
host. What tool did they use, where did the dump land, and what did they look at?

## Scenario 16 - Anti-forensics, log & history wiping (Linux) *default build*
wkstn-lnx (172.30.0.50) looks suspiciously quiet - wtmp and syslog are empty and
root's shell history is gone, yet the box was clearly used. Someone tried to
cover their tracks. Who escalated, and exactly which logs did they wipe? (Hint:
the SIEM still holds what the host no longer does.)

## Scenario 17 - Scheduled-job persistence & C2 beacon (Linux) *default build*
wkstn-lnx keeps calling out to an unfamiliar host at regular intervals, even
after reboots. Something scheduled is beaconing home. How did the attacker make
their access survive a restart, where does the job live on disk, and which host
does it beacon to?

## Scenario 18 - Scheduled-task & service persistence (Windows) *needs the VM*
WKSTN-01 was cleaned once, but access keeps coming back after reboots. The
attacker planted more than one persistence mechanism. Find every way they
arranged to run again - a Run key won't be the whole story this time.

## Scenario 19 - Host discovery & LOLBin proxy execution (Windows) *needs the VM*
Early on WKSTN-01, before stealing anything, the attacker enumerated the network
and ran code through a trusted signed Windows binary to stay under the radar.
Reconstruct their reconnaissance and the living-off-the-land execution from Sysmon.


## Scenario 20 - Full intrusion: foothold to exfil to cover-up (Linux) *default build, HARD*
wkstn-lnx (172.30.0.50) is a mess. Overnight it was scanned and logged into; by
morning there was a strange new "service" account, files had left the building,
and parts of /var/log are blank. Leadership wants the whole story: initial access,
how they became root, what credentials and data were taken, every way back in, and
what they tried to erase. Nothing here is a single smoking gun - chain the evidence
into one timeline and hand over the full IOC set.


## Scenario 21 - API attack on the shop app: SQLi & XSS (Juice Shop) *default build*
The second web app on the edge - the shop at http://localhost:8080 (OWASP Juice
Shop) - took a run of hostile requests against its REST API from a single source:
a login-bypass attempt, UNION-style injection in the product search, and a script
payload. The modern-app sibling of the DVWA cases: a JSON/REST target behind its
own WAF. Which API endpoints were hit, what class was each attack, and did the WAF
catch them? (The shop's WAF logs separately from DVWA's - and from ordinary browser
traffic.)

---

## How to work a scenario
1. Start broad in Discover — filter to the victim host and the time window.
2. Find the earliest suspicious event (initial access).
3. Follow the process/connection chain forward.
4. Identify persistence and the external IP.
5. Pivot on the external IP — did anything else talk to it?
6. Write it up, then check `SOLUTIONS.md`.
