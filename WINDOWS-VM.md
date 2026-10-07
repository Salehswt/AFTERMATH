# Optional: the Windows victim VM (one-time setup)

The Docker lab needs none of this. Do the steps below ONLY if you want a real
Windows workstation for higher-fidelity DFIR (Sysmon, event logs, macros).

Requirement: run this on a **bare-metal** machine (not inside another VM),
with VMware Workstation. VirtualBox works too, but pick one.

## Step 1 - run the preflight check
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-windows.ps1
```
It tells you exactly what's missing. Fix each [FAIL], re-run until all PASS.

## Step 2 - the three VMware prerequisites (install once, by hand)
The check will flag any you're missing:
1. **VMware Workstation** - you have it.
2. **Vagrant** - `winget install HashiCorp.Vagrant` (reopen PowerShell after).
3. **vagrant-vmware-desktop plugin** - `vagrant plugin install vagrant-vmware-desktop`
4. **Vagrant VMware Utility** - download + install from
   https://developer.hashicorp.com/vagrant/install/vmware
   (this one has no silent installer, so it's manual - that's normal).

## Step 3 - build it
Once the preflight is all green:
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -WithWindowsVictim
```
The Windows box downloads (~10 GB, first run only) and provisions itself:
Sysmon, Elastic Agent, weak config, Atomic Red Team. It enrolls into the same
Kibana as the Linux victim, so you can hunt across both.

## Why the manual prerequisites?
VMware's Vagrant integration (plugin + utility) can't be silently automated the
way Docker can. Installing them once by hand - and confirming with the preflight
- is what makes the actual VM build reliable instead of failing halfway. This is
the same approach DetectionLab and other pro ranges use.

## How the VM reaches the SIEM
The VM is **not** on the containers' Docker network (172.30.0.0/24) — that
subnet lives inside Docker/WSL2 and a VM can't route to it. Instead the VM sits
on its own **host-only network** (192.168.56.0/24, VirtualBox's default) at
`192.168.56.20`, and reaches Elasticsearch/Fleet **through the host**, which
publishes ports 9200/8220.

The lab runs Elastic's **Basic (free) license**, which does *not* allow a
per-policy Elasticsearch output, and an Agent output with two hosts
*load-balances* (so a host only the VM can reach would break the containers). So
the whole lab keeps **one** shared output that addresses Elasticsearch and Fleet
by their in-Docker hostnames (`elasticsearch:9200`, `fleet-server:8220`).

The VM can't resolve those Docker names, so its provisioner adds **hosts-file
entries** mapping `elasticsearch` and `fleet-server` to the host, where Docker
publishes 9200/8220. Same hostnames, resolved differently per network —
containers via Docker DNS, the VM via its hosts file — so the VM reaches the
*same* endpoints the containers use, with zero change to the shared output.

**Which host IP** (`LAB_HOST_IP`) — the installer picks it by provider:

| Provider | Guest adapter for the host-only net | Host IP used |
|---|---|---|
| **VirtualBox** | configured in the guest → `192.168.56.20` works | `192.168.56.1` (host-only default) |
| **VMware (Windows host)** | *not* configured in the guest (a known VMware limitation) | the **VMnet8/NAT** host IP, auto-detected (e.g. `192.168.37.1`) |

On VMware+Windows the host-only adapter inside the guest is left unconfigured,
so the VM reaches the host over the **NAT** network instead — the installer
detects the `VMware Network Adapter VMnet8` IP automatically. Override either
with `$env:LAB_HOST_IP` if yours differs.

The installer then creates a plain `windows-victim` policy and adds the
**Windows** integration (Sysmon/Operational + PowerShell/Operational), which is
what makes scenario 01's `winlog.event_id:1/3/13` and `4104` detections light up;
the System integration alone would miss them.

If your host's IP on the host-only adapter is different (custom range, or
VMware), set it before building:
```powershell
$env:LAB_HOST_IP = "192.168.x.1"   # PowerShell
```
```bash
LAB_HOST_IP=192.168.x.1 ./install.sh --windows   # Linux/macOS
```
The provisioner runs a reachability check first; if the VM can't hit
`LAB_HOST_IP:8220` it stops with instructions instead of half-enrolling. To
retry just the agent step after fixing it:
```powershell
cd victim ; vagrant provision --provision-with 04-agent
```

Because the Windows victim is off the attack network, its scenario-01 telemetry
is **host-based** (Sysmon, event logs) rather than network-sensor data — which
is how you'd investigate a real workstation. The C2 IP still appears as the
*destination* of the beacon in Sysmon event id 3 even though the packet doesn't
traverse the lab network.

## Notes
- The Windows eval image expires after ~90 days; rebuild with
  `cd victim ; vagrant destroy -f ; vagrant up`.
- If VMware and Hyper-V/WSL2 clash, update to VMware Workstation 15.5.5+ which
  runs alongside Hyper-V.
- The host firewall must allow the VM to reach 9200/8220 on the host-only
  adapter. Docker publishes them on 0.0.0.0 by default, so no Docker change is
  needed — but a strict host firewall can still block the host-only subnet.
