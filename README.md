# Wazuh SCA policy for Debian 13 – community-fixed edition

`cis_debian13_fixed.yml` is `ruleset/sca/debian/cis_debian13.yml` from wazuh/wazuh **v4.14.8**
with the rules corrected that no correctly configured Debian 13 system can satisfy. Every change
keeps the upstream line as a comment (`# ORIGINAL: …`) directly above the corrected line, tagged
with the check id and the reason – the file header lists all of them.

* `original.yml` – upstream file, byte-identical (for `diff`)
* `build.py` – produces `cis_debian13_fixed.yml` from `original.yml`; every edit is explicit and
  validated (YAML parses, 207 checks, no unsupported regex construct left)
* `cis_debian13_fixed.yml` – the result

## Deploy – read this first
SCA does **not execute commands** from policies that arrive via the manager's shared folder
(`etc/shared/`) unless the agent sets the internal option `sca.remote_commands=1`. Most CIS checks
use commands (`sshd -T`, `dpkg-query`, `systemctl`, `auditctl`, `stat`), so a shared policy without
that option reports them as "not applicable". Two ways out:

1. **Local file AND local configuration (recommended):** deliver the policy with your
   configuration management to a local path on every agent, e.g.
   `/var/ossec/etc/sca/cis_debian13_fixed.yml` (root:wazuh 0640), and list it in the agent's own
   `ossec.conf` `<sca><policies>` block. What counts is the *origin of the configuration*, not the
   file location: a policy entry that arrives through the centralized `agent.conf` is treated as
   remote even if it points to a local file, and its commands are ignored. With local
   configuration no remote-command trust is granted to the manager – relevant when the manager
   belongs to another trust domain than the agents.
2. **Shared folder / `agent.conf` + `sca.remote_commands=1`** in
   `/var/ossec/etc/local_internal_options.conf` on every agent. Simpler distribution, but a
   compromised manager could then run arbitrary commands as root on all agents via a policy.
**The stock policy must be disabled with its absolute path** – this file keeps the upstream
check ids on purpose (comparable results, minimal diff), and the SCA module skips a policy
whose ids already exist in a loaded one (`Found duplicated check ID … Skipping it`).
A bare file name in `enabled="no"` is resolved relative to `/var/ossec/` and does not match.

Local variant – inside the existing `<sca>` block of the agent's `ossec.conf`:

```xml
<policies>
  <policy enabled="no">/var/ossec/ruleset/sca/cis_debian13.yml</policy>
  <policy>/var/ossec/etc/sca/cis_debian13_fixed.yml</policy>
</policies>
```

Verify on an agent: `grep sca /var/ossec/logs/ossec.log` must show
`Loaded policy '/var/ossec/etc/sca/cis_debian13_fixed.yml'`, no "duplicated check ID" warning and no
"Ignoring check … sca.remote_commands is disabled" line (that line means the policy was configured remotely).

## Site adaptation
CIS 4.x lets you choose one firewall front end – comment out the branches you do not use in a
derived copy (see `policy.id`/`file` metadata; keep ids unique). Organisation-specific exceptions
belong into such a derived file, never into this one.

## Why not a pull request upstream?
It is – this repository is the review-ready intermediate. Related upstream threads:
wazuh/wazuh discussions #37243, issues #39339, #34505.

License: GNU GPL v2, as upstream.
