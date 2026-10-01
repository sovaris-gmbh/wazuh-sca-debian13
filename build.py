import re, sys, yaml, textwrap

SRC = open('original.yml').read()
REF = "wazuh/wazuh v4.14.8 ruleset/sca/debian/cis_debian13.yml"

# ---------------------------------------------------------------- helpers
def block_span(txt, cid):
    m = re.search(r"^  - id: %d\n.*?(?=^  - id: |\Z)" % cid, txt, re.S | re.M)
    if not m: sys.exit(f"check {cid} not found")
    return m.start(), m.end()

def replace_line(txt, cid, old, new, reason, tag="FIX"):
    """Replace one exact rule line inside a check; keep the original as a comment."""
    s, e = block_span(txt, cid)
    blk = txt[s:e]
    old_full = "      - " + old
    if blk.count(old_full) != 1: sys.exit(f"[{cid}] line not unique/found:\n{old}")
    ind = "      "
    comment = "\n".join(ind + "# " + l for l in textwrap.wrap(f"{tag} ({cid}): {reason}", 110))
    newl = "\n".join(ind + "- " + n for n in ([new] if isinstance(new, str) else new))
    rep = f"{comment}\n{ind}# ORIGINAL: - {old}\n{newl}"
    return txt[:s] + blk.replace(old_full, rep) + txt[e:]

def set_condition(txt, cid, new, reason):
    s, e = block_span(txt, cid)
    blk = txt[s:e]
    m = re.search(r"^    condition: (\w+)$", blk, re.M)
    if not m: sys.exit(f"[{cid}] condition not found")
    old = m.group(1)
    comment = "\n".join("    # " + l for l in textwrap.wrap(f"FIX ({cid}): condition '{old}' -> '{new}': {reason}", 112))
    rep = f"{comment}\n    # ORIGINAL: condition: {old}\n    condition: {new}"
    return txt[:s] + blk.replace(m.group(0), rep, 1) + txt[e:]

def add_rule(txt, cid, new, reason):
    """Append a rule at the end of the rules list of a check."""
    s, e = block_span(txt, cid)
    blk = txt[s:e]
    m = re.search(r"^    rules:\n((?:      .*\n)+)", blk, re.M)
    if not m: sys.exit(f"[{cid}] rules not found")
    ind = "      "
    comment = "\n".join(ind + "# " + l for l in textwrap.wrap(f"FIX ({cid}): {reason}", 110))
    rep = m.group(0) + f"{comment}\n{ind}- {new}\n"
    return txt[:s] + blk.replace(m.group(0), rep, 1) + txt[e:]

def disable_check(txt, cid, reason):
    """Comment out a whole check (org exception)."""
    s, e = block_span(txt, cid)
    blk = txt[s:e]
    body, trail = blk.rstrip("\n"), blk[len(blk.rstrip("\n")):]
    # keep trailing section comments (lines starting with '  # ') outside the disabled block
    lines = body.split("\n")
    while lines and (lines[-1].startswith("  # ") or lines[-1].strip() == ""):
        trail = lines.pop() + "\n" + trail
    head = "\n".join("  # " + l for l in textwrap.wrap(f"ORG-EXCEPTION ({cid}): {reason}", 112))
    rep = head + "\n" + "\n".join("  #" + l for l in lines) + "\n" + trail
    return txt[:s] + rep + txt[e:]

# ---------------------------------------------------------------- 1) fixed policy
t = SRC

HEADER = '''# Security Configuration Assessment
# CIS Checks for Debian Linux 13 - COMMUNITY-FIXED EDITION
#
# Derived from: %s
# Copyright (C) 2023, Wazuh Inc. - GNU General Public License v2 (unchanged).
# Modifications (c) 2026 sovaris - published under the same license.
#
# WHY THIS FILE EXISTS
#   The upstream policy contains rules that no correctly configured system can satisfy:
#   contradictory rules under `condition: all`, regular expressions written in PCRE
#   syntax although Wazuh SCA evaluates OS_Regex, and rules that do not match the
#   output format of auditctl(8) on Debian 13. Every change below keeps the ORIGINAL
#   line as a comment directly above the corrected line, prefixed with the check id,
#   so the diff against upstream stays reviewable line by line.
#
# OS_Regex FACTS THIS FILE RELIES ON (see Wazuh documentation, "Regular expression syntax")
#   .   matches a literal dot          \\.  matches ANY character
#   \\w  = A-Z a-z 0-9 @ - _            \\p  = punctuation  ( ) * + , - . : ; < = > ? [ ] ! " ' # $ %% & | { }
#   *  and +  may only follow backslash classes (\\d+ is valid, d+ and [..]+ are not)
#   character classes in brackets ([a-z]) and lookarounds are NOT supported
#   `f:FILE -> !r:X` is true if a LINE of FILE does not match X; a leading `not` inverts the rule
#
# CHANGES (upstream check id -> what and why)
#   33097  chrony checks apply only if chrony is the chosen time daemon (CIS 2.3.2 is conditional)
#   33188  `retry=(d+)` is not valid OS_Regex (no '+' after a bare letter) -> `retry=\\d+`
#   33193-33199  same `(d+)` bug in every pwquality value check; `compare =>` is not an operator;
#          `d:.../pwquality.conf.d/*` is not a directory path; 33195 lacks `compare` before `< 0`,
#          cannot capture negative credits (`ucredit = -1`) and ignores the `minclass = 4` alternative
#   33202/33203  `remember` had to be followed directly by `enforce_for_root`, but pam_pwhistory
#          requires `remember=N`; option order is now irrelevant (independent && segments)
#   33205  `condition: none` on the bare word `remember` fires on the pam_pwhistory line that
#          check 33201 demands; now restricted to pam_unix.so lines (the intent of CIS 5.3.3.4.2)
#   33210  required at least one shadow line with warn>=7 instead of "no line with warn<7"
#   33211  `condition: all` demanded SHA512 AND YESCRYPT in login.defs -> `any`, active lines only
#   33212  required at least one UNLOCKED account with inactive<=45 (impossible on key-only systems)
#          -> "no unlocked account with inactive>45" (empty-field rule unchanged)
#   33217  `condition: all` demanded `passwd -S root` to report L AND P -> `any`
#   33248  `not f: -> !r:` required audit_backlog_limit in EVERY line of /etc/default/grub;
#          now: parameter present in /etc/default/grub or a /etc/default/grub.d drop-in
#   33254  auditctl prints `-C uid!=euid` and `-F auid!=-1` (Debian 13, audit 4.x); both forms accepted
#   33257/33270/33271  file-name regex `.+\\.rules$` is PCRE; OS_Regex form is `\\.+.rules$`
#   33266  auditctl prints watches without trailing slash; `\\\\s+` was a double-escaped literal
#   33267/33268/33269/33270  a `&& -F auid!=unset` segment lacked the `r:` prefix; auditctl form accepted
#   33300  `^[\\w@-]+:x:` uses a bracket class (unsupported) -> `^\\w+:x:` (\\w already covers @ - _)
#
# SITE ADAPTATION (not changed here, intentionally):
#   CIS 4.x lets you choose ONE firewall front end (ufw, nftables or iptables). The checks of the
#   two branches you do not use (4.3.x nftables, 4.4.x iptables when ufw is used) will report
#   "failed"; comment them out in your site copy. Same for 2.3.x if you use systemd-timesyncd
#   (33097 is now conditional). Organisation-specific exceptions belong into a derived file.
#
# References: github.com/wazuh/wazuh/discussions/37243, issues/39339, issues/34505,
#             documentation.wazuh.com -> Ruleset XML syntax -> Regular expression syntax
#
# Based on:
# Center for Internet Security Debian Linux 12 Benchmark v1.1.0 - 09-26-2024  (sic - upstream note)
''' % REF

old_head = SRC[:SRC.index("policy:")]
t = t.replace(old_head, HEADER, 1)
t = t.replace('  id: "cis_debian13"\n  file: "cis_debian13.yml"\n  name: "Center for Internet Security Debian Linux 13 Benchmark"',
              '  id: "cis_debian13_fixed"\n  file: "cis_debian13_fixed.yml"\n  name: "Center for Internet Security Debian Linux 13 Benchmark (community-fixed)"', 1)

# 33097 chrony conditional
t = set_condition(t, 33097, "any", "CIS 2.3.2.x applies only when chrony is the chosen time synchronisation daemon; Debian 13 defaults to systemd-timesyncd (covered by 2.3.3.x). With chrony absent the check is not applicable and must not fail.")
t = add_rule(t, 33097, '"not c:dpkg-query -s chrony -> r:install ok installed"', "escape rule: chrony not installed = not applicable (CIS conditional section)")

# 33188
t = replace_line(t, 33188, r"'f:/etc/pam.d/common-password -> r:password\s*\t*requisite\s*\t*pam_pwquality.so\s*\t*retry=(d+)'",
    r"'f:/etc/pam.d/common-password -> r:password\s*\t*requisite\s*\t*pam_pwquality.so\s*\t*retry=\d+'",
    "`(d+)` is not valid OS_Regex ('+' only after backslash classes); the check could never pass (github.com/wazuh/wazuh/discussions/37243).")

# 33193-33199 generic pwquality fixes
for cid in range(33193, 33200):
    s, e = block_span(t, cid); blk = t[s:e]
    rules = re.findall(r"^      - (.*)$", blk, re.M)
    for r in rules:
        new = r.replace("(d+)", r"(\d+)").replace("compare => ", "compare >= ").replace("pwquality.conf.d/*", "pwquality.conf.d")
        if cid == 33195:
            new = new.replace(r"(\d+) < 0", r"(\d+) compare < 0").replace(r"=\s*\t*(\d+) compare < 0", r"=\s*\t*-(\d+) compare >= 1")
        if new != r:
            t = replace_line(t, cid, r, new, "`(d+)` -> `(\\d+)` (OS_Regex); `=>` is not a comparison operator; `d:` takes a directory path, not a glob" + ("; missing `compare` before `< 0`; credits are NEGATIVE numbers (`ucredit = -1`) and `\\d+` cannot capture the sign - now `-(\\d+) compare >= 1` = 'negative with magnitude >= 1'" if cid == 33195 else ""))
    if cid == 33195:
        t = add_rule(t, 33195, r"'f:/etc/security/pwquality.conf -> !r:^\s*\t*# && n:minclass\s*\t*=\s*\t*(\d+) compare >= 4'", "CIS 5.3.3.2.3 accepts `minclass = 4` as an alternative to the four credit settings; the upstream check tested credits only.")
        t = add_rule(t, 33195, r"'d:/etc/security/pwquality.conf.d -> r:\.+.conf$ -> !r:^\s*\t*# && n:minclass\s*\t*=\s*\t*(\d+) compare >= 4'", "same alternative for /etc/security/pwquality.conf.d drop-ins.")

# 33202 / 33203
t = replace_line(t, 33202, r"'f:/etc/pam.d/common-password -> !r:^\s*\t*# && r:\s*\t*password\s*\t*requisite\s*\t*pam_pwhistory.so\s*\t*remember\s*\t*enforce_for_root'",
    r"'f:/etc/pam.d/common-password -> !r:^\s*\t*# && r:pam_pwhistory.so && r:remember=\d+ && r:enforce_for_root'",
    "pam_pwhistory needs `remember=N`; the original regex demanded `remember` immediately followed by `enforce_for_root`. Segments are matched on the same line independently, so option order no longer matters.")
t = replace_line(t, 33203, r"'f:/etc/pam.d/common-password -> !r:^\s*\t*# && r:\s*\t*password\s*\t*requisite\s*\t*pam_pwhistory.so\s*\t*remember\s*\t*enforce_for_root\s*\t*use_authtok'",
    r"'f:/etc/pam.d/common-password -> !r:^\s*\t*# && r:pam_pwhistory.so && r:remember=\d+ && r:enforce_for_root && r:use_authtok'",
    "same defect as 33202; `use_authtok` checked as an independent segment.")

# 33205
for f in ["common-password", "common-auth", "common-account", "common-session", "common-session-noninteractive"]:
    t = replace_line(t, 33205, f'"f:/etc/pam.d/{f} -> r:remember"', f'"f:/etc/pam.d/{f} -> r:pam_unix.so && r:remember"',
        "CIS 5.3.3.4.2 forbids `remember` on the pam_unix.so line only; the bare word also matched the pam_pwhistory line that check 33201 requires (mutually exclusive checks).")

# 33210
t = replace_line(t, 33210, r"'f:/etc/shadow -> n:^\w+:\S*:\S*:\S*:\S*:(\d+):\S*:\S*:\S* compare >= 7'",
    r"'not f:/etc/shadow -> n:^\w+:\S*:\S*:\S*:\S*:(\d+):\S*:\S*:\S* compare < 7'",
    "the original passed only if SOME line had warn>=7; intent is that NO line has warn<7 (empty fields are covered by the next rule).")

# 33211
t = set_condition(t, 33211, "any", "SHA512 and YESCRYPT are alternatives, not both required.")
t = replace_line(t, 33211, r"'f:/etc/login.defs -> r:ENCRYPT_METHOD\s*\t*SHA512'", r"'f:/etc/login.defs -> !r:^\s*\t*# && r:^ENCRYPT_METHOD\s*\t*SHA512'", "active setting only (unanchored regex also matched comment lines).")
t = replace_line(t, 33211, r"'f:/etc/login.defs -> r:ENCRYPT_METHOD\s*\t*YESCRYPT'", r"'f:/etc/login.defs -> !r:^\s*\t*# && r:^ENCRYPT_METHOD\s*\t*YESCRYPT'", "active setting only (unanchored regex also matched comment lines).")

# 33212
t = replace_line(t, 33212, r"'f:/etc/shadow -> !r:^\w+:!|^\w+:\p: && n:^\w+:\S*:\S*:\S*:\S*:\S*:(\d+):\S*:\S* compare <= 45'",
    r"'not f:/etc/shadow -> !r:^\w+:!|^\w+:\p: && n:^\w+:\S*:\S*:\S*:\S*:\S*:(\d+):\S*:\S* compare > 45'",
    "the original required at least one UNLOCKED account with inactive<=45 - impossible on key-only systems where every account is locked. Intent: no unlocked account with inactive>45.")

# 33217
t = set_condition(t, 33217, "any", "`passwd -S root` reports either L (locked) or P (password set); requiring both is impossible (same defect as github.com/wazuh/wazuh/issues/39339).")

# 33248
t = set_condition(t, 33248, "any", "parameter may live in /etc/default/grub or in a /etc/default/grub.d drop-in (grub-mkconfig sources both).")
t = replace_line(t, 33248, r"'not f:/etc/default/grub -> !r:audit_backlog_limit=\d+'",
    [r"'f:/etc/default/grub -> !r:^\s*\t*# && r:audit_backlog_limit=\d+'", r"'d:/etc/default/grub.d -> r:\.+.cfg$ -> !r:^\s*\t*# && r:audit_backlog_limit=\d+'"],
    "`not f: -> !r:` is true only if EVERY line contains the parameter (comments included) - never true. Now: an active line with the parameter in the main file or a drop-in.")

# 33254 auditctl format
t = replace_line(t, 33254, r'"c:auditctl -l -> r:^-a && r:exit,always|always,exit && r:-F arch=b64|-F arch=b32 && r:-C euid!=uid  && r:-F auid!=unset && r:-S execve && r:-k user_emulation|key=user_emulation"',
    r'"c:auditctl -l -> r:^-a && r:exit,always|always,exit && r:-F arch=b64|-F arch=b32 && r:-C uid!=euid|-C euid!=uid && r:-F auid!=unset|-F auid!=-1|-F auid!=4294967295 && r:-S execve && r:-k user_emulation|key=user_emulation"',
    "auditctl -l (audit 4.x, Debian 13) prints the rule as `-C uid!=euid ... -F auid!=-1`; both spellings are accepted now.")

# 33257 / 33270 / 33271 filename regex + segments
def fix_filename_regex(t, cid):
    s, e = block_span(t, cid); blk = t[s:e]
    for r in re.findall(r"^      - (.*)$", blk, re.M):
        if r".+\.rules$" in r:
            new = r.replace(r".+\.rules$", r"\.+.rules$").replace("&& -F auid!=unset", "&& r:-F auid!=unset").replace("r:-F auid!=-1 &&", "r:-F auid!=-1|-F auid!=unset|-F auid!=4294967295 &&")
            t = replace_line(t, cid, r, new, "`.+\\.rules$` is PCRE; in OS_Regex `.` is a literal dot and `\\.` any character, so the OS_Regex form is `\\.+.rules$` (as used by 43 other checks in this policy)" + ("; a `-F auid!=unset` segment lacked its `r:` prefix" if "&& -F auid" in r else ""))
    return t
for cid in (33257, 33270, 33271): t = fix_filename_regex(t, cid)
t = replace_line(t, 33270, r'"c:auditctl -l -> r:^-a && r:always,exit|exit,always  && r:-S all && r:-F path=/usr/sbin/usermod && r:-F perm=x && r:-F auid>=1000 && r:-F auid!=-1 && r:-F key=usermod"',
    r'"c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-S all && r:-F path=/usr/sbin/usermod && r:-F perm=x && r:-F auid>=1000 && r:-F auid!=-1|-F auid!=unset|-F auid!=4294967295 && r:-F key=usermod"',
    "auditctl output form of auid may be -1, unset or 4294967295 depending on the audit userspace version.")

# 33266 auditctl slash + double escape
t = replace_line(t, 33266, r"'c:auditctl -l -> r:^-w && r:/etc/apparmor/|/etc/apparmor\\s+ && r:-p wa && r:-k MAC-policy|key=MAC-policy'",
    r"'c:auditctl -l -> r:^-w && r:-w /etc/apparmor\s|-w /etc/apparmor/ && r:-p wa && r:-k MAC-policy|key=MAC-policy'",
    "auditctl -l prints watches WITHOUT trailing slash (`-w /etc/apparmor -p wa`); `\\\\s+` in a single-quoted YAML string reached OS_Regex as a literal backslash and never matched.")
t = replace_line(t, 33266, r"'c:auditctl -l -> r:^-w && r:/etc/apparmor.d/|/etc/apparmor.d\\s+ && r:-p wa && r:-k MAC-policy|key=MAC-policy'",
    r"'c:auditctl -l -> r:^-w && r:-w /etc/apparmor.d\s|-w /etc/apparmor.d/ && r:-p wa && r:-k MAC-policy|key=MAC-policy'",
    "same as above for /etc/apparmor.d (`.` is a literal dot in OS_Regex).")

# 33267/33268/33269 missing r: + auditctl variants
for cid, cmd in ((33267, "/usr/bin/chcon"), (33268, "/usr/bin/setfacl"), (33269, "/usr/bin/chacl")):
    t = replace_line(t, cid, rf"'d:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F path={cmd} && r:-F perm=x && r:-F auid>=1000 && -F auid!=unset && r:-k perm_chng'",
        rf"'d:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F path={cmd} && r:-F perm=x && r:-F auid>=1000 && r:-F auid!=unset|-F auid!=-1 && r:-k perm_chng'",
        "the segment `-F auid!=unset` lacked its `r:` prefix and was never evaluated as a regex.")
    t = replace_line(t, cid, rf'"c:auditctl -l -> r:^-a && r:always,exit|exit,always  && r:-S all && r:-F path={cmd} && r:-F perm=x && r:-F auid>=1000 && r:-F auid!=-1 && r:-F key=perm_chng"',
        rf'"c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-S all && r:-F path={cmd} && r:-F perm=x && r:-F auid>=1000 && r:-F auid!=-1|-F auid!=unset|-F auid!=4294967295 && r:-F key=perm_chng"',
        "auditctl output form of auid may be -1, unset or 4294967295 depending on the audit userspace version.")

# 33300
t = replace_line(t, 33300, r"'not f:/etc/passwd -> !r:^[\w@-]+:x:'", r"'not f:/etc/passwd -> !r:^\w+:x:'",
    "bracket character classes are not supported by OS_Regex; `\\w` already includes @ - _ so the intent is preserved (github.com/wazuh/wazuh/discussions/37243).")

FIXED = t
open('cis_debian13_fixed.yml', 'w').write(FIXED)

# ---------------------------------------------------------------- validation
pol = yaml.safe_load(open('cis_debian13_fixed.yml'))
ids = [c['id'] for c in pol['checks']]
assert len(ids) == len(set(ids)) == 207, "check set must stay identical to upstream"
bad = re.compile(r"\[|\{\d|\(\?|(?<!\\)[A-Za-z0-9)\]][+*]|compare =>")
hits = [(c['id'], r) for c in pol['checks'] for r in c.get('rules', []) if any(bad.search(q.split(':',1)[1] if ':' in q else q) for q in re.split(r"\s*&&\s*", r.split('->',1)[-1]))]
print(f"cis_debian13_fixed.yml: {len(ids)} checks, OS_Regex-suspect rules: {len(hits)}")
