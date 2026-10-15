#!/usr/bin/env python
"""One read-only after-move verdict over exported SQL Server catalog rows.

Reads CSV exports of catalog views taken from the destination instance after a
geodatabase was restored there, and says what the move left broken: database
users whose login did not come along, versions owned by such users, jobs owned
by a login that does not exist, four-part and cross-database names that no
longer resolve, linked servers on a provider the target no longer ships, and a
grant on a table that its versioned view (_evw) never received.

It copies nothing, repairs nothing and opens no connection. Every verdict is
computed from the rows in the files, never from a function that asks the
server or Windows (SUSER_SID can answer from Windows, so it can call an
orphaned user fine).

The existing tools do the moving and the repair well. dbatools copies logins
and jobs and linked servers and remaps orphaned users. This tool is the check
you run after it, or after a manual restore: one verdict, from rows you can
keep, that knows the geodatabase cases a general tool does not.

    python sqlmove.py --self-test
    python sqlmove.py EXPORT_DIR
    python sqlmove.py EXPORT_DIR --target-major 16
    python sqlmove.py EXPORT_DIR --out findings.csv --apply

EXPORT_DIR holds one UTF-8 CSV per catalog view, named as the README lists
them. A rule whose files are absent is reported as skipped, and a skipped rule
checked nothing. Nothing is written without --apply.

Exit codes: 0 at least one row was examined and no rule failed, 1 at least one
rule failed, 2 a file could not be read or written, 3 an export was refused
(a column missing, a SID that is not hex), 4 nothing was examined, 5 no rule
failed but a rule was skipped (only with --require-all), 64 usage error, 70 an
unexpected crash, which is never a finding.
"""

from __future__ import print_function

import argparse
import ast
import collections
import contextlib
import csv
import importlib.util
import io
import os
import re
import shutil
import sys
import tempfile
import traceback

# =============================================================================
# CONFIGURATION. Deliberately not flags. Change here, not at the call site.
# =============================================================================

FAIL = "FAIL"
WARN = "WARN"

# Columns each export must have, by file stem. Extra columns are ignored and
# never printed. A header is matched ignoring case and surrounding spaces.
FILES = {
    "server_principals": ("name", "sid", "type"),
    "database_principals": ("name", "sid", "authentication_type_desc"),
    "database_permissions": ("class_desc", "schema_name", "object_name",
                             "column_name", "grantee", "permission_name",
                             "state_desc"),
    "objects": ("schema_name", "object_name", "type"),
    "jobs": ("name", "owner_sid"),
    "source_jobs": ("name", "owner_sid"),
    "source_server_principals": ("name", "sid", "type"),
    "linked_servers": ("server_id", "name", "provider",
                       "is_data_access_enabled"),
    "dependencies": ("referencing_name", "referenced_server_name",
                     "referenced_database_name", "referenced_schema_name",
                     "referenced_entity_name"),
    "databases": ("name",),
    "versions": ("name", "owner"),
}

SID_COLUMNS = ("sid", "owner_sid")

# SYS and INFORMATION_SCHEMA in sys.database_principals have a NULL SID. Every
# other SID column must hold a SID, and an export that does not is refused.
OPTIONAL_SIDS = (("database_principals", "sid"),)

# Columns that can hold a SQL NULL. sqlcmd and some other clients write a NULL
# as the text NULL, which would read as a server, a database or a column named
# NULL. In these columns only, the text NULL in any case is read as empty.
NULLABLE_COLUMNS = {
    "database_permissions": ("schema_name", "object_name", "column_name"),
    "dependencies": ("referenced_server_name", "referenced_database_name",
                     "referenced_schema_name", "referenced_entity_name"),
    "linked_servers": ("provider",),
    "versions": ("owner",),
    "database_principals": ("sid",),
}
INT_COLUMNS = ("server_id",)
BOOL_COLUMNS = ("is_data_access_enabled",)

# A login the source instance owns for itself. These are never carried, so
# their absence on the destination says nothing about the move.
SYSTEM_LOGIN_PREFIXES = ("##", "nt service\\", "nt authority\\")

# Login types worth carrying: SQL login, Windows login, Windows group.
CARRIED_LOGIN_TYPES = ("S", "U", "G")

# The data permissions a geodatabase editor holds, plus CONTROL, which implies
# them. A versioned view needs each of them that the table has.
TABLE_PERMISSIONS = ("SELECT", "INSERT", "UPDATE", "DELETE", "CONTROL")

EVW_SUFFIX = "_evw"

# The first SQL Server version that does not ship SQL Server Native Client.
NO_NATIVE_CLIENT_MAJOR = 16


Finding = collections.namedtuple("Finding", "rule severity subject detail")


class InputError(ValueError):
    """An export that cannot be trusted, so nothing is checked."""


class Report(object):
    """What a run found, which rules ran, and which were skipped."""

    def __init__(self, findings, ran, skipped, files):
        self.findings = findings
        self.ran = ran              # [(rule, examined, fails, warns)]
        self.skipped = skipped      # [(rule, reason)]
        self.files = files

    @property
    def fails(self):
        return sum(1 for f in self.findings if f.severity == FAIL)

    @property
    def warns(self):
        return sum(1 for f in self.findings if f.severity == WARN)

    @property
    def examined(self):
        return sum(row[1] for row in self.ran)


# =============================================================================
# THE DECISION CORE. Pure functions over lists of dicts. No file, no network.
# =============================================================================

def fold(text):
    """Compare names the way a case-insensitive SQL Server collation does."""
    return text.casefold()


def parse_sid(text):
    """A SID exported as hex, with or without 0x, as lower-case hex digits."""
    match = re.match(r"^(?:0[xX])?([0-9a-fA-F]+)$", text.strip())
    if not match or len(match.group(1)) % 2 or len(match.group(1)) > 170:
        raise ValueError("%r is not a SID in hex (varbinary(85), at most 85 "
                         "bytes)" % text.strip()[:24])
    return match.group(1).lower()


def parse_bool(text):
    value = text.strip().casefold()
    if value in ("1", "true"):
        return True
    if value in ("0", "false"):
        return False
    raise ValueError("%r is not 0, 1, true or false" % text.strip()[:24])


def _four_part(row):
    parts = [row["referenced_server_name"], row["referenced_database_name"],
             row["referenced_schema_name"], row["referenced_entity_name"]]
    while len(parts) > 1 and not parts[0]:
        parts.pop(0)
    return ".".join("[%s]" % p if p else "" for p in parts)


def _create_login_advice(name, sid):
    """How to make a login that a database user or a job can map to.

    CREATE LOGIN takes SID = only for SQL Server logins. A Windows login
    (DOMAIN\\name) takes its SID from the account, so FROM WINDOWS is the way.
    Neither export holds the principal type for a database user, so a
    backslash in the name tells the two apart.
    """
    if "\\" in name:
        return ("Create the login with CREATE LOGIN [%s] FROM WINDOWS (a "
                "Windows login takes its SID from the account, and the SID "
                "option is for SQL Server logins only)" % name)
    return "Create the login with its SID (CREATE LOGIN ... SID = 0x%s)" % sid


def orphans(data):
    """Database users whose SID is in no login, as (user, same-name SID).

    Uses the documented detection: an INSTANCE-authenticated database user
    whose SID is not in sys.server_principals. The same-name SID is the SID of
    a login that has the user's name, or None.
    """
    sids = set(r["sid"] for r in data["server_principals"])
    by_name = dict((fold(r["name"]), r["sid"])
                   for r in data["server_principals"])
    found = []
    for user in data["database_principals"]:
        if user["authentication_type_desc"].strip().upper() != "INSTANCE":
            continue
        if user["sid"] not in sids:
            found.append((user, by_name.get(fold(user["name"]))))
    return found


def check_orphans(data, target_major):
    findings = []
    examined = 0
    for user in data["database_principals"]:
        if user["authentication_type_desc"].strip().upper() == "INSTANCE":
            examined += 1
    for user, same_name in orphans(data):
        if same_name is None:
            detail = ("no login has this SID or this name. %s, or confirm "
                      "the user is stale."
                      % _create_login_advice(user["name"], user["sid"]))
        else:
            detail = ("a login of the same name exists with a different SID "
                      "(0x%s against the user's 0x%s). A name match is not a "
                      "SID match: a person decides whether ALTER USER ... WITH "
                      "LOGIN is right." % (same_name, user["sid"]))
        if fold(user["name"]) == "sde":
            detail += (" In an sde-schema geodatabase this is the "
                       "geodatabase administrator. Esri lets only a "
                       "version's owner or the administrator delete a "
                       "version, so version cleanup has no usable owner until "
                       "this is fixed.")
        findings.append(Finding("orphan-user", FAIL, user["name"], detail))
    return findings, examined


def check_version_owner(data, target_major):
    orphaned = set(fold(u["name"]) for u, _ in orphans(data))
    known = set(fold(u["name"]) for u in data["database_principals"])
    findings = []
    examined = 0
    for version in data["versions"]:
        owner = version["owner"]
        if not owner:
            continue
        examined += 1
        subject = "version %s (owner %s)" % (version["name"], owner)
        if fold(owner) in orphaned:
            reason = "the owner is an orphaned user and cannot connect"
        elif fold(owner) not in known:
            reason = "the owner is not a user in this database"
        else:
            continue
        if fold(version["name"]) == "default":
            advice = ("This is the default version. Fix the owner's login "
                      "(see orphan-user) and leave the version alone.")
        else:
            advice = ("Only the owner or the geodatabase administrator can "
                      "delete it, and deleting a version that was not "
                      "posted loses its edits. Do not drop the user first: "
                      "reconcile and post or discard the edits, delete the "
                      "version as the administrator, then drop the user.")
        findings.append(Finding("version-owner", FAIL, subject,
                                "%s. %s" % (reason, advice)))
    return findings, examined


def check_job_owner(data, target_major):
    sids = set(r["sid"] for r in data["server_principals"])
    findings = []
    for job in data["jobs"]:
        if job["owner_sid"] not in sids:
            findings.append(Finding(
                "job-owner", FAIL, job["name"],
                "the owner SID 0x%s matches no login on this instance. A "
                "job needs the logins it uses to exist on the destination."
                % job["owner_sid"]))
    return findings, len(data["jobs"])


def check_job_copy(data, target_major):
    source_names = dict((r["sid"], r["name"])
                        for r in data["source_server_principals"])
    dest_names = dict((r["sid"], r["name"]) for r in data["server_principals"])
    dest_jobs = dict((fold(j["name"]), j) for j in data["jobs"])
    findings = []
    for job in data["source_jobs"]:
        there = dest_jobs.get(fold(job["name"]))
        if there is None:
            findings.append(Finding(
                "job-copy", FAIL, job["name"],
                "the job is on the source and not on the destination. Jobs "
                "live in msdb and do not travel with a restored database."))
            continue
        was = source_names.get(job["owner_sid"])
        now = dest_names.get(there["owner_sid"])
        if was is not None and now is not None and fold(was) != fold(now):
            findings.append(Finding(
                "job-copy", WARN, job["name"],
                "the owner changed from %s on the source to %s on the "
                "destination." % (was, now)))
    return findings, len(data["source_jobs"])


def check_logins(data, target_major):
    dest_sids = set(r["sid"] for r in data["server_principals"])
    dest_names = dict((fold(r["name"]), r["sid"])
                      for r in data["server_principals"])
    findings = []
    examined = 0
    for login in data["source_server_principals"]:
        if login["type"].strip().upper() not in CARRIED_LOGIN_TYPES:
            continue
        if fold(login["name"]).startswith(SYSTEM_LOGIN_PREFIXES):
            continue
        examined += 1
        if login["sid"] in dest_sids:
            continue
        other = dest_names.get(fold(login["name"]))
        if other is None:
            if login["type"].strip().upper() == "S":
                how = ("Create it with its source SID (0x%s)" % login["sid"])
            else:
                how = ("Create it with CREATE LOGIN [%s] FROM WINDOWS, which "
                       "takes the SID from the account" % login["name"])
            detail = ("the login is on the source and not on the "
                      "destination. %s so the database users that map to it "
                      "stay mapped." % how)
        else:
            detail = ("the login exists with SID 0x%s, not the source SID "
                      "0x%s. A database user mapped to the source SID is an "
                      "orphan, and a login that is created again gets a new "
                      "SID." % (other, login["sid"]))
        findings.append(Finding("login-missing", FAIL, login["name"], detail))
    return findings, examined


def _servers(data):
    rows = data["linked_servers"]
    by_name = dict((fold(r["name"]), r) for r in rows)
    return by_name


def check_xdb_server(data, target_major):
    by_name = _servers(data)
    findings = []
    examined = 0
    for dep in data["dependencies"]:
        server = dep["referenced_server_name"]
        if not server:
            continue
        examined += 1
        row = by_name.get(fold(server))
        subject = "%s -> %s" % (dep["referencing_name"], _four_part(dep))
        if row is None:
            findings.append(Finding(
                "xdb-server", FAIL, subject,
                "server '%s' is not in sys.servers on this instance, so the "
                "name cannot resolve. The catalog records such a name "
                "without resolving it, so nothing warned at restore time. "
                "Use a three-part name, or create the linked server."
                % server))
        elif row["server_id"] == 0:
            findings.append(Finding(
                "xdb-server", WARN, subject,
                "server '%s' is the local server (server_id 0). The name "
                "follows the instance, so a rename, or a restore onto "
                "another instance, breaks it. Use a three-part name."
                % server))
        elif not row["is_data_access_enabled"]:
            findings.append(Finding(
                "xdb-server", FAIL, subject,
                "linked server '%s' has distributed queries disabled "
                "(is_data_access_enabled = 0)." % server))
    return findings, examined


def check_xdb_database(data, target_major):
    by_name = _servers(data)
    local = set(n for n, r in by_name.items() if r["server_id"] == 0)
    databases = set(fold(r["name"]) for r in data["databases"])
    findings = []
    examined = 0
    for dep in data["dependencies"]:
        database = dep["referenced_database_name"]
        server = dep["referenced_server_name"]
        if not database or (server and fold(server) not in local):
            continue
        examined += 1
        if fold(database) not in databases:
            findings.append(Finding(
                "xdb-database", FAIL,
                "%s -> %s" % (dep["referencing_name"], _four_part(dep)),
                "database '%s' is not on this instance. Restore it here or "
                "change the reference." % database))
    return findings, examined


def check_provider(data, target_major):
    findings = []
    examined = 0
    for row in data["linked_servers"]:
        if row["server_id"] == 0:
            continue
        examined += 1
        provider = fold(row["provider"])
        if provider == "sqloledb":
            severity = WARN
            detail = ("SQLOLEDB is the legacy OLE DB provider and is not "
                      "recommended. Use Microsoft OLE DB Driver (MSOLEDBSQL).")
        elif (provider.startswith("sqlncli") and provider != "sqlncli"
              and target_major >= NO_NATIVE_CLIENT_MAJOR):
            # Microsoft: Native Client, every generation, is not shipped with
            # SQL Server 2022 and later.
            severity = FAIL
            detail = ("%s is SQL Server Native Client, which SQL Server "
                      "2022 (major version 16) and later do not ship. The "
                      "target is version %d. Use MSOLEDBSQL."
                      % (row["provider"], target_major))
        else:
            continue
        findings.append(Finding("linked-provider", severity, row["name"],
                                detail))
    return findings, examined


def _grants(rows):
    """Index whole-object, schema and database permissions by principal."""
    held = {}
    for row in rows:
        state = row["state_desc"].strip().upper()
        if state not in ("GRANT", "GRANT_WITH_GRANT_OPTION", "DENY"):
            continue
        kind = row["class_desc"].strip().upper()
        schema = fold(row["schema_name"])
        if kind == "OBJECT_OR_COLUMN" and not row["column_name"]:
            scope = ("OBJECT", schema, fold(row["object_name"]))
        elif kind == "SCHEMA":
            scope = ("SCHEMA", schema)
        elif kind == "DATABASE":
            scope = ("DATABASE",)
        else:
            continue
        key = (fold(row["grantee"]), row["permission_name"].strip().upper(),
               scope)
        held[key] = "DENY" if state == "DENY" else "GRANT"
    return held


def _effective(held, grantee, permission, schema, obj):
    """DENY wins at any level, then a GRANT of the permission or CONTROL."""
    result = None
    for scope in (("OBJECT", schema, obj), ("SCHEMA", schema), ("DATABASE",)):
        for name in (permission, "CONTROL"):
            state = held.get((grantee, name, scope))
            if state == "DENY":
                return "DENY"
            if state:
                result = "GRANT"
    return result


def check_evw(data, target_major):
    tables = dict(((fold(o["schema_name"]), fold(o["object_name"])), o)
                  for o in data["objects"] if o["type"].strip().upper() == "U")
    pairs = []
    for obj in data["objects"]:
        name = fold(obj["object_name"])
        if obj["type"].strip().upper() != "V" or not name.endswith(EVW_SUFFIX):
            continue
        base = tables.get((fold(obj["schema_name"]), name[:-len(EVW_SUFFIX)]))
        if base is not None:
            pairs.append((base, obj))
    held = _grants(data["database_permissions"])
    wanted_on = collections.defaultdict(set)
    for (grantee, permission, scope), state in held.items():
        if (scope[0] == "OBJECT" and state == "GRANT"
                and permission in TABLE_PERMISSIONS):
            wanted_on[scope[1:]].add((grantee, permission))
    findings = []
    examined = 0
    for table, view in sorted(pairs, key=lambda p: (p[0]["schema_name"],
                                                    p[0]["object_name"])):
        schema = fold(table["schema_name"])
        wanted = sorted(wanted_on.get((schema, fold(table["object_name"])),
                                      ()))
        for grantee, permission in wanted:
            examined += 1
            state = _effective(held, grantee, permission, schema,
                               fold(view["object_name"]))
            if state == "GRANT":
                continue
            shown = "%s.%s" % (view["schema_name"], view["object_name"])
            base = "%s.%s" % (table["schema_name"], table["object_name"])
            if state == "DENY":
                detail = ("%s is denied to %s on or above %s, while the "
                          "table %s grants it." % (permission, grantee, shown,
                                                   base))
            else:
                detail = ("%s is granted to %s on %s and not on its "
                          "versioned view %s. Esri documents the copy to the "
                          "view for grants made through ArcGIS; the export "
                          "shows none here. Re-grant as the dataset owner "
                          "through ArcGIS." % (permission, grantee, base,
                                               shown))
            findings.append(Finding("evw-grant", FAIL, "%s / %s" % (
                shown, grantee), detail))
    return findings, examined


# (rule, files it needs, needs --target-major, function)
RULES = (
    ("orphan-user", ("server_principals", "database_principals"), False,
     check_orphans),
    ("version-owner", ("server_principals", "database_principals",
                       "versions"), False, check_version_owner),
    ("job-owner", ("server_principals", "jobs"), False, check_job_owner),
    ("job-copy", ("source_jobs", "jobs", "source_server_principals",
                  "server_principals"), False, check_job_copy),
    ("login-missing", ("source_server_principals", "server_principals"),
     False, check_logins),
    ("xdb-server", ("dependencies", "linked_servers"), False,
     check_xdb_server),
    ("xdb-database", ("dependencies", "linked_servers", "databases"), False,
     check_xdb_database),
    ("linked-provider", ("linked_servers",), True, check_provider),
    ("evw-grant", ("objects", "database_permissions"), False, check_evw),
)


def run_checks(data, target_major=None):
    """Run every rule whose files are present. A skipped rule is recorded."""
    findings, ran, skipped = [], [], []
    for name, needs, needs_target, check in RULES:
        absent = [stem + ".csv" for stem in needs if stem not in data]
        if absent:
            skipped.append((name, "missing " + ", ".join(absent)))
            continue
        if needs_target and target_major is None:
            skipped.append((name, "needs --target-major"))
            continue
        got, examined = check(data, target_major)
        if examined == 0:
            # A header-only file is what a query run in the wrong database, or
            # with too little permission, returns. It checked nothing.
            skipped.append((name, "examined no rows"))
            continue
        findings.extend(got)
        ran.append((name, examined,
                    sum(1 for f in got if f.severity == FAIL),
                    sum(1 for f in got if f.severity == WARN)))
    return Report(findings, ran, skipped, sorted(data))


def gate(report, require_all=False):
    """1 when a rule failed, 4 when nothing was examined, else 0.

    With require_all, a clean run that skipped any rule is 5: the rules that
    ran found nothing, but some rule checked nothing.
    """
    if report.fails:
        return 1
    if report.examined == 0:
        return 4
    if require_all and report.skipped:
        return 5
    return 0


def _one_line(text):
    return " ".join(text.split())


def describe(report):
    lines = []
    lines.append("files read: %s" % (", ".join(report.files) or "none"))
    if report.ran:
        lines.append("rules run:")
        for name, examined, fails, warns in report.ran:
            lines.append("  %-16s %5d examined  %3d FAIL  %3d WARN"
                         % (name, examined, fails, warns))
    if report.skipped:
        lines.append("rules skipped (each checked nothing):")
        for name, reason in report.skipped:
            lines.append("  %-16s %s" % (name, reason))
    for finding in report.findings:
        lines.append("")
        lines.append("%s  %s  %s" % (finding.severity, finding.rule,
                                     _one_line(finding.subject)))
        lines.append("      %s" % _one_line(finding.detail))
    lines.append("")
    if report.fails:
        lines.append("VERDICT: %d FAIL, %d WARN. The move is not verified. "
                     "Fix the FAIL lines, export again and run again."
                     % (report.fails, report.warns))
    elif report.examined == 0:
        lines.append("VERDICT: NOTHING CHECKED. No rule examined a row, so "
                     "this is not a clean move. Look for missing or empty "
                     "files, or for a rule that needs --target-major.")
    else:
        lines.append("VERDICT: no FAIL in %d row(s) examined by %d rule(s), "
                     "%d WARN." % (report.examined, len(report.ran),
                                   report.warns))
        if report.skipped:
            lines.append("%d rule(s) were skipped and checked nothing. Clean "
                         "means only the rules that ran." % len(report.skipped))
    return lines


def findings_rows(report):
    return [{"severity": f.severity, "rule": f.rule,
             "subject": _one_line(f.subject), "detail": _one_line(f.detail)}
            for f in report.findings]


# =============================================================================
# I/O. Reading the exports and writing the findings.
# =============================================================================

def load_table(path, stem):
    """One export as a list of dicts with the columns the rules read."""
    wanted = FILES[stem]
    with open(path, "r", encoding="utf-8-sig", errors="replace",
              newline="") as handle:
        text = handle.read()
    if "\x00" in text:
        raise InputError("%s: the file holds NUL characters, which is what a "
                         "UTF-16 file looks like. Save the export as UTF-8."
                         % path)
    reader = csv.reader(io.StringIO(text, newline=""))
    header = next(reader, None)
    if header is None:
        raise InputError("%s: the file is empty, not even a header" % path)
    names = [h.strip().casefold() for h in header]
    absent = [c for c in wanted if c not in names]
    if absent:
        raise InputError("%s: columns not in the CSV: %s. It has: %s"
                         % (path, ", ".join(absent), ", ".join(names)))
    index = dict((c, names.index(c)) for c in wanted)
    rows = []
    previous = reader.line_num
    for raw in reader:
        line = previous + 1
        previous = reader.line_num
        if not raw:
            continue
        row = {}
        for column in wanted:
            at = index[column]
            row[column] = raw[at].strip() if at < len(raw) else ""
            if (column in NULLABLE_COLUMNS.get(stem, ())
                    and row[column].upper() == "NULL"):
                row[column] = ""
            try:
                if column in SID_COLUMNS:
                    if row[column] or (stem, column) not in OPTIONAL_SIDS:
                        row[column] = parse_sid(row[column])
                elif column in INT_COLUMNS:
                    row[column] = int(row[column])
                elif column in BOOL_COLUMNS:
                    row[column] = parse_bool(row[column])
            except ValueError as exc:
                raise InputError("%s line %d, column %s: %s"
                                 % (path, line, column, exc))
        rows.append(row)
    return rows


def read_export(directory):
    """Every known export that is in the directory, by file stem."""
    data = {}
    for stem in sorted(FILES):
        path = os.path.join(directory, stem + ".csv")
        if os.path.isfile(path):
            data[stem] = load_table(path, stem)
    return data


def write_findings(path, report):
    # Mode "x" creates the file and fails if it exists, so a path that appeared
    # after the check in _run is never overwritten.
    with open(path, "x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["severity", "rule",
                                                    "subject", "detail"])
        writer.writeheader()
        writer.writerows(findings_rows(report))


# ------------------------------------------------------------------ self-test

def self_test():
    """Run the assertions in a temp directory that is removed even when one
    of them raises, so a crash never leaves sqlmove-selftest-* behind."""
    tmp = tempfile.mkdtemp(prefix="sqlmove-selftest-")
    try:
        return _self_test(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _self_test(tmp):
    """Assertions over the decision core and the CLI. No network, no
    credentials. The only files are the ones written under tmp."""
    passed = [0]
    failed = []

    def check(cond, label):
        if cond:
            passed[0] += 1
            print("PASS  %s" % label)
        else:
            failed.append(label)
            print("FAIL  %s" % label)

    def raises(fn, label, kind=ValueError, needle=""):
        try:
            fn()
        except kind as exc:
            check(needle in str(exc), label)
        except Exception as exc:
            check(False, "%s (wrong exception %r)" % (label, exc))
        else:
            check(False, "%s (no error raised)" % label)

    # ---- row builders. Every name, SID and server here is synthetic.
    def sp(name, sid, kind="S"):
        return {"name": name, "sid": sid, "type": kind}

    def dp(name, sid, auth="INSTANCE"):
        return {"name": name, "sid": sid, "authentication_type_desc": auth}

    def jb(name, owner):
        return {"name": name, "owner_sid": owner}

    def sv(server_id, name, provider="MSOLEDBSQL19", access=True):
        return {"server_id": server_id, "name": name, "provider": provider,
                "is_data_access_enabled": access}

    def dep(ref, server="", database="", schema="", entity="t"):
        return {"referencing_name": ref, "referenced_server_name": server,
                "referenced_database_name": database,
                "referenced_schema_name": schema,
                "referenced_entity_name": entity}

    def ob(schema, name, kind):
        return {"schema_name": schema, "object_name": name, "type": kind}

    def pm(grantee, permission, obj="sites", schema="dbo", state="GRANT",
           cls="OBJECT_OR_COLUMN", column=""):
        return {"class_desc": cls, "schema_name": schema, "object_name": obj,
                "column_name": column, "grantee": grantee,
                "permission_name": permission, "state_desc": state}

    def ver(name, owner):
        return {"name": name, "owner": owner}

    def names(findings):
        return [(f.rule, f.severity, f.subject) for f in findings]

    def put(directory, stem, header, rows, encoding="utf-8"):
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, stem + ".csv")
        with io.open(path, "w", encoding=encoding, newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(header)
            writer.writerows(rows)
        return path

    def raw_put(directory, stem, text):
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, stem + ".csv")
        with io.open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        return path

    def run_cli(argv):
        """main() with its output captured, so the self-test stays readable."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    print("sqlmove self-test: temporary files only, no network, no "
          "credentials")
    print("-" * 68)

    # ---- the SID and the booleans an export carries
    check(parse_sid("0x0A01") == "0a01",
          "a SID exported with 0x is read as lower-case hex")
    check(parse_sid("0X0a0B") == "0a0b" and parse_sid("ab01") == "ab01",
          "0X and a bare hex string are read the same way")
    check(parse_sid("  0x0105  ") == "0105", "spaces around a SID are dropped")
    check(parse_sid("a" * 170) == "a" * 170,
          "a SID of 85 bytes, the most varbinary(85) holds, is accepted")
    raises(lambda: parse_sid("a" * 172), "a SID of 86 bytes is refused")
    raises(lambda: parse_sid("0x123"), "an odd number of hex digits is refused")
    raises(lambda: parse_sid("0xZZ"), "a SID that is not hex is refused")
    raises(lambda: parse_sid(""), "an empty SID is refused")
    raises(lambda: parse_sid("0x"), "a bare 0x is refused")
    check(parse_bool("1") and parse_bool(" TRUE ") and parse_bool("true"),
          "1 and true, in any case, read as true")
    check(not parse_bool("0") and not parse_bool("False"),
          "0 and false read as false")
    raises(lambda: parse_bool("yes"), "a word that is not a boolean is refused")
    raises(lambda: parse_bool(""), "an empty boolean is refused")
    check(fold("EDIT_A") == fold("edit_a"), "names compare ignoring case")

    check(_four_part(dep("p", "srv", "db", "dbo", "t")) == "[srv].[db].[dbo].[t]",
          "a four-part name is printed with every part bracketed")
    check(_four_part(dep("p", "", "db", "dbo", "t")) == "[db].[dbo].[t]",
          "a three-part name drops the empty server")
    check(_four_part(dep("p", "", "db", "", "t")) == "[db]..[t]",
          "a name with no schema keeps the empty schema between dots")
    check(_four_part(dep("p", "", "", "", "t")) == "[t]",
          "a one-part name is printed alone")
    check(_four_part(dep("p", "", "", "", "")) == "",
          "a row with no entity name does not crash the printer")

    # ---- the instance every later case reads: logins and database users
    logins = [sp("sa", "01"), sp("sde", "a001"), sp("edit_a", "a002"),
              sp("reader_b", "a003"), sp("CORP\\svc", "b001", "U"),
              sp("##MS_PolicyEvent##", "c001"), sp("renamed_login", "a005")]
    users = [dp("dbo", "01"), dp("sde", "a0ff"), dp("edit_a", "a002"),
             dp("edit_b", "a004"), dp("reader_b", "a0a3"),
             dp("CORP\\ann", "b002"), dp("guest", "00", "NONE"),
             dp("editors_role", "d001", "NONE"), dp("cu", "c0c0", "DATABASE"),
             dp("renamed_u", "a005")]
    inst = {"server_principals": logins, "database_principals": users}

    # ---- orphaned users
    found = orphans(inst)
    check([u["name"] for u, _ in found]
          == ["sde", "edit_b", "reader_b", "CORP\\ann"],
          "the orphans are the INSTANCE users whose SID is in no login")
    check(dict((u["name"], s) for u, s in found)
          == {"sde": "a001", "edit_b": None, "reader_b": "a003",
              "CORP\\ann": None},
          "each orphan carries the SID of a same-name login, or None")
    check("guest" not in [u["name"] for u, _ in found]
          and "editors_role" not in [u["name"] for u, _ in found],
          "a user with no login by design (NONE) is never an orphan")
    check("cu" not in [u["name"] for u, _ in found],
          "a contained database user is never an orphan")
    check("renamed_u" not in [u["name"] for u, _ in found],
          "a user is matched to its login by SID, so a renamed login does "
          "not orphan it")
    check("CORP\\ann" in [u["name"] for u, _ in found],
          "a Windows user with no login row is an orphan, whatever a "
          "directory lookup would say  <-- pinned defect")
    got, examined = check_orphans(inst, None)
    check(examined == 7 and len(got) == 4,
          "seven INSTANCE users were examined and four are orphans")
    check(all(f.rule == "orphan-user" and f.severity == FAIL for f in got),
          "every orphan is an orphan-user FAIL")
    by_subject = dict((f.subject, f.detail) for f in got)
    check("geodatabase administrator" in by_subject["sde"],
          "an orphaned sde user is called the geodatabase administrator")
    check("geodatabase administrator" not in by_subject["edit_b"]
          and "geodatabase administrator" not in by_subject["reader_b"],
          "and no other orphan is")
    check("SID = 0xa004" in by_subject["edit_b"],
          "an orphan with no same-name login is told the SID to create it "
          "with")
    check("FROM WINDOWS" in by_subject["CORP\\ann"]
          and "SID = " not in by_subject["CORP\\ann"]
          and "for SQL Server logins only" in by_subject["CORP\\ann"],
          "an orphaned Windows user is told FROM WINDOWS and never a SID = "
          "option, which CREATE LOGIN allows for SQL logins only  "
          "<-- pinned defect")
    check("0xa003" in by_subject["reader_b"] and "0xa0a3"
          in by_subject["reader_b"] and "not a SID match"
          in by_subject["reader_b"],
          "a same-name login with another SID names both SIDs and is not "
          "called a match  <-- pinned defect")
    check(orphans({"server_principals": [sp("READER_X", "aa02")],
                   "database_principals": [dp("Reader_X", "aa01")]})
          == [(dp("Reader_X", "aa01"), "aa02")],
          "the same-name search ignores case")
    check(check_orphans({"server_principals": [],
                         "database_principals": []}, None) == ([], 0),
          "no users examined means zero examined, not a pass")

    # ---- versions and the order of cleanup
    vdata = dict(inst, versions=[ver("DEFAULT", "sde"), ver("wip_1", "edit_b"),
                                 ver("q3", "edit_a"), ver("ghost", "nobody"),
                                 ver("blank", "")])
    got, examined = check_version_owner(vdata, None)
    check(names(got) == [
        ("version-owner", FAIL, "version DEFAULT (owner sde)"),
        ("version-owner", FAIL, "version wip_1 (owner edit_b)"),
        ("version-owner", FAIL, "version ghost (owner nobody)")],
        "versions owned by an orphan or by nobody are reported, the rest "
        "are not")
    check(examined == 4, "a version with no owner is not examined")
    check("Do not drop the user first" in got[1].detail
          and "loses its edits" in got[1].detail
          and "orphaned user" in got[1].detail,
          "an orphan's version says to delete it before the user is dropped"
          "  <-- pinned defect")
    check("not a user in this database" in got[2].detail
          and "Do not drop" in got[2].detail,
          "a version owned by an absent user says so")
    check("default version" in got[0].detail
          and "Do not drop" not in got[0].detail
          and "delete" not in got[0].detail,
          "the default version is never told to be deleted  "
          "<-- pinned defect")
    check(check_version_owner(dict(inst, versions=[ver("v", "EDIT_A")]),
                              None) == ([], 1),
          "the owner is matched ignoring case")

    # ---- job owners and jobs that did not come
    jdata = dict(inst, jobs=[jb("nightly", "b001"), jb("weekly", "b999")])
    got, examined = check_job_owner(jdata, None)
    check(names(got) == [("job-owner", FAIL, "weekly")] and examined == 2,
          "a job whose owner SID matches no login is reported")
    check("0xb999" in got[0].detail, "and the SID is named")
    copy = {
        "source_server_principals": [sp("CORP\\svc", "b001", "U"),
                                     sp("old_owner", "e001"),
                                     sp("dest_gone", "e002")],
        "server_principals": logins,
        "source_jobs": [jb("nightly", "b001"), jb("renamed_job", "e001"),
                        jb("monthly", "b001"), jb("unknown_src", "ffff"),
                        jb("dest_unres", "e002")],
        "jobs": [jb("Nightly", "b001"), jb("renamed_job", "a002"),
                 jb("unknown_src", "a002"), jb("dest_unres", "9999")]}
    got, examined = check_job_copy(copy, None)
    check(names(got) == [("job-copy", WARN, "renamed_job"),
                         ("job-copy", FAIL, "monthly")] and examined == 5,
          "a job missing from the destination fails and a changed owner "
          "warns, matched ignoring case")
    check("old_owner" in got[0].detail and "edit_a" in got[0].detail,
          "the owner change names both logins")
    check("do not travel" in got[1].detail,
          "a missing job says jobs do not travel with a restored database")

    # ---- logins that did not come
    lg = {"source_server_principals": [
        sp("sa", "01"), sp("appsvc", "a010"), sp("edit_a", "a0aa"),
        sp("NT SERVICE\\MSSQLSERVER", "c010", "U"), sp("##MS_X##", "c011"),
        sp("app_cert", "c012", "C"), sp("CORP\\grp", "b020", "G"),
        sp("CORP\\winmiss", "b030", "U"),
        sp("NT AUTHORITY\\SYSTEM", "c020", "U"), sp("entra_user", "c040", "E")],
        "server_principals": logins}
    got, examined = check_logins(lg, None)
    check(names(got) == [("login-missing", FAIL, "appsvc"),
                         ("login-missing", FAIL, "edit_a"),
                         ("login-missing", FAIL, "CORP\\grp"),
                         ("login-missing", FAIL, "CORP\\winmiss")],
          "a login missing, or present with another SID, is reported, and a "
          "missing Windows login is too  <-- pinned defect")
    check(examined == 5,
          "instance-owned logins, certificate logins and Entra logins are "
          "not examined  <-- pinned defect")
    check("SID (0xa010)" in got[0].detail and "0xa002" in got[1].detail
          and "0xa0aa" in got[1].detail and "orphan" in got[1].detail,
          "a missing login is told its source SID and a changed one names "
          "both")
    check("FROM WINDOWS" in got[2].detail and "FROM WINDOWS" in got[3].detail
          and "SID (0x" not in got[2].detail + got[3].detail,
          "a missing Windows login or group is told FROM WINDOWS, not a "
          "source SID  <-- pinned defect")

    # ---- cross-server and cross-database references
    servers = [sv(0, "srv_new"), sv(1, "link_erp", "SQLNCLI11"),
               sv(2, "link_hr", "MSOLEDBSQL19", False)]
    deps = [dep("proc1", "srv_old", "geodb", "dbo", "assets"),
            dep("proc2", "link_erp", "erp", "dbo", "t"),
            dep("proc3", "link_hr", "hr", "dbo", "t"),
            dep("proc4", "SRV_NEW", "geodb", "dbo", "t"),
            dep("proc5", "", "otherdb", "dbo", "t"),
            dep("proc6", "", "GEODB", "dbo", "x"),
            dep("proc7", "srv_new", "gone", "dbo", "x"),
            dep("proc8", "", "", "dbo", "local_table")]
    xdata = {"dependencies": deps, "linked_servers": servers,
             "databases": [{"name": "master"}, {"name": "geodb"}]}
    got, examined = check_xdb_server(xdata, None)
    check(names(got) == [
        ("xdb-server", FAIL, "proc1 -> [srv_old].[geodb].[dbo].[assets]"),
        ("xdb-server", FAIL, "proc3 -> [link_hr].[hr].[dbo].[t]"),
        ("xdb-server", WARN, "proc4 -> [SRV_NEW].[geodb].[dbo].[t]"),
        ("xdb-server", WARN, "proc7 -> [srv_new].[gone].[dbo].[x]")],
        "a four-part name whose server is not in sys.servers fails, as "
        "does a linked server with distributed queries off")
    check(examined == 5, "only references that name a server are examined")
    check("not in sys.servers" in got[0].detail
          and "three-part" in got[0].detail,
          "the missing-server message names the cause and the fix  "
          "<-- pinned defect")
    check("is_data_access_enabled = 0" in got[1].detail,
          "a linked server with data access off says so")
    check("local server (server_id 0)" in got[2].detail,
          "a name that resolves to the local server only warns")
    got, examined = check_xdb_database(xdata, None)
    check(names(got) == [
        ("xdb-database", FAIL, "proc5 -> [otherdb].[dbo].[t]"),
        ("xdb-database", FAIL, "proc7 -> [srv_new].[gone].[dbo].[x]")],
        "a reference to a database that is not on the instance fails")
    check(examined == 4,
          "a reference through a remote server is not examined here, and "
          "the database name is matched ignoring case")
    check(not any("srv_old" in f.subject for f in got),
          "a loopback name that no longer exists is reported once, as a "
          "missing server, not again as a missing database  "
          "<-- pinned defect")

    # ---- linked-server providers
    provs = [sv(0, "srv_new", "SQLNCLI11"), sv(1, "a_ncli11", "SQLNCLI11"),
             sv(2, "b_ncli10", "SQLNCLI10"), sv(3, "c_ncli", "SQLNCLI"),
             sv(4, "d_oledb", "SQLOLEDB"), sv(5, "e_new", "MSOLEDBSQL19"),
             sv(6, "f_new", "")]
    got, examined = check_provider({"linked_servers": provs}, 16)
    check(names(got) == [("linked-provider", FAIL, "a_ncli11"),
                         ("linked-provider", FAIL, "b_ncli10"),
                         ("linked-provider", WARN, "d_oledb")],
          "on SQL Server 2022 every Native Client generation fails, and the "
          "legacy SQLOLEDB warns  <-- pinned defect")
    check(examined == 6, "the local server row is not a linked server")
    check("do not ship" in got[0].detail and "MSOLEDBSQL" in got[0].detail,
          "the provider message says the target does not ship it")
    got, examined = check_provider({"linked_servers": provs}, 15)
    check(names(got) == [("linked-provider", WARN, "d_oledb")],
          "on SQL Server 2019 Native Client is still shipped, so only the "
          "legacy provider warns  <-- pinned defect")
    check(check_provider({"linked_servers": [sv(0, "s")]}, 16) == ([], 0),
          "a catalog with only the local server examines nothing")

    # ---- the versioned view that did not get the grant
    objs = [ob("dbo", "sites", "U"), ob("dbo", "sites_evw", "V"),
            ob("dbo", "assets", "U"), ob("dbo", "assets_evw", "V"),
            ob("dbo", "plain", "U"), ob("dbo", "orphan_evw", "V"),
            ob("dbo", "SITES_ARCHIVE", "U"), ob("dbo", "x_evw", "U")]
    perms = [
        pm("edit_a", "SELECT"), pm("edit_a", "INSERT"),
        pm("edit_a", "UPDATE"), pm("edit_a", "SELECT", "sites_evw"),
        pm("reader_b", "SELECT"), pm("reader_b", "SELECT", "sites_evw"),
        pm("edit_c", "SELECT", "assets"),
        pm("edit_c", "SELECT", "", "dbo", cls="SCHEMA"),
        pm("edit_d", "SELECT", "assets"),
        pm("edit_d", "SELECT", "", "", cls="DATABASE"),
        pm("edit_e", "SELECT", "assets"),
        pm("edit_e", "SELECT", "assets_evw", state="DENY"),
        pm("edit_f", "SELECT"), pm("edit_f", "CONTROL", "sites_evw"),
        pm("edit_g", "SELECT", column="shape"),
        pm("edit_h", "SELECT", state="DENY"),
        pm("edit_i", "SELECT", "assets", state="GRANT_WITH_GRANT_OPTION"),
        pm("edit_j", "SELECT", "plain"), pm("edit_k", "EXECUTE"),
        pm("edit_l", "SELECT", cls="TYPE"),
        pm("edit_l", "SELECT", state="REVOKE"),
        pm("EDIT_M", "SELECT", "SITES", "DBO"),
        pm("edit_m", "SELECT", "sites_evw"),
        pm("edit_n", "CONTROL", "assets"),
        pm("edit_n", "SELECT", "assets_evw"),
        pm("edit_o", "SELECT"),
        pm("edit_o", "SELECT", "", "dbo", state="DENY", cls="SCHEMA")]
    edata = {"objects": objs, "database_permissions": perms}
    got, examined = check_evw(edata, None)
    check(names(got) == [
        ("evw-grant", FAIL, "dbo.assets_evw / edit_e"),
        ("evw-grant", FAIL, "dbo.assets_evw / edit_i"),
        ("evw-grant", FAIL, "dbo.assets_evw / edit_n"),
        ("evw-grant", FAIL, "dbo.sites_evw / edit_a"),
        ("evw-grant", FAIL, "dbo.sites_evw / edit_a"),
        ("evw-grant", FAIL, "dbo.sites_evw / edit_o")],
        "a grant on a versioned table with none on its _evw view is "
        "reported  <-- pinned defect")
    check(examined == 12,
          "twelve grants on a table that has a versioned view were "
          "examined")
    check([f.detail.split(" ")[0] for f in got if "edit_a" in f.subject]
          == ["INSERT", "UPDATE"],
          "each missing permission is its own finding")
    check("denied" in got[0].detail and "on or above" in got[0].detail,
          "a DENY on the view is called a denial, not a missing grant")
    check("through ArcGIS" in got[1].detail
          and "versioned view dbo.assets_evw" in got[1].detail,
          "a missing grant points to the ArcGIS route and names the view")
    check("denied" in got[5].detail,
          "a DENY at schema level is a denial too")
    check(not any("edit_c" in f.subject for f in got),
          "a schema-level grant covers the view")
    check(not any("edit_d" in f.subject for f in got),
          "a database-level grant covers the view")
    check(not any("edit_f" in f.subject for f in got),
          "CONTROL on the view covers a table SELECT")
    check(not any("edit_m" in f.subject for f in got),
          "schema, table and grantee names are matched ignoring case")
    check(not any(s in f.subject for f in got
                  for s in ("edit_g", "edit_h", "edit_j", "edit_k", "edit_l",
                            "reader_b")),
          "column grants, DENYs on the table, tables with no view, other "
          "permissions and unknown rows examine nothing")
    check(check_evw({"objects": objs, "database_permissions": []}, None)
          == ([], 0), "no grants examines nothing")
    check(check_evw({"objects": [ob("dbo", "x_evw", "V")],
                     "database_permissions": [pm("a", "SELECT", "x")]},
                    None) == ([], 0),
          "a view whose base table is not in the export is not paired")
    # Only a view whose name ends in _evw pairs with a table. Without the
    # guard the last four characters of any name are cut off, so roads_old
    # looks like a view of roads, and a table called x_evw like one of x.
    pdata = {"objects": [ob("dbo", "roads", "U"), ob("dbo", "roads_old", "V"),
                         ob("dbo", "roads2024", "V"),
                         ob("dbo", "roads_evw", "V"), ob("dbo", "x", "U"),
                         ob("dbo", "x_evw", "U")],
             "database_permissions": [pm("ed", "SELECT", "roads"),
                                      pm("ed", "SELECT", "roads_evw"),
                                      pm("ed", "SELECT", "x")]}
    check(check_evw(pdata, None) == ([], 1),
          "a view not named <table>_evw, and a table named <table>_evw, are "
          "never paired with the table  <-- pinned defect")

    # ---- grants the first pass missed: DELETE alone, a column grant, and a
    # class the tool does not read must not count as a grant on the view
    odata = {"objects": [ob("dbo", "sites", "U"), ob("dbo", "sites_evw", "V")],
             "database_permissions": [
                 pm("del_a", "DELETE"),
                 pm("col_b", "SELECT"),
                 pm("col_b", "SELECT", "sites_evw", column="shape"),
                 pm("typ_c", "SELECT"),
                 pm("typ_c", "SELECT", "sites_evw", cls="TYPE")]}
    got, examined = check_evw(odata, None)
    check(names(got) == [("evw-grant", FAIL, "dbo.sites_evw / col_b"),
                         ("evw-grant", FAIL, "dbo.sites_evw / del_a"),
                         ("evw-grant", FAIL, "dbo.sites_evw / typ_c")]
          and examined == 3,
          "a table DELETE grant, and a view that holds only a column grant "
          "or a grant of another class, are reported  <-- pinned defect")
    got, examined = check_evw({"objects": odata["objects"],
                               "database_permissions": [
                                   pm("ctl", "CONTROL"),
                                   pm("ctl", "SELECT", "sites_evw"),
                                   pm("ctl", "INSERT", "sites_evw"),
                                   pm("ctl", "UPDATE", "sites_evw"),
                                   pm("ctl", "DELETE", "sites_evw")]}, None)
    check(names(got) == [("evw-grant", FAIL, "dbo.sites_evw / ctl")]
          and got[0].detail.startswith("CONTROL"),
          "CONTROL on the table is expected as CONTROL on the view; four "
          "data grants do not stand in for it")

    # ---- running the rules, and what a skipped rule means
    report = run_checks({})
    check(report.ran == [] and len(report.skipped) == len(RULES)
          and report.examined == 0,
          "an empty export runs no rule and skips all of them")
    check(gate(report) == 4,
          "and checking nothing exits 4, not 0  <-- pinned defect")
    check(dict(report.skipped)["orphan-user"]
          == "missing server_principals.csv, database_principals.csv",
          "a skipped rule names the files it needs")
    check(dict(report.skipped)["linked-provider"] == "missing linked_servers.csv",
          "a rule with no file is skipped for the file first")
    report = run_checks({"linked_servers": servers})
    check(dict(report.skipped)["linked-provider"] == "needs --target-major",
          "linked-provider is skipped, and says why, without --target-major")
    report = run_checks({"linked_servers": servers}, 16)
    check([r[0] for r in report.ran] == ["linked-provider"]
          and report.fails == 1 and gate(report) == 1,
          "and it runs, and fails the gate, with --target-major")
    blank = dict((stem, []) for stem in FILES)
    report = run_checks(blank, 16)
    check(report.ran == [] and report.examined == 0 and gate(report) == 4
          and len(report.skipped) == len(RULES)
          and set(why for _, why in report.skipped) == {"examined no rows"},
          "files that exist and hold no rows run no rule: each is listed as "
          "skipped and nothing is checked  <-- pinned defect")
    report = run_checks({"server_principals": [sp("sa", "01")],
                         "database_principals": [dp("dbo", "01")],
                         "objects": [ob("dbo", "sites", "U"),
                                     ob("dbo", "sites_evw", "V")],
                         "database_permissions": []})
    check([r[0] for r in report.ran] == ["orphan-user"]
          and dict(report.skipped)["evw-grant"] == "examined no rows",
          "a rule whose file has a header and no rows is skipped, though the "
          "other rules ran  <-- pinned defect")
    lines = describe(report)
    check(lines[-2].startswith("VERDICT: no FAIL in 1 row(s) examined by 1 "
                               "rule(s)") and any(
                                   l.startswith("  evw-grant") and
                                   "examined no rows" in l for l in lines),
          "and the verdict counts only the rules that examined a row  "
          "<-- pinned defect")
    allclean = {
        "server_principals": [sp("sa", "01"), sp("edit_a", "a002"),
                              sp("CORP\\svc", "b001", "U")],
        "database_principals": [dp("dbo", "01"), dp("edit_a", "a002")],
        "versions": [ver("q3", "edit_a")],
        "jobs": [jb("nightly", "b001")],
        "source_jobs": [jb("nightly", "b001")],
        "source_server_principals": [sp("sa", "01"), sp("edit_a", "a002"),
                                    sp("CORP\\svc", "b001", "U")],
        "linked_servers": [sv(0, "srv_new"), sv(1, "link_erp")],
        "dependencies": [dep("p", "link_erp", "erp", "dbo", "t"),
                         dep("p2", "", "geodb", "dbo", "t")],
        "databases": [{"name": "master"}, {"name": "geodb"}],
        "objects": [ob("dbo", "sites", "U"), ob("dbo", "sites_evw", "V")],
        "database_permissions": [pm("edit_a", "SELECT"),
                                 pm("edit_a", "SELECT", "sites_evw")]}
    report = run_checks(allclean, 16)
    check(gate(report, True) == 0,
          "--require-all keeps exit 0 when every rule ran")
    check(report.ran == [("orphan-user", 2, 0, 0), ("version-owner", 1, 0, 0),
                         ("job-owner", 1, 0, 0), ("job-copy", 1, 0, 0),
                         ("login-missing", 3, 0, 0), ("xdb-server", 1, 0, 0),
                         ("xdb-database", 1, 0, 0),
                         ("linked-provider", 1, 0, 0),
                         ("evw-grant", 1, 0, 0)]
          and report.skipped == [] and gate(report) == 0,
          "an instance where every rule examined a row is clean, exit 0")
    report = run_checks(allclean)
    check(gate(report) == 0 and gate(report, True) == 5,
          "a clean run with a skipped rule is exit 0, and exit 5 with "
          "--require-all")
    check([r[0] for r in report.ran] == [
        "orphan-user", "version-owner", "job-owner", "job-copy",
        "login-missing", "xdb-server", "xdb-database", "evw-grant"]
        and report.skipped == [("linked-provider", "needs --target-major")],
        "without --target-major only linked-provider is skipped, so the "
        "other eight rules do not need it  <-- pinned defect")
    report = run_checks(xdata)
    check(report.ran == [("xdb-server", 5, 2, 2), ("xdb-database", 4, 2, 0)],
          "each rule's row reports its examined, FAIL and WARN counts")
    full = dict(inst, jobs=[jb("nightly", "b001")], versions=[],
                source_jobs=[], source_server_principals=[],
                dependencies=[], linked_servers=[], databases=[],
                objects=[], database_permissions=[])
    full["database_principals"] = [dp("dbo", "01")]
    report = run_checks(full, 16)
    check(report.fails == 0 and report.examined == 2 and gate(report) == 0,
          "a clean instance exits 0")
    warn_only = run_checks({"jobs": [jb("n", "a002")], "source_jobs":
                            [jb("n", "e001")],
                            "source_server_principals": [sp("old", "e001")],
                            "server_principals": logins + [sp("old", "e001")]})
    check(warn_only.fails == 0 and warn_only.warns == 1
          and gate(warn_only) == 0,
          "a warning alone never fails the gate")

    # ---- the report text
    lines = describe(run_checks({"jobs": [jb("n", "a002")],
                                 "server_principals": logins}))
    check(lines[0] == "files read: jobs, server_principals"
          and lines[1] == "rules run:",
          "the report starts with the files it read")
    check(any(l.startswith("  job-owner") and "1 examined" in l
              and "0 FAIL" in l for l in lines),
          "each rule that ran prints its examined count")
    check("rules skipped (each checked nothing):" in lines
          and any(l.startswith("  orphan-user") for l in lines),
          "skipped rules are listed under a heading that says they checked "
          "nothing")
    check(lines[-1] == "8 rule(s) were skipped and checked nothing. Clean "
          "means only the rules that ran.",
          "a clean verdict with skipped rules says clean covers only the "
          "rules that ran  <-- pinned defect")
    check(lines[-2].startswith("VERDICT: no FAIL in 1 row(s) examined by 1 "
                               "rule(s)"),
          "a clean verdict counts rows and rules")
    lines = describe(run_checks({}))
    check(lines[0] == "files read: none"
          and lines[-1].startswith("VERDICT: NOTHING CHECKED"),
          "an empty run says NOTHING CHECKED")
    check(not any(l.startswith("rules run") for l in lines),
          "and prints no rules-run heading")
    lines = describe(run_checks(allclean, 16))
    check(lines[-1].startswith("VERDICT: no FAIL in 12 row(s) examined by 9 "
                               "rule(s)")
          and not any("were skipped" in l for l in lines)
          and "rules skipped (each checked nothing):" not in lines,
          "a verdict with no skipped rule prints no skipped note")
    lines = describe(run_checks(xdata))
    check("  xdb-server           5 examined    2 FAIL    2 WARN" in lines,
          "a rule's line prints its counts in fixed columns")
    lines = describe(run_checks(vdata))
    check(any(l.startswith("FAIL  version-owner  version DEFAULT") for l in
              lines) and lines[-1].startswith("VERDICT: 7 FAIL, 0 WARN. The "
                                              "move is not verified."),
          "a failing run prints each finding and a verdict that says the "
          "move is not verified")
    multi = Report([Finding("r", FAIL, "a\nb", "x\r\n  y")], [("r", 1, 1, 0)],
                   [], [])
    check("WARN  job-copy  renamed_job" in describe(run_checks(copy))
          and WARN == "WARN",
          "a warning prints as WARN, two spaces, its rule and its subject")
    check("FAIL  r  a b" in describe(multi)
          and "      x y" in describe(multi),
          "a value with a line break prints on one line  <-- pinned defect")
    check(findings_rows(multi) == [{"severity": FAIL, "rule": "r",
                                    "subject": "a b", "detail": "x y"}],
          "the findings file holds one line per finding too")

    # ---- reading an export
    d = os.path.join(tmp, "read")
    put(d, "server_principals", ["name", "sid", "type"],
        [["a", "0x0A01", "S"], ["b", "0x0b02", "U"]])
    check(read_export(d) == {"server_principals": [
        {"name": "a", "sid": "0a01", "type": "S"},
        {"name": "b", "sid": "0b02", "type": "U"}]},
        "an export is read into rows and its SIDs are normalised")
    put(d, "other", ["x"], [["1"]])
    check(list(read_export(d)) == ["server_principals"],
          "a file that is not a known export is ignored")
    put(d, "database_principals", ["name", "sid", "authentication_type_desc"],
        [["a_role", "", "NONE"], ["a_user", "0xA1", "INSTANCE"],
         ["no_sid_user", "", "INSTANCE"]])
    read_back = read_export(d)["database_principals"]
    check([r["sid"] for r in read_back] == ["", "a1", ""],
          "a principal with an empty SID reads as an empty SID, not a "
          "refusal  <-- pinned defect")
    check([u["name"] for u, _ in orphans({
        "server_principals": [sp("a_user", "a1")],
        "database_principals": read_back})] == ["no_sid_user"],
        "and an INSTANCE user with no SID is an orphan, never a match")
    os.remove(os.path.join(d, "database_principals.csv"))
    put(d, "databases", ["name"], [])
    check(read_export(d)["databases"] == [],
          "a header with no rows reads as no rows")
    put(d, "linked_servers",
        ["Server_ID ", " NAME", "Provider", "Is_Data_Access_Enabled", "x"],
        [["0", "s", "p", "1", "extra"], ["3", "t", "q", "False", ""]])
    check(read_export(d)["linked_servers"] == [
        {"server_id": 0, "name": "s", "provider": "p",
         "is_data_access_enabled": True},
        {"server_id": 3, "name": "t", "provider": "q",
         "is_data_access_enabled": False}],
        "headers match ignoring case and surrounding spaces, and server_id and the "
        "boolean are typed")
    d2 = os.path.join(tmp, "bom")
    raw_put(d2, "databases", "\ufeffname\r\nmaster\r\n")
    check(read_export(d2)["databases"] == [{"name": "master"}],
          "a UTF-8 byte order mark does not hide the first column  "
          "<-- pinned defect")
    raw_put(d2, "versions", "name,owner\nv1\n,x,extra,more\n")
    check(read_export(d2)["versions"] == [{"name": "v1", "owner": ""},
                                          {"name": "", "owner": "x"}],
          "a short row reads its missing cells as blank and a long row's "
          "extra cells are ignored")
    raw_put(d2, "versions", "name,owner\n\n\nv2,o\n")
    check(read_export(d2)["versions"] == [{"name": "v2", "owner": "o"}],
          "blank lines are skipped")
    # A client such as sqlcmd writes a SQL NULL as the text NULL.
    d4 = os.path.join(tmp, "nulls")
    put(d4, "database_permissions",
        ["class_desc", "schema_name", "object_name", "column_name", "grantee",
         "permission_name", "state_desc"],
        [["OBJECT_OR_COLUMN", "dbo", "sites", "NULL", "edit_a", "UPDATE",
          "GRANT"],
         ["DATABASE", "NULL", "null", "Null", "edit_b", "SELECT", "GRANT"]])
    put(d4, "objects", ["schema_name", "object_name", "type"],
        [["dbo", "sites", "U"], ["dbo", "sites_evw", "V"]])
    put(d4, "dependencies",
        ["referencing_name", "referenced_server_name",
         "referenced_database_name", "referenced_schema_name",
         "referenced_entity_name"], [["p1", "NULL", "Null", "dbo", "NULL"]])
    put(d4, "linked_servers",
        ["server_id", "name", "provider", "is_data_access_enabled"],
        [["0", "srv_new", "NULL", "0"]])
    put(d4, "database_principals", ["name", "sid", "authentication_type_desc"],
        [["SYS", "NULL", "NONE"], ["INFORMATION_SCHEMA", "null", "NONE"]])
    put(d4, "server_principals", ["name", "sid", "type"],
        [["NULL", "0x01", "S"]])
    put(d4, "versions", ["name", "owner"], [["v", "NULL"]])
    nulls = read_export(d4)
    check(nulls["database_permissions"][0]["column_name"] == ""
          and nulls["database_permissions"][1]["schema_name"] == ""
          and nulls["database_permissions"][1]["object_name"] == ""
          and nulls["database_permissions"][1]["column_name"] == "",
          "the text NULL, in any case, is an empty permission scope  "
          "<-- pinned defect")
    check(nulls["dependencies"][0]["referenced_server_name"] == ""
          and nulls["dependencies"][0]["referenced_database_name"] == ""
          and nulls["dependencies"][0]["referenced_entity_name"] == "",
          "the text NULL is not a server, a database or an entity name  "
          "<-- pinned defect")
    check(nulls["linked_servers"][0]["provider"] == ""
          and nulls["versions"][0]["owner"] == ""
          and [r["sid"] for r in nulls["database_principals"]] == ["", ""],
          "the text NULL is an empty provider, version owner and database "
          "principal SID  <-- pinned defect")
    check(nulls["server_principals"][0]["name"] == "NULL",
          "a column that cannot be NULL keeps the text, so a login called "
          "NULL stays a login")
    code, out, err = run_cli([d4])
    check(code == 1 and "FAIL  evw-grant  dbo.sites_evw / edit_a" in out
          and "[NULL]" not in out,
          "a table grant exported with the text NULL as its column still "
          "reaches evw-grant, and no server is called NULL  "
          "<-- pinned defect")
    d5 = os.path.join(tmp, "nullschema")
    put(d5, "dependencies",
        ["referencing_name", "referenced_server_name",
         "referenced_database_name", "referenced_schema_name",
         "referenced_entity_name"], [["p2", "", "db", "NULL", "t"]])
    check(_four_part(read_export(d5)["dependencies"][0]) == "[db]..[t]",
          "the text NULL in referenced_schema_name is an empty schema, not "
          "a schema called NULL")
    raw_bytes = os.path.join(tmp, "cp1252")
    os.makedirs(raw_bytes)
    with io.open(os.path.join(raw_bytes, "databases.csv"), "wb") as handle:
        handle.write(b"name\r\ncaf\xe9\r\n")
    check(read_export(raw_bytes)["databases"] == [{"name": "caf\ufffd"}],
          "a byte that is not UTF-8 reads as U+FFFD, not a crash")
    d3 = os.path.join(tmp, "bad")
    raw_put(d3, "server_principals",
            'name,sid,type\n"a\nb",0x01,S\n\n"bad\nname",0xZZ,S\n')
    raises(lambda: read_export(d3), "a SID that is not hex refuses the "
           "export", InputError, "line 5, column sid")
    raw_put(d3, "linked_servers",
            "server_id,name,provider,is_data_access_enabled\nx,s,p,1\n")
    raises(lambda: read_export(os.path.join(tmp, "bad")),
           "a non-numeric server_id refuses the export", InputError,
           "column server_id")
    os.remove(os.path.join(d3, "server_principals.csv"))
    raw_put(d3, "linked_servers",
            "server_id,name,provider,is_data_access_enabled\n1,s,p,maybe\n")
    raises(lambda: read_export(d3), "a boolean that is not a boolean "
           "refuses the export", InputError, "column is_data_access_enabled")
    os.remove(os.path.join(d3, "linked_servers.csv"))
    raw_put(d3, "jobs", "")
    raises(lambda: read_export(d3), "an empty file refuses the export",
           InputError, "not even a header")
    raw_put(d3, "jobs", "name\nj\n")
    raises(lambda: read_export(d3), "a missing column refuses the export "
           "and names it", InputError, "columns not in the CSV: owner_sid")
    put(d3, "jobs", ["name", "owner_sid"], [["j", "0x01"]],
        encoding="utf-16")
    raises(lambda: read_export(d3), "a UTF-16 export is refused with the "
           "reason, not read as garbage", InputError, "Save the export as "
           "UTF-8")
    os.remove(os.path.join(d3, "jobs.csv"))

    # ---- the CLI, over a small export of every file
    demo = os.path.join(tmp, "demo")

    def write_demo(directory):
        put(directory, "server_principals", ["name", "sid", "type", "pw"],
            [["sa", "0x01", "S", "canary-hash-1"],
             ["sde", "0xA001", "S", "canary-hash-2"],
             ["edit_a", "0xA002", "S", "canary-hash-3"]])
        put(directory, "database_principals",
            ["name", "sid", "authentication_type_desc"],
            [["dbo", "0x01", "INSTANCE"], ["sde", "0xA0FF", "INSTANCE"],
             ["edit_a", "0xA002", "INSTANCE"],
             ["edit_b", "0xA004", "INSTANCE"]])
        put(directory, "versions", ["name", "owner"],
            [["DEFAULT", "sde"], ["wip", "edit_b"], ["q3", "edit_a"]])
        put(directory, "jobs", ["name", "owner_sid"],
            [["nightly", "0xA002"], ["weekly", "0xB999"]])
        put(directory, "linked_servers",
            ["server_id", "name", "provider", "is_data_access_enabled"],
            [["0", "srv_new", "", "0"], ["1", "link_erp", "SQLNCLI11", "1"]])
        put(directory, "dependencies",
            ["referencing_name", "referenced_server_name",
             "referenced_database_name", "referenced_schema_name",
             "referenced_entity_name"],
            [["proc1", "srv_old", "geodb", "dbo", "assets"],
             ["proc2", "", "otherdb", "dbo", "t"]])
        put(directory, "databases", ["name"], [["master"], ["geodb"]])
        put(directory, "objects", ["schema_name", "object_name", "type"],
            [["dbo", "sites", "U"], ["dbo", "sites_evw", "V"]])
        put(directory, "database_permissions",
            ["class_desc", "schema_name", "object_name", "column_name",
             "grantee", "permission_name", "state_desc"],
            [["OBJECT_OR_COLUMN", "dbo", "sites", "", "edit_a", "SELECT",
              "GRANT"],
             ["OBJECT_OR_COLUMN", "dbo", "sites", "", "edit_a", "UPDATE",
              "GRANT"],
             ["OBJECT_OR_COLUMN", "dbo", "sites_evw", "", "edit_a", "SELECT",
              "GRANT"]])
        put(directory, "source_server_principals", ["name", "sid", "type"],
            [["sa", "0x01", "S"], ["report_login", "0xA050", "S"]])
        put(directory, "source_jobs", ["name", "owner_sid"],
            [["nightly", "0xA002"], ["monthly", "0xA002"]])

    write_demo(demo)

    def snapshot(directory):
        """Every file name in the directory with its exact bytes."""
        result = {}
        for name in sorted(os.listdir(directory)):
            with io.open(os.path.join(directory, name), "rb") as handle:
                result[name] = handle.read()
        return result

    demo_before = snapshot(demo)
    code, out, err = run_cli([demo, "--target-major", "16"])
    check(code == 1 and err == "", "the demo export fails the gate with exit 1")
    check(out.startswith("sqlmove: %s\nfiles read: " % demo),
          "the output starts with the directory it read")
    for rule in ("orphan-user", "version-owner", "job-owner", "job-copy",
                 "login-missing", "xdb-server", "xdb-database",
                 "linked-provider", "evw-grant"):
        check(any(l.startswith("  %-16s" % rule) for l in out.splitlines()),
              "the rule %s ran and printed its row" % rule)
    check("FAIL  orphan-user  sde" in out and "FAIL  orphan-user  edit_b"
          in out, "the orphaned users are listed")
    check("FAIL  evw-grant  dbo.sites_evw / edit_a" in out
          and "UPDATE is granted to edit_a on dbo.sites and not on its "
          "versioned view dbo.sites_evw" in out,
          "the missing view grant is listed with its permission")
    check("FAIL  xdb-server  proc1 -> [srv_old].[geodb].[dbo].[assets]"
          in out, "the loopback name that no longer exists is listed")
    check("FAIL  linked-provider  link_erp" in out,
          "the Native Client provider is listed with --target-major 16")
    check("\nVERDICT: " in out and "The move is not verified." in out,
          "the verdict says the move is not verified")
    check("canary-hash" not in out and "canary-hash" not in err,
          "a column the tool does not read is never printed  "
          "<-- pinned defect")
    code, out2, err = run_cli([demo])
    check(code == 1 and "linked-provider  needs --target-major" in out2
          and "FAIL  linked-provider" not in out2,
          "without --target-major the provider rule is listed as skipped")
    check("Check only" not in out2 and "wrote" not in out2,
          "a run with no --out prints no note about a findings file")

    # Nothing is written without --apply.
    target = os.path.join(tmp, "findings.csv")
    code, out, err = run_cli([demo, "--out", target])
    check(code == 1 and "Check only. %s was not written. Re-run with "
          "--apply." % target in out and not os.path.exists(target),
          "--out without --apply writes nothing and says so")
    code, out, err = run_cli([demo, "--target-major", "16", "--out", target,
                              "--apply"])
    check(code == 1 and os.path.exists(target)
          and "wrote %s" % target in out, "--out with --apply writes the file")
    with io.open(target, encoding="utf-8", newline="") as handle:
        written = list(csv.DictReader(handle))
    check(len(written) == out.count("\nFAIL  ") + out.count("\nWARN  ")
          and set(written[0]) == {"severity", "rule", "subject", "detail"},
          "the findings file holds one row per finding printed")
    with io.open(target, encoding="utf-8") as handle:
        check("canary-hash" not in handle.read(),
              "and no unread column reaches the findings file  "
              "<-- pinned defect")
    check(snapshot(demo) == demo_before and len(demo_before) == len(FILES),
          "after the dry runs and the --apply run the export directory holds "
          "the same files with the same bytes  <-- pinned defect")
    code, out, err = run_cli([demo, "--out", os.path.join(demo, "jobs.csv")])
    check(code == 64 and "is also an input export" in err and out == "",
          "--out naming an input export is refused, on a dry run too  "
          "<-- pinned defect")
    code, out, err = run_cli([demo, "--out", os.path.join(tmp, "nodir",
                                                          "f.csv"),
                              "--apply"])
    check(code == 2 and "could not write" in err
          and "The move is not verified." in out,
          "a findings file that cannot be written exits 2 with the verdict "
          "already printed")
    code, out, err = run_cli([demo, "--apply"])
    check(code == 64 and "--apply needs --out" in err and out == "",
          "--apply with nothing to write is a usage error")
    keep = os.path.join(tmp, "keep.txt")
    with io.open(keep, "w", encoding="utf-8") as handle:
        handle.write("precious\n")
    for extra in ([], ["--apply"]):
        code, out, err = run_cli([demo, "--out", keep] + extra)
        with io.open(keep, encoding="utf-8") as handle:
            kept = handle.read()
        check(code == 64 and "already exists" in err and out == ""
              and kept == "precious\n",
              "--out naming any file that exists is refused%s and the file "
              "is untouched  <-- pinned defect"
              % (", with --apply," if extra else ", on a dry run,"))
    raises(lambda: write_findings(keep, Report([], [], [], [])),
           "the findings file is created exclusively, so a file that "
           "appears after the check is never overwritten", FileExistsError)

    # Usage errors.
    code, out, err = run_cli([])
    check(code == 64 and "export directory is required" in err and out == "",
          "no directory is a usage error")
    for bad in ("4", "8", "100", "-1"):
        code, out, err = run_cli([demo, "--target-major", bad])
        check(code == 64 and out == "",
              "--target-major %s is a usage error" % bad)
    code, out, err = run_cli([demo, "--target-major", "sixteen"])
    check(code == 64, "--target-major that is not a number is a usage error")
    code, out, err = run_cli([os.path.join(tmp, "absent")])
    check(code == 2 and "is not a directory" in err and out == "",
          "a directory that does not exist exits 2")

    # Abbreviations. With them on, --ap parses as --apply and writes.
    for prefix, full in (("--ap", "--apply"), ("--tar", "--target-major"),
                         ("--o", "--out"), ("--self", "--self-test"),
                         ("--require", "--require-all")):
        arg_err = io.StringIO()
        refused = False
        with contextlib.redirect_stderr(arg_err):
            try:
                _parse([demo, prefix] + (
                    [] if prefix in ("--ap", "--self", "--require")
                    else ["16"]))
            except SystemExit:
                refused = True
        check(refused and "unrecognized arguments" in arg_err.getvalue(),
              "a prefix of %s is refused, not read as %s%s" % (
                  full, full, "  <-- pinned defect" if full in (
                      "--apply", "--require-all") else ""))
    code, out, err = run_cli([demo, "--ap", "--out", target])
    check(code == 64 and out == "",
          "main turns a refused prefix into exit 64 and writes nothing")

    # Parsed defaults.
    a = _parse([demo])
    check(a.apply is False and a.out is None and a.target_major is None,
          "--apply defaults to off, and --out and --target-major to nothing")
    check(a.export_dir == demo and a.self_test is False,
          "the export directory is read positionally")
    check(_parse(["--self-test"]).self_test and _parse(["--self-test"])
          .export_dir is None, "--self-test needs no directory")
    check(_parse([demo, "--target-major", "16"]).target_major == 16
          and _parse([demo, "--out", "o.csv"]).out == "o.csv"
          and _parse([demo, "--apply"]).apply is True,
          "--target-major, --out and --apply are read")

    # A refused export exits 3 and writes nothing.
    refused_dir = os.path.join(tmp, "refused")
    write_demo(refused_dir)
    raw_put(refused_dir, "versions", "name\nv1\n")
    refused_out = os.path.join(tmp, "refused.csv")
    code, out, err = run_cli([refused_dir, "--out", refused_out, "--apply"])
    check(code == 3 and out.startswith("REFUSED   ")
          and "columns not in the CSV: owner" in out
          and "VERDICT: REFUSED. Nothing was checked." in out
          and not os.path.exists(refused_out),
          "a bad export exits 3, names the file and column, and writes "
          "nothing  <-- pinned defect")
    raw_put(refused_dir, "versions", "name,owner\nv1,x\n")
    raw_put(refused_dir, "databases", "name\n" + "x" * 140000 + "\n")
    code, out, err = run_cli([refused_dir])
    check(code == 2 and "field larger than field limit" in err,
          "a field over the csv limit exits 2, not 70 or a traceback")
    real_load = globals()["load_table"]

    def unreadable(path, stem):
        raise IOError("probe: cannot read")

    try:
        globals()["load_table"] = unreadable
        code, out, err = run_cli([demo])
    finally:
        globals()["load_table"] = real_load
    check(code == 2 and "probe: cannot read" in err and out == "",
          "a file that cannot be read exits 2")

    # An empty directory checks nothing.
    empty = os.path.join(tmp, "empty")
    os.makedirs(empty)
    code, out, err = run_cli([empty])
    check(code == 4 and "VERDICT: NOTHING CHECKED" in out,
          "a directory with no exports exits 4, not 0  <-- pinned defect")

    # A clean instance exits 0.
    clean = os.path.join(tmp, "clean")
    put(clean, "server_principals", ["name", "sid", "type"],
        [["sa", "0x01", "S"]])
    put(clean, "database_principals",
        ["name", "sid", "authentication_type_desc"],
        [["dbo", "0x01", "INSTANCE"]])
    code, out, err = run_cli([clean])
    check(code == 0 and "VERDICT: no FAIL in 1 row(s) examined by 1 rule(s)"
          in out and "skipped and checked nothing" in out,
          "a clean run exits 0 and still says that skipped rules checked "
          "nothing")
    code, out, err = run_cli([clean, "--require-all"])
    check(code == 5 and "INCOMPLETE: --require-all is set and 8 rule(s) "
          "checked nothing" in out and "VERDICT: no FAIL" in out,
          "--require-all turns a clean run that skipped rules into exit 5  "
          "<-- pinned defect")
    code, out, err = run_cli([demo, "--require-all"])
    check(code == 1 and "INCOMPLETE" not in out,
          "--require-all never hides a failed rule behind exit 5")
    code, out, err = run_cli([empty, "--require-all"])
    check(code == 4 and "INCOMPLETE" not in out,
          "--require-all keeps exit 4 for a run that examined nothing")
    for low_high in ("9", "99"):
        code, out, err = run_cli([clean, "--target-major", low_high])
        check(code == 0, "--target-major %s, inside the accepted range, "
              "runs" % low_high)

    # A console that cannot encode a name must not crash the run.
    cjk = os.path.join(tmp, "cjk")
    put(cjk, "server_principals", ["name", "sid", "type"],
        [["sa", "0x01", "S"]])
    put(cjk, "database_principals", ["name", "sid", "authentication_type_desc"],
        [["\u7528\u6237", "0xA0FF", "INSTANCE"]])
    raw_out = io.BytesIO()
    console = io.TextIOWrapper(raw_out, encoding="cp1252", errors="strict",
                               newline="")
    with contextlib.redirect_stdout(console), contextlib.redirect_stderr(
            io.StringIO()):
        code = main([cjk])
    console.flush()
    check(code == 1 and b"FAIL  orphan-user  ??" in raw_out.getvalue(),
          "a name the console cannot encode prints as ? and the run exits 1, "
          "not 70  <-- pinned defect")

    # An upper-case SID in jobs.csv matches a lower-case login SID.
    up = os.path.join(tmp, "upper")
    put(up, "server_principals", ["name", "sid", "type"],
        [["svc", "0xb001", "U"]])
    put(up, "jobs", ["name", "owner_sid"], [["nightly", "0XB001"]])
    code, out, err = run_cli([up])
    check(code == 0 and "\nFAIL  " not in out,
          "a job owner SID written as 0X in capitals matches the login  "
          "<-- pinned defect")

    # A crash is not a finding.
    real_run = globals()["run_checks"]

    def boom(*args, **kw):
        raise RuntimeError("probe")

    try:
        globals()["run_checks"] = boom
        code, out, err = run_cli([demo])
    finally:
        globals()["run_checks"] = real_run
    check(code == 70 and "unexpected RuntimeError: probe" in err
          and "Traceback" in err and "VERDICT" not in out,
          "an unexpected exception exits 70, not the 1 that means a rule "
          "failed  <-- pinned defect")

    # The CLI hand-off that no other assertion could see fail.
    real_self_test = globals()["self_test"]
    try:
        globals()["self_test"] = lambda: 7
        handed = run_cli(["--self-test", "ignored"])[0]
    finally:
        globals()["self_test"] = real_self_test
    check(handed == 7,
          "main returns the exit status of --self-test, so a red self-test "
          "fails CI  <-- pinned defect")

    # The temp directory goes even when the body raises.
    seen = []

    def exploding(path):
        seen.append(path)
        raise RuntimeError("probe")

    real_body = globals()["_self_test"]
    try:
        globals()["_self_test"] = exploding
        try:
            self_test()
        except RuntimeError:
            seen.append("raised")
    finally:
        globals()["_self_test"] = real_body
    check(len(seen) == 2 and seen[1] == "raised"
          and not os.path.exists(seen[0]),
          "a self-test that raises still removes its temp directory  "
          "<-- pinned defect")

    # ---- the harness itself. A check() that cannot record a failure would
    # report every defect above as a pass. The probe's output is swallowed so
    # a green run prints no FAIL line.
    quiet = sys.stdout
    sys.stdout = io.StringIO()
    mark = len(failed)
    try:
        check(False, "probe: a false condition must be recorded as a failure")
        raises(lambda: None, "probe: a call that raises nothing must fail")
        raises(lambda: [][0], "probe: the wrong exception must fail")
        raises(lambda: parse_sid("zz"), "probe: a missing needle must fail",
               ValueError, "no such text")
    finally:
        sys.stdout = quiet
    probe = failed[mark:]
    del failed[mark:]
    check(len(probe) == 4,
          "check() and raises() really do record a failure  <-- pinned defect")
    raises(lambda: parse_sid("zz"),
           "and raises() accepts the exception and text it is looking for",
           ValueError, "not a SID")

    def summary(passed_count, failures):
        print("-" * 68)
        total = passed_count + len(failures)
        if failures:
            print("%d assertions, %d failed" % (total, len(failures)))
            for f in failures:
                print("  FAILED: %s" % f)
            return 1
        print("%d assertions, 0 failed" % total)
        return 0

    # The footer on its red path. A footer that could only print 0 failed
    # would hide every FAIL line above it from anyone who reads the last line.
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        red = summary(1, ["probe one", "probe two"])
    check(red == 1 and "3 assertions, 2 failed" in buf.getvalue()
          and "  FAILED: probe two" in buf.getvalue(),
          "the footer reports failures by count and by name, and exits 1"
          "  <-- pinned defect")

    # ---- what the README says about the source: ASCII, no f-strings, the
    # standard library only, and no module that could open a connection.
    with io.open(os.path.abspath(__file__), "rb") as handle:
        raw_source = handle.read()
    tree = ast.parse(raw_source)
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.add(node.module.split(".")[0])
    check(max(raw_source) < 128, "the source is pure ASCII")
    check(not any(isinstance(n, ast.JoinedStr) for n in ast.walk(tree)),
          "the source has no f-string, so Python 3.9 reads it")
    check(modules == {"__future__", "argparse", "ast", "collections",
                      "contextlib", "csv", "importlib", "io", "os", "re",
                      "shutil", "sys", "tempfile", "traceback"},
          "the source imports only these standard modules, and none of them "
          "opens a socket on its own")
    check(not modules & {"socket", "ssl", "http", "urllib", "ftplib",
                         "smtplib", "subprocess", "pyodbc", "pymssql"},
          "no network, subprocess or database-driver module is imported")

    # ---- importing the module runs nothing. Another script may import it
    # for the core, and must not start a run.
    spec = importlib.util.spec_from_file_location(
        "sqlmove_imported", os.path.abspath(__file__))
    imported = importlib.util.module_from_spec(spec)
    buf = io.StringIO()
    # No bytecode cache, so the self-test writes nothing outside its own
    # temporary directory.
    cache_before = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        with contextlib.redirect_stdout(buf):
            spec.loader.exec_module(imported)
    finally:
        sys.dont_write_bytecode = cache_before
    check(buf.getvalue() == "" and imported.gate(imported.run_checks({})) == 4,
          "importing the module prints nothing and exposes the core")

    return summary(passed[0], failed)


# ------------------------------------------------------------------------ CLI

def _parse(argv):
    ap = argparse.ArgumentParser(
        prog="sqlmove.py",
        description="One read-only after-move verdict over exported SQL "
                    "Server catalog rows.",
        epilog="Nothing is written without --apply.",
        allow_abbrev=False,
    )
    ap.add_argument("export_dir", nargs="?", metavar="EXPORT_DIR",
                    help="a directory of catalog exports, one CSV per view")
    ap.add_argument("--target-major", dest="target_major", type=int,
                    help="major version of the destination SQL Server (16 "
                         "for SQL Server 2022). Needed by linked-provider.")
    ap.add_argument("--out", help="path for the findings CSV")
    ap.add_argument("--apply", action="store_true",
                    help="write --out. Without this nothing is written.")
    ap.add_argument("--require-all", dest="require_all", action="store_true",
                    help="exit 5 when no rule failed but a rule was skipped")
    ap.add_argument("--self-test", dest="self_test", action="store_true",
                    help="run the offline assertions and exit")
    return ap.parse_args(argv)


def _tolerate_odd_characters():
    """Make print() unable to fail on a character the console cannot encode."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(errors="replace")


def _same_file(a, b):
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(
        os.path.realpath(b))


def main(argv=None):
    """Run the CLI. An error this code did not anticipate exits 70, because 1
    is the code a scheduled job reads as 'a rule failed'."""
    _tolerate_odd_characters()
    try:
        return _run(argv)
    except Exception as exc:
        print("error: unexpected %s: %s. This is a fault in the tool, not a "
              "finding about the data." % (type(exc).__name__, exc),
              file=sys.stderr)
        traceback.print_exc()
        return 70


def _run(argv):
    try:
        args = _parse(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        # argparse exits 2 on a flag it refuses, and 2 here means a file
        # could not be read. A mistyped --ap is a usage error, so it gets 64.
        return 64 if exc.code == 2 else exc.code

    if args.self_test:
        return self_test()

    if not args.export_dir:
        print("error: an export directory is required. Use --self-test to "
              "verify the tool without one.", file=sys.stderr)
        return 64
    if args.target_major is not None and not 9 <= args.target_major <= 99:
        print("error: --target-major must be a SQL Server major version, "
              "such as 16.", file=sys.stderr)
        return 64
    if args.apply and not args.out:
        print("error: --apply needs --out.", file=sys.stderr)
        return 64
    if not os.path.isdir(args.export_dir):
        print("error: %s is not a directory." % args.export_dir,
              file=sys.stderr)
        return 2
    if args.out:
        for stem in FILES:
            if _same_file(args.out, os.path.join(args.export_dir,
                                                 stem + ".csv")):
                # Checked on a dry run too: the run that would clobber an
                # export should say so before --apply is added.
                print("error: --out %s is also an input export. Name a new "
                      "file." % args.out, file=sys.stderr)
                return 64
        if os.path.lexists(args.out):
            # A hard link to an export exists too, so it is refused here.
            print("error: --out %s already exists. Name a new file; nothing "
                  "is overwritten." % args.out, file=sys.stderr)
            return 64

    try:
        data = read_export(args.export_dir)
    except InputError as exc:
        print("REFUSED   %s" % exc)
        print("\nVERDICT: REFUSED. Nothing was checked.")
        return 3
    except (IOError, OSError, csv.Error) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    report = run_checks(data, args.target_major)
    print("sqlmove: %s" % args.export_dir)
    for line in describe(report):
        print(line)

    if args.out:
        if args.apply:
            try:
                write_findings(args.out, report)
            except (IOError, OSError, csv.Error) as exc:
                print("error: could not write %s: %s" % (args.out, exc),
                      file=sys.stderr)
                return 2
            print("\nwrote %s" % args.out)
        else:
            print("\nCheck only. %s was not written. Re-run with --apply."
                  % args.out)

    code = gate(report, args.require_all)
    if code == 5:
        print("\nINCOMPLETE: --require-all is set and %d rule(s) checked "
              "nothing, so this is not a full verdict. Exit 5."
              % len(report.skipped))
    return code


if __name__ == "__main__":
    sys.exit(main())
