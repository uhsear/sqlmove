# sqlmove

Give one read-only verdict on a geodatabase that was moved to another SQL Server instance. It
reads CSV exports of catalog views and says what the move left broken: database users with no
login, versions owned by those users, jobs with no owner, names that no longer resolve, and a
grant that the table has and its `_evw` view does not. It opens no connection, copies nothing and
repairs nothing.

A geodatabase moved to a new instance over a weekend. The restore finished. The row counts
matched. The scripts that copy logins, jobs and linked servers printed "succeeded" for every item.
The story combines failures from several moves, and the details are changed.

Nothing was wrong for a week. Then the failures arrived one at a time, each far from the move. A
stored procedure read the geodatabase through a four-part name that held the old server name. The
catalog records such a name without resolving it, so nothing warned at restore time. A nightly job
was owned by a login that never moved. A database user that owned edit versions had no login on
the new instance, so nobody could connect as that user and clean the versions up. And a table that
the editors could write had no grant on its `_evw` view. Esri says those grants are what let a
user edit through SQL and the versioned view.

One of the repairs was false. A rehearsal reported that every orphaned user was fixed. The check
had asked `SUSER_SID()` whether a login existed. That function can answer from Windows, so a live
directory account looked like a login even when no login existed on the instance. A second query
that read `sys.server_principals` directly found the users still orphaned. The repair command
returns a row for a user it failed to fix as well, with a `Status` that says so, and a summary
that counts rows does not read it.

The defence everybody reaches for first is the copy tool's own summary. It says what the tool did.
It does not say what the new instance holds. This tool reads what the new instance holds, from
rows you can keep, and never from a function that asks the server or Windows.

```
$ python sqlmove.py --self-test
sqlmove self-test: temporary files only, no network, no credentials
--------------------------------------------------------------------
...
PASS  a Windows user with no login row is an orphan, whatever a directory lookup would say  <-- pinned defect
PASS  a same-name login with another SID names both SIDs and is not called a match  <-- pinned defect
PASS  an orphan's version says to delete it before the user is dropped  <-- pinned defect
...
PASS  the missing-server message names the cause and the fix  <-- pinned defect
PASS  a loopback name that no longer exists is reported once, as a missing server, not again as a missing database  <-- pinned defect
PASS  a grant on a versioned table with none on its _evw view is reported  <-- pinned defect
...
PASS  and checking nothing exits 4, not 0  <-- pinned defect
PASS  a clean verdict with skipped rules says clean covers only the rules that ran  <-- pinned defect
...
PASS  a prefix of --apply is refused, not read as --apply  <-- pinned defect
...
PASS  a bad export exits 3, names the file and column, and writes nothing  <-- pinned defect
PASS  a directory with no exports exits 4, not 0  <-- pinned defect
...
PASS  importing the module prints nothing and exposes the core
--------------------------------------------------------------------
165 assertions, 0 failed
```

The full run prints all 165 assertions. Each `...` line above is where this block is cut.

## What already exists

dbatools does the moving, and does it well. `Copy-DbaLogin` transfers logins "while preserving
authentication details and security context", and copies passwords "with original SIDs to
prevent orphaned users". `Get-DbaDbOrphanUser` lists orphaned users, `Repair-DbaDbOrphanUser`
remaps them, and `Test-DbaLinkedServerConnection` tries every linked server
([dbatools](https://dbatools.io/)). Use them to move and to repair. They connect to live
instances and they act.

This tool is the check you run after them, or after a manual restore. It does not move or repair
anything. It adds four things the general tools do not know about:

- It decides from exported rows, so the answer is a file you can keep and run again.
- It knows the geodatabase cases: an orphaned `sde` user, versions owned by an orphan and the
  order to clean them up in, and a table grant that its `_evw` view lacks.
- It reads a skipped check as unchecked. A rule whose file is absent is listed as skipped, and a
  run that examined no row exits 4, not 0.
- It never decides from `SUSER_SID()`. The two catalog views are the only evidence.

A search of GitHub for the name `sqlmove` found two unrelated repositories (`sqlmovers`, with no
description, and a MySQL-to-SQL-Server copier) on the day it was run. Searches for a post-move
SQL Server check and for a geodatabase restore check returned no repository. That shows only
that the searches found nothing.

## Requirements

Python 3.9 or newer and nothing else. No `arcpy`, no third-party package, no network, no database
driver. The input is CSV, which any SQL Server client can export.

The self-test prints the same 165 assertions, line for line, on Windows (Python 3.13.2, 3.12.10
and 3.9.25) and on Ubuntu (Python 3.12.3). `coverage run --branch sqlmove.py --self-test` reports
100 percent of 835 statements and 206 branches.

```
git clone https://github.com/uhsear/sqlmove.git
```

## Usage

Export the catalog views below from the destination instance into one directory. Save each file
as UTF-8. Then run the tool on the directory.

```
python sqlmove.py --self-test
python sqlmove.py EXPORT_DIR
python sqlmove.py EXPORT_DIR --target-major 16
python sqlmove.py EXPORT_DIR --out findings.csv --apply
```

| Flag | Default | What it does |
|---|---|---|
| `EXPORT_DIR` | none | A directory of exports. Required unless `--self-test`. |
| `--target-major` | off | Major version of the destination SQL Server, 16 for SQL Server 2022. The `linked-provider` rule needs it. |
| `--out` | off | Write every finding to this CSV. Needs `--apply`. |
| `--apply` | off | Actually write. Without it nothing is written. |
| `--self-test` | off | Run the assertions and exit. Other flags are ignored. |

Every flag must be spelled in full. The parser sets `allow_abbrev=False`, so `--ap` is refused
with exit 64 instead of being read as `--apply`, and `--tar` and `--o` are refused too.

`--out` must name a new file. A path that is also one of the input exports is refused with exit
64, on a dry run too.

### The exports

A rule runs when all of its files are in the directory. A column the tool does not read is
ignored and never printed. Header names match ignoring case and spaces. A SID is hex with or
without `0x`. The queries below are what the author would run. They were written from the
documentation and were not run against a live SQL Server for this repository, so check them in
your version.

| File | Catalog view | Columns read |
|---|---|---|
| `server_principals.csv` | [`sys.server_principals`](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-principals-transact-sql) | `name`, `sid`, `type` |
| `database_principals.csv` | `sys.database_principals` | `name`, `sid`, `authentication_type_desc` |
| `database_permissions.csv` | [`sys.database_permissions`](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-database-permissions-transact-sql) | `class_desc`, `schema_name`, `object_name`, `column_name`, `grantee`, `permission_name`, `state_desc` |
| `objects.csv` | `sys.objects` | `schema_name`, `object_name`, `type` |
| `jobs.csv` | [`msdb.dbo.sysjobs`](https://learn.microsoft.com/en-us/sql/relational-databases/system-tables/dbo-sysjobs-transact-sql) | `name`, `owner_sid` |
| `linked_servers.csv` | [`sys.servers`](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-servers-transact-sql) | `server_id`, `name`, `provider`, `is_data_access_enabled` |
| `dependencies.csv` | [`sys.sql_expression_dependencies`](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-sql-expression-dependencies-transact-sql) | `referencing_name`, `referenced_server_name`, `referenced_database_name`, `referenced_schema_name`, `referenced_entity_name` |
| `databases.csv` | `sys.databases` | `name` |
| `versions.csv` | `sde.SDE_versions` or `dbo.SDE_versions` | `name`, `owner` |
| `source_server_principals.csv` | `sys.server_principals` on the source | `name`, `sid`, `type` |
| `source_jobs.csv` | `msdb.dbo.sysjobs` on the source | `name`, `owner_sid` |

```sql
-- server_principals.csv, source_server_principals.csv (SID as 0x hex: CONVERT style 1)
SELECT name, CONVERT(varchar(172), sid, 1) AS sid, type FROM sys.server_principals;

-- database_principals.csv (run in the geodatabase)
SELECT name, CONVERT(varchar(172), sid, 1) AS sid, authentication_type_desc
FROM sys.database_principals;

-- jobs.csv, source_jobs.csv
SELECT name, CONVERT(varchar(172), owner_sid, 1) AS owner_sid FROM msdb.dbo.sysjobs;

-- linked_servers.csv (the local server is the row with server_id 0)
SELECT server_id, name, provider, is_data_access_enabled FROM sys.servers;

-- dependencies.csv (run in the geodatabase)
SELECT OBJECT_NAME(referencing_id) AS referencing_name, referenced_server_name,
       referenced_database_name, referenced_schema_name, referenced_entity_name
FROM sys.sql_expression_dependencies;

-- databases.csv
SELECT name FROM sys.databases;

-- objects.csv (run in the geodatabase)
SELECT s.name AS schema_name, o.name AS object_name, o.type
FROM sys.objects AS o JOIN sys.schemas AS s ON s.schema_id = o.schema_id
WHERE o.type IN ('U', 'V');

-- database_permissions.csv (run in the geodatabase; class 0 database, 1 object, 3 schema)
SELECT p.class_desc,
       COALESCE(so.name, ss.name) AS schema_name, o.name AS object_name,
       c.name AS column_name, g.name AS grantee, p.permission_name, p.state_desc
FROM sys.database_permissions AS p
JOIN sys.database_principals AS g ON g.principal_id = p.grantee_principal_id
LEFT JOIN sys.objects AS o ON p.class = 1 AND o.object_id = p.major_id
LEFT JOIN sys.schemas AS so ON so.schema_id = o.schema_id
LEFT JOIN sys.schemas AS ss ON p.class = 3 AND ss.schema_id = p.major_id
LEFT JOIN sys.columns AS c ON p.class = 1 AND p.minor_id > 0
     AND c.object_id = p.major_id AND c.column_id = p.minor_id
WHERE p.class IN (0, 1, 3);

-- versions.csv: Esri lists SDE_versions among the system tables and does not list its
-- columns. Check INFORMATION_SCHEMA.COLUMNS in your release, then export name and owner.
```

A database role or schema can have a NULL SID in `sys.database_principals`. An empty SID is
accepted there and nowhere else, and a user that authenticates through the instance with no SID
is an orphan.

## What it checks

| Rule | Needs | FAIL when | Source |
|---|---|---|---|
| `orphan-user` | `server_principals`, `database_principals` | An `INSTANCE` user's SID is in no login. A same-name login with another SID is named as such, never as a match. | [Microsoft: orphaned users](https://learn.microsoft.com/en-us/sql/sql-server/failover-clusters/troubleshoot-orphaned-users-sql-server) gives the same query. |
| `version-owner` | the two above, `versions` | A version's owner is an orphan or is not a user. The message gives the order: do not drop the user first. | [Esri: delete a traditional version](https://doc.esri.com/en/arcgis-pro/latest/help/data/geodatabases/overview/delete-a-traditional-version.html) |
| `job-owner` | `server_principals`, `jobs` | The owner SID matches no login. | [Microsoft: metadata on another server](https://learn.microsoft.com/en-us/sql/relational-databases/databases/manage-metadata-when-making-a-database-available-on-another-server) |
| `job-copy` | `source_jobs`, `jobs`, both principals | A job is on the source and not the destination. WARN when its owner changed. | same page |
| `login-missing` | both principals | A source login is absent, or has another SID. Instance-owned logins are skipped. | same page |
| `xdb-server` | `dependencies`, `linked_servers` | A four-part name names a server that is not in `sys.servers`, or a linked server with data access off. WARN for the local server's own name. | [sys.sql_expression_dependencies](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-sql-expression-dependencies-transact-sql), [sys.servers](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-servers-transact-sql) |
| `xdb-database` | `dependencies`, `linked_servers`, `databases` | A cross-database name names a database that is not on the instance. | same pages |
| `linked-provider` | `linked_servers`, `--target-major` | `SQLNCLI11` on SQL Server 2022 or later. WARN for `SQLOLEDB` and other Native Client versions. | [SQL Server Native Client](https://learn.microsoft.com/en-us/sql/relational-databases/native-client/sql-server-native-client) |
| `evw-grant` | `objects`, `database_permissions` | A table grants SELECT, INSERT, UPDATE, DELETE or CONTROL to a principal, and its `<table>_evw` view does not, by object, schema or database grant. A DENY is named as a denial. | [Esri: privileges](https://doc.esri.com/en/arcgis-pro/latest/help/data/geodatabases/manage-sql-server/privileges-sqlserver.html), [Esri: versioned view](https://desktop.arcgis.com/en/arcmap/latest/manage-data/using-sql-with-gdbs/what-is-a-versioned-view.htm) |

What the documentation says, and what it does not:

- **Orphans.** A database user is orphaned when its SID is not in `master`. The user can become
  orphaned after a restore onto an instance where the login was never created, and a login that
  is created again has a different SID. This is why the tool compares SIDs and says a name match
  is not enough.
- **`SUSER_SID()`.** Its page shows the function used to "obtain the SID from Windows", and it
  has an option that decides whether the Windows name is checked against the one SQL Server
  stores. The page does not say outright that it answers for a name with no login. The rehearsal
  described above is the evidence for that, and it was seen once. The tool avoids the function
  either way.
- **Silent at restore time.** For cross-database and cross-server entities the catalog page says
  "Entity names are reported; however, entity IDs aren't resolved." The export therefore holds the
  name, and this tool checks the name against `sys.servers` and `sys.databases`. That the restore
  raised no error and the call failed later is what the author saw. The pages above do not
  describe the error, so the tool does not quote one.
- **Native Client.** SQL Server Native Client "isn't shipped with" SQL Server 2022 and later, and
  `SQLNCLI` and `SQLNCLI11` "aren't recommended for new application development". From SQL
  Server 2019 the provider name `SQLNCLI` maps to the Microsoft OLE DB Driver (`sys.servers`
  page), so the tool does not flag it. It flags `SQLNCLI11` as FAIL on version 16 or later and
  treats the other Native Client names as WARN, because the pages do not name them.
- **Versioned view grants.** Esri says that when you grant SELECT, INSERT, UPDATE and DELETE
  through ArcGIS on a traditionally versioned table, "those privileges are automatically granted
  on the associated versioned view". The page says such grants must be made through ArcGIS by
  the dataset owner. It does not say what a T-SQL `GRANT` on the table does to the view. A
  `GRANT` names one securable ([GRANT Object
  Permissions](https://learn.microsoft.com/en-us/sql/t-sql/statements/grant-object-permissions-transact-sql)),
  so the tool reports only what the export shows: a grant on the table and none that reaches
  the view. The view is the table name with `_evw` added.
- **Version cleanup.** Only a version's owner or the geodatabase administrator can delete a
  version, and deleting one that was not posted loses its edits. The tool states exactly that.
  It does not claim that dropping the user first corrupts anything, because the pages do not say
  so.
- **Jobs and logins.** Jobs and logins live outside the user database, so a restore does not carry
  them, and the logins a job uses must exist on the destination (Microsoft page above).
- **Not covered.** There is no rule for database-level settings after a restore. The source
  notes claimed that a restore wipes them. The pages read for this tool say that TRUSTWORTHY,
  `DB_CHAINING` and the Service Broker options are OFF after an attach or a restore, and say
  nothing about the other options, so the tool ships no rule it cannot support.

## A real run

`after_move` is a synthetic export of an instance after a move, with one fault planted for each
rule. Every name, SID and server in it is made up. The run is on Ubuntu with Python 3.12.3.

```
$ python3 sqlmove.py after_move --target-major 16
sqlmove: after_move
files read: database_permissions, database_principals, databases, dependencies, jobs, linked_servers, objects, server_principals, source_jobs, source_server_principals, versions
rules run:
  orphan-user          5 examined    3 FAIL    0 WARN
  version-owner        3 examined    2 FAIL    0 WARN
  job-owner            2 examined    1 FAIL    0 WARN
  job-copy             3 examined    1 FAIL    0 WARN
  login-missing        6 examined    3 FAIL    0 WARN
  xdb-server           3 examined    2 FAIL    0 WARN
  xdb-database         1 examined    1 FAIL    0 WARN
  linked-provider      2 examined    1 FAIL    0 WARN
  evw-grant            2 examined    1 FAIL    0 WARN

FAIL  orphan-user  sde
      a login of the same name exists with a different SID (0xa001 against the user's 0xa0ff). A name match is not a SID match: a person decides whether ALTER USER ... WITH LOGIN is right. In an sde-schema geodatabase this is the geodatabase administrator. Esri lets only a version's owner or the administrator delete a version, so version cleanup has no usable owner until this is fixed.

FAIL  orphan-user  edit_b
      no login has this SID or this name. Create the login with the user's SID (CREATE LOGIN ... SID = 0xa004), or confirm the user is stale.

FAIL  orphan-user  CORP\ann
      no login has this SID or this name. Create the login with the user's SID (CREATE LOGIN ... SID = 0xb002), or confirm the user is stale.

FAIL  version-owner  version DEFAULT (owner sde)
      the owner is an orphaned user and cannot connect. This is the default version. Fix the owner's login (see orphan-user) and leave the version alone.

FAIL  version-owner  version wip (owner edit_b)
      the owner is an orphaned user and cannot connect. Only the owner or the geodatabase administrator can delete it, and deleting a version that was not posted loses its edits. Do not drop the user first: reconcile and post or discard the edits, delete the version as the administrator, then drop the user.
...
FAIL  xdb-server  drilldown_proc -> [srv_old].[geodb].[dbo].[parcels]
      server 'srv_old' is not in sys.servers on this instance, so the name cannot resolve. The catalog records such a name without resolving it, so nothing warned at restore time. Use a three-part name, or create the linked server.
...
FAIL  evw-grant  dbo.roads_evw / edit_a
      UPDATE is granted to edit_a on dbo.roads and not on its versioned view dbo.roads_evw. Esri documents the copy to the view for grants made through ArcGIS; the export shows none here. Re-grant as the dataset owner through ArcGIS.

VERDICT: 15 FAIL, 0 WARN. The move is not verified. Fix the FAIL lines, export again and run again.
```

The block is cut at each `...`. The full run lists every finding. `CORP\ann` is a Windows user with
no login row, so it is an orphan whatever a directory lookup says about the account.

`drilldown_proc` points at `srv_old`, which exists in no row of `sys.servers`. `xdb-database` does
not report it a second time as a missing database. The `DEFAULT` version is never told to be
deleted.

Without `--target-major` the provider rule is listed as skipped and the rest runs:

```
$ python3 sqlmove.py after_move
...
  linked-provider  needs --target-major
```

## Refusals and silence

**A clean run says what it did not check.** `clean/` holds only two files:

```
$ python3 sqlmove.py clean
sqlmove: clean
files read: database_principals, server_principals
rules run:
  orphan-user          2 examined    0 FAIL    0 WARN
rules skipped (each checked nothing):
  version-owner    missing versions.csv
  ...
VERDICT: no FAIL in 2 row(s) examined by 1 rule(s), 0 WARN.
8 rule(s) were skipped and checked nothing. Clean means only the rules that ran.
$ echo $?
0
```

**A run that examined nothing exits 4, not 0.** An empty directory, a directory of header-only
files, or an export that names no file the tool knows:

```
$ python3 sqlmove.py empty_dir
...
VERDICT: NOTHING CHECKED. No rule examined a row, so this is not a clean move. Look for missing or empty files, or for a rule that needs --target-major.
$ echo $?
4
```

**An export that cannot be trusted is refused, exit 3, and nothing is written.** A SID that is not
hex, a missing column, an empty file and a UTF-16 file (which `sqlcmd` and PowerShell can
write) each name the file and the reason:

```
$ python3 sqlmove.py refused2
REFUSED   refused2/jobs.csv line 2, column owner_sid: '0xZZ99' is not a SID in hex (varbinary(85), at most 85 bytes)

VERDICT: REFUSED. Nothing was checked.
$ python3 sqlmove.py utf16
REFUSED   utf16/jobs.csv: the file holds NUL characters, which is what a UTF-16 file looks like. Save the export as UTF-8.

VERDICT: REFUSED. Nothing was checked.
```

The line number is the line the record starts on, so a quoted field that holds a line break does
not move it.

**A warning does not fail the gate.** `warn_only/` holds a reference through the local server's own
name and a `SQLOLEDB` linked server:

```
$ python3 sqlmove.py warn_only --target-major 16
...
VERDICT: no FAIL in 3 row(s) examined by 3 rule(s), 2 WARN.
6 rule(s) were skipped and checked nothing. Clean means only the rules that ran.
$ echo $?
0
```

## Writing the findings

```
$ python3 sqlmove.py after_move --target-major 16 --out findings.csv
...
Check only. findings.csv was not written. Re-run with --apply.
$ python3 sqlmove.py after_move --target-major 16 --out findings.csv --apply
...
wrote findings.csv
$ wc -l findings.csv
16 findings.csv
$ python3 sqlmove.py after_move --out after_move/jobs.csv
error: --out after_move/jobs.csv is also an input export. Name a new file.
$ python3 sqlmove.py after_move --ap
sqlmove.py: error: unrecognized arguments: --ap
```

The file has a header and one row per finding: `severity`, `rule`, `subject`, `detail`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | At least one row was examined and no rule failed. Warnings do not change it. |
| 1 | At least one rule failed. The move is not verified. |
| 2 | A file or directory could not be read, or `--out` could not be written. |
| 3 | An export was refused: a missing column, a SID that is not hex, an empty file or a UTF-16 file. |
| 4 | Nothing was examined. Every rule was skipped, or every file held no rows. |
| 64 | Usage error, including an unknown or abbreviated flag, a bad `--target-major`, and an `--out` that is an input. |
| 70 | An unexpected crash. This is a fault in the tool and not a finding. The traceback is on stderr. |

Exit 3 and exit 4 are deliberately not exit 0. "I checked and found nothing" and "I could not
check" are different facts, and a scheduled job must not read one as the other.

## Where each claim was exercised

| Claim | Exercised by |
|---|---|
| Every rule fires and every rule stays quiet on a clean case | 165 self-test assertions and the `after_move` run above |
| Exit codes 0, 1, 2, 3, 4, 64 and 70 | CLI assertions. The real runs above show 0, 1, 3, 4 and 64. |
| 100 percent statement and branch coverage | `coverage run --branch`, 835 statements, 206 branches, 0 missed |
| Mutation: the assertions fail when the code is wrong | 39 hand-picked edits to the decision core and the CLI, each made on a copy, and the self-test failed on all 39. The first sweep left one alive, the line number of a record that spans lines. It now has an assertion. |
| Identical on both hosts | The same 165 assertions, line for line, on Windows 3.13.2, 3.12.10 and 3.9.25 and Ubuntu 3.12.3 |
| No column the tool does not read reaches stdout or a file | A canary value in an unread column, searched for in the output and in `findings.csv` |
| No network, no subprocess, ASCII only, no f-string | The self-test parses its own source with `ast` and lists the modules it imports |
| Nothing is written without `--apply` | A dry run, then `--apply`, and a check that the export directory gains no file |
| Network paths | There are none. The tool imports no module that opens a socket, so there is no stub server to run it against. |
| Credentials | None are read or needed. No password column is read, and a canary in one is never printed. |

## Limits

- **It reads exports, not an instance.** It cannot see a login that exists on the instance and was
  left out of the export. A stale export gives a stale verdict.
- **The export queries were not run here.** No SQL Server was available to this repository's
  tests. The self-test and the demos run on hand-made CSV files that follow the documented column
  names. Run the queries on your own instance and compare a few rows by hand the first time.
- **Names compare ignoring case.** That matches the default case-insensitive collations. On a
  case-sensitive collation it can treat two names as one.
- **Local Windows accounts.** A login such as `HOST\user` carries the old machine name. A move to a
  new host reports it as a missing login, which is true, and no rule maps it to the new host.
- **`dependencies` is per database and by name.** `sys.sql_expression_dependencies` records a name
  that appears in a saved expression. Dynamic SQL is not tracked, and the page does not list
  `OPENQUERY` or a linked server named in a string. Those references cannot be seen in this
  export, so a stored procedure that reaches a linked server by `OPENQUERY` is not checked.
- **Roles are not expanded.** `evw-grant` compares principals by name. A table grant to a role and
  a view grant to a member of that role are two different grantees here. Permissions of fixed
  database roles do not appear in `sys.database_permissions` at all (Microsoft page above). A
  column-level permission is ignored.
- **Only `_evw` views.** Older versioned views ended in `_vw`. This tool pairs `_evw` only.
- **Traditional versioning only.** `SDE_versions` and the `_evw` view belong to traditional
  versioning. A branch-versioned dataset has neither.
- **It does not know which OLE DB drivers are installed.** A catalog export cannot say. A linked
  server on `MSOLEDBSQL19` is not flagged if that driver is missing on the host.
- **No settings rule.** See "Not covered" above.
- **A hole is not a value.** A version with no owner is not examined. A job with no `owner_sid` is
  an export problem and is refused.
- **Output files are written in place**, not through a temporary file. A failed write can leave a
  partial file, and the exit code is 2. A finding that starts with `=`, `+`, `-` or `@` is written
  as it came; quote it before opening the file in a spreadsheet.
- **`--self-test` ignores every other flag.** It writes only to a temporary directory, which it
  removes at the end, even when an assertion raises.
- **A field over the CSV module's size limit** exits 2. The limit is the module's own default.
- **Only UTF-8 CSV.** A byte that is not UTF-8 becomes U+FFFD, and two names can collapse into one.

## Contributing

Open an issue or pull request on GitHub.

## Author

Built by [Asir Khan](https://www.linkedin.com/in/asir-khan-310317264/).

## License

MIT.

## Related

Other single-file tools in this portfolio that pair with this one:

- [evwlint](https://github.com/uhsear/evwlint) - find the SQL that reads a versioned base table
  instead of its `_evw` view. It answers what reads the table; this tool answers whether the view
  received the grant at all.
- [bkpbase](https://github.com/uhsear/bkpbase) - say whether a restorable full backup exists, from
  exported `msdb.backupset` rows. Run it before the move; this tool runs after.
- [compressfloor](https://github.com/uhsear/compressfloor) - name what holds a geodatabase's
  compress floor. Run it before you clean up the versions that `version-owner` reports.
- [gdbprune](https://github.com/uhsear/gdbprune) - delete stale leaf versions, with the plan
  printed first. It is the tool for the cleanup that `version-owner` tells you to do first.
- [idreuse](https://github.com/uhsear/idreuse) - the same refusal to call a check clean when it
  compared nothing.
