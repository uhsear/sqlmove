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
...
PASS  an orphaned Windows user is told FROM WINDOWS and never a SID = option, which CREATE LOGIN allows for SQL logins only  <-- pinned defect
PASS  a same-name login with another SID names both SIDs and is not called a match  <-- pinned defect
...
PASS  an orphan's version says to delete it before the user is dropped  <-- pinned defect
...
PASS  the missing-server message names the cause and the fix  <-- pinned defect
...
PASS  a loopback name that no longer exists is reported once, as a missing server, not again as a missing database  <-- pinned defect
PASS  on SQL Server 2022 every Native Client generation fails, and the legacy SQLOLEDB warns  <-- pinned defect
...
PASS  a grant on a versioned table with none on its _evw view is reported  <-- pinned defect
...
PASS  a view not named <table>_evw, and a table named <table>_evw, are never paired with the table  <-- pinned defect
PASS  a table DELETE grant, and a view that holds only a column grant or a grant of another class, are reported  <-- pinned defect
...
PASS  and checking nothing exits 4, not 0  <-- pinned defect
...
PASS  files that exist and hold no rows run no rule: each is listed as skipped and nothing is checked  <-- pinned defect
PASS  a header-only database_principals.csv skips version-owner instead of failing every owner  <-- pinned defect
...
PASS  a login export with no rows skips every rule that tests a SID or name against it, and fails none  <-- pinned defect
...
PASS  a clean run with a skipped rule is exit 5, and exit 0 only with --allow-skipped  <-- pinned defect
...
PASS  a databases.csv without master skips xdb-database, and never fails a database that exists  <-- pinned defect
...
PASS  one with no row for the local server skips xdb-server and xdb-database, and never fails a server that exists  <-- pinned defect
...
PASS  an export made without ALTER ANY USER skips orphan-user and version-owner, never a clean exit 0  <-- pinned defect
...
PASS  a destination with no jobs still fails a missing job, and says to confirm that the export could see jobs  <-- pinned defect
...
PASS  a clean verdict with skipped rules says clean covers only the rules that ran  <-- pinned defect
...
PASS  a quote that is never closed is refused, not folded over the rows after it  <-- pinned defect
PASS  a quote that closes on a later line folds the rows between: a record that spans lines with the wrong cell count is refused  <-- pinned defect
...
PASS  the text NULL, in any case, is an empty permission scope  <-- pinned defect
...
PASS  a table grant exported with the text NULL as its column still reaches evw-grant, and no server is called NULL  <-- pinned defect
...
PASS  a wrong-column integer is quoted back up to 24 characters, like a SID or boolean  <-- pinned defect
...
PASS  an orphan user named like a formula is written to the findings file with one apostrophe, whatever it starts with, and a name with those characters inside is untouched  <-- pinned defect
...
PASS  after the dry runs and the --apply run the export directory holds the same files with the same bytes  <-- pinned defect
...
PASS  --out naming any file that exists is refused, on a dry run, and the file is untouched  <-- pinned defect
...
PASS  a prefix of --apply is refused, not read as --apply  <-- pinned defect
...
PASS  a bad export exits 3, names the file and column, and writes nothing  <-- pinned defect
PASS  a headerless file does not print its first data row; the columns are counted  <-- pinned defect
PASS  a header name the tool does not read is counted, not echoed  <-- pinned defect
...
PASS  a directory with no exports exits 4, not 0  <-- pinned defect
PASS  a clean run that skipped rules exits 5, not 0, and says so  <-- pinned defect
...
PASS  a clean run with --apply --out writes a findings file with a header and no row, and exits 5
...
PASS  a name the console cannot encode prints as ? and the run exits 1, not 70  <-- pinned defect
...
PASS  a source login list without the sa row skips login-missing, never a clean exit 0  <-- pinned defect
PASS  the same source list with its sa row still fails the missing login
PASS  a destination login list without the sa row skips every login-name rule  <-- pinned defect
PASS  headers-only catalog views and a user list from a login without ALTER ANY USER examine nothing: exit 4, no FAIL  <-- pinned defect
...
PASS  a value in that column that is not a boolean is refused with exit 3, never a crash  <-- pinned defect
PASS  a user list with no can_alter_any_user column skips the user rules, never a clean exit 0  <-- pinned defect
...
PASS  importing the module prints nothing and exposes the core
--------------------------------------------------------------------
261 assertions, 0 failed
```

The full run prints all 261 assertions. Each `...` line above is where this block is cut.

## What already exists

dbatools does the moving, and does it well. The quoted phrases below were checked against the
command pages on the date of the last README edit.
[`Copy-DbaLogin`](https://dbatools.io/Copy-DbaLogin) transfers logins "while preserving
authentication details and security context", and copies passwords "with original SIDs to
prevent orphaned users". [`Repair-DbaDbOrphanUser`](https://dbatools.io/Repair-DbaDbOrphanUser)
remaps orphaned users. Those two change the instance. Three dbatools commands only read:
[`Get-DbaDbOrphanUser`](https://dbatools.io/Get-DbaDbOrphanUser) ("Get orphaned users"),
[`Test-DbaAgentJobOwner`](https://dbatools.io/Test-DbaAgentJobOwner) ("Identifies SQL Agent jobs
with incorrect ownership") and
[`Test-DbaLinkedServerConnection`](https://dbatools.io/Test-DbaLinkedServerConnection) ("Tests
connectivity to all linked servers"). All of them connect to a live instance. If you can run
dbatools against both instances, its read-only commands already cover orphaned users and job
owners, and the connection test covers a linked server that does not answer.

This tool is the check you run after them, or after a manual restore. It does not move or repair
anything. It adds four things the commands above do not do:

- It decides from exported rows, so the answer is a file you can keep and run again.
- It knows the geodatabase cases: an orphaned `sde` user, versions owned by an orphan and the
  order to clean them up in, and a table grant that its `_evw` view lacks.
- It reads a skipped check as unchecked. A rule whose file is absent, or whose file holds no row it
  reads, is listed as skipped. So is a rule that tests a SID or name against a login export that
  holds no row, because that export is what a query without permission returns. `version-owner` is skipped the same way for an empty `database_principals.csv`. A run that examined no row exits 4, with or without
  `--allow-skipped`. A clean run that skipped a rule exits 5, and exits 0 only with that flag.
- It never decides from `SUSER_SID()`. The two catalog views are the only evidence.

A search of GitHub for the name `sqlmove` found two unrelated repositories (`sqlmovers`, with no
description, and a MySQL-to-SQL-Server copier) before this repository was published; a search
today also returns this repository. Searches for a post-move
SQL Server check and for a geodatabase restore check returned no repository. That shows only
that the searches found nothing.

## Requirements

Python 3.9 or newer and nothing else. No `arcpy`, no third-party package, no network, no database
driver. The input is CSV. Any SQL Server client that can write UTF-8 CSV with NULL as an empty cell or as the text `NULL` will do (see "The exports").

The self-test prints the same 261 assertions, line for line, on Windows (Python 3.13.2, 3.12.10
and 3.9.25) and on Ubuntu (Python 3.12.3). The outputs match byte for byte once Windows carriage
returns are removed. `coverage run --branch sqlmove.py --self-test` reports
100 percent of 1148 statements and 266 branches.

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
python sqlmove.py EXPORT_DIR --allow-skipped
```

| Flag | Default | What it does |
|---|---|---|
| `EXPORT_DIR` | none | A directory of exports. Required unless `--self-test`. |
| `--target-major` | off | Major version of the destination SQL Server, 16 for SQL Server 2022. The `linked-provider` rule needs it. Only 9 to 99 is accepted; any other value exits 64. |
| `--out` | off | Write every finding to this CSV. Needs `--apply`. |
| `--apply` | off | Actually write. Without it nothing is written. |
| `--allow-skipped` | off | Exit 0, not 5, when no rule failed but a rule was skipped. The skipped rules are still listed. Use it only when a partial run is expected. |
| `--require-all` | no effect | Exit 5 for a skipped rule is now the default. The flag stays so that a job written for the earlier release still runs. It wins over `--allow-skipped`. |
| `--self-test` | off | Run the assertions and exit. Other flags are ignored. |

Every flag must be spelled in full. The parser sets `allow_abbrev=False`, so `--ap` is refused
with exit 64 instead of being read as `--apply`, and `--tar` and `--o` are refused too.

`--out` must name a path that does not exist. A path that is also one of the input exports, and any
other path that already exists, is refused with exit 64, on a dry run too. The file is created
exclusively, so a file that appears between the check and the write is not overwritten either.

### The exports

A rule runs when all of its files are in the directory. A column the tool does not read is
ignored and never printed. Header names match ignoring case and surrounding spaces. A SID is hex with or
without `0x`. The queries below are what the author would run. They were written from the
documentation and were not run against a live SQL Server for this repository, so check them in
your version.

| File | Catalog view | Columns read |
|---|---|---|
| `server_principals.csv` | [`sys.server_principals`](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-principals-transact-sql) | `name`, `sid`, `type` |
| `database_principals.csv` | [`sys.database_principals`](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-database-principals-transact-sql) | `name`, `sid`, `authentication_type_desc`, and optionally `can_alter_any_user` |
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

-- database_principals.csv (run in the geodatabase). can_alter_any_user is optional: 1 when the
-- login sees every database user, 0 when it sees only its own row and the system principals.
SELECT name, CONVERT(varchar(172), sid, 1) AS sid, authentication_type_desc,
       HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'ALTER ANY USER') AS can_alter_any_user
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

**Partial exports.** Three catalog views list some rows to every caller and hide the rest, so the
tool looks for a row that every caller sees and skips the rules that depend on the file when that
row is absent. `databases.csv` must hold `master`: Microsoft says a caller sees any database that
is `master` or `tempdb`, or the one it is connected to, and needs `ALTER ANY DATABASE`,
`VIEW ANY DATABASE` or `CREATE DATABASE` to see the others
([sys.databases](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-databases-transact-sql)).
`linked_servers.csv` must hold the local server, `server_id` 0: the page says permissions are not
required to view it
([sys.servers](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-servers-transact-sql)).
A file without the row skips `xdb-database` or `xdb-server` and `xdb-database`, and the report says
why. The user list has no such row, so `HAS_PERMS_BY_NAME` supplies one. It returns 1 when the
caller holds the effective permission and 0 when it does not
([HAS_PERMS_BY_NAME](https://learn.microsoft.com/en-us/sql/t-sql/functions/has-perms-by-name-transact-sql)).
Microsoft says other users appear only to a caller with `ALTER ANY USER` or a permission on the
user. When the column is absent, or any row holds 0, the text `NULL` or nothing, `orphan-user` and
`version-owner` are skipped, because the tool cannot tell a short user list from a full one.

`sys.database_principals` documents a NULL SID for `SYS` and `INFORMATION_SCHEMA`. An empty SID is
accepted there and nowhere else, and a user that authenticates through the instance with no SID
is an orphan.

**NULL.** `sqlcmd` writes a SQL NULL as the text `NULL`. In the columns that can hold a NULL in
the catalog, the tool reads the text `NULL`, in any case, as an empty cell: the three scope columns
of `database_permissions`, the four `referenced_*` columns of `dependencies`, `provider`,
the `owner` of a version and the `sid` of `database_principals`. In every other column the text
stays, so a login named `NULL` is still a login. Without this, an object-level grant (whose
`column_name` is NULL) is read as a column grant and skipped, and every reference reads as a
server called `NULL`. Export without a `#TYPE` line (PowerShell `Export-Csv -NoTypeInformation`)
and without the dashed line `sqlcmd` prints under a header (`-h -1` with your own header row).

## What it checks

| Rule | Needs | FAIL when | Source |
|---|---|---|---|
| `orphan-user` | `server_principals`, `database_principals` | An `INSTANCE` user's SID is in no login. Skipped when `can_alter_any_user` is 0 or absent. A same-name login with another SID is named as such, never as a match. | [Microsoft: orphaned users](https://learn.microsoft.com/en-us/sql/sql-server/failover-clusters/troubleshoot-orphaned-users-sql-server) gives the same query. |
| `version-owner` | the two above, `versions` | A version's owner is an orphan or is not a user. The message gives the order: do not drop the user first. Skipped when `can_alter_any_user` is 0 or absent. | [Esri: delete a traditional version](https://doc.esri.com/en/arcgis-pro/latest/help/data/geodatabases/overview/delete-a-traditional-version.html) |
| `job-owner` | `server_principals`, `jobs` | The owner SID matches no login. | [Microsoft: metadata on another server](https://learn.microsoft.com/en-us/sql/relational-databases/databases/manage-metadata-when-making-a-database-available-on-another-server) |
| `job-copy` | `source_jobs`, `jobs`, both principals | A job is on the source and not the destination. WARN when its owner changed. | same page |
| `login-missing` | both principals | A source login is absent, or has another SID. Logins that start with `##`, `NT SERVICE\` or `NT AUTHORITY\` are skipped. | same page |
| `xdb-server` | `dependencies`, `linked_servers` | A four-part name names a server that is not in `sys.servers`, or a linked server with data access off. WARN for the local server's own name. Skipped when `linked_servers.csv` has no `server_id` 0 row. | [sys.sql_expression_dependencies](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-sql-expression-dependencies-transact-sql), [sys.servers](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-servers-transact-sql) |
| `xdb-database` | `dependencies`, `linked_servers`, `databases` | A cross-database name names a database that is not on the instance. Skipped when `databases.csv` has no `master` row or `linked_servers.csv` has no `server_id` 0 row. | same pages |
| `linked-provider` | `linked_servers`, `--target-major` | `SQLNCLI10` or `SQLNCLI11` on `--target-major` 16 or later. WARN for `SQLOLEDB`. | [SQL Server Native Client](https://learn.microsoft.com/en-us/sql/relational-databases/native-client/sql-server-native-client) |
| `evw-grant` | `objects`, `database_permissions` | A table grants SELECT, INSERT, UPDATE, DELETE or CONTROL to a principal, and its `<table>_evw` view does not, by object, schema or database grant. A DENY is named as a denial. | [Esri: privileges](https://doc.esri.com/en/arcgis-pro/latest/help/data/geodatabases/manage-sql-server/privileges-sqlserver.html), [Esri: what a versioned view is](https://desktop.arcgis.com/en/arcmap/latest/manage-data/using-sql-with-gdbs/what-is-a-versioned-view.htm) |

What the documentation says, and what it does not:

- **Orphans.** A database user is orphaned when its SID is not in `master`. The user can become
  orphaned after a restore onto an instance where the login was never created, and a login that
  is created again has a different SID. This is why the tool compares SIDs and says a name match
  is not enough.
- **[`SUSER_SID()`](https://learn.microsoft.com/en-us/sql/t-sql/functions/suser-sid-transact-sql).** Its page shows the function used to "obtain the SID from Windows", and it
  has an option that decides whether the Windows name is checked against the one SQL Server
  stores. The page does not say outright that it answers for a name with no login. The rehearsal
  described above is the evidence for that, and it was seen once. The tool avoids the function
  either way.
- **Silent at restore time.** For cross-database and cross-server entities the catalog page says
  "Entity names are reported; however, entity IDs aren't resolved." The export therefore holds the
  name, and this tool checks the name against `sys.servers` and `sys.databases`. That the restore
  raised no error and the call failed later is what the author saw. The pages above do not
  describe the error, so the tool does not quote one.
- **Native Client.** The Microsoft page defines Native Client as the ODBC and OLE DB drivers for
  SQL Server "prior to SQL Server 2022 (16.x)", and says SQL Server Native Client "isn't shipped
  with" SQL Server 2022 and later. That covers every generation, so `SQLNCLI10` and `SQLNCLI11`
  are both FAIL on version 16 or later. From SQL Server 2019 the provider name `SQLNCLI` maps to
  the Microsoft OLE DB Driver by default (`sys.servers` page), so the tool does not flag it. `SQLOLEDB` is
  WARN: the legacy provider is not recommended, and the pages do not say it is removed.
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
  them, and the logins a job uses must exist on the destination (Microsoft page above). The
  orphaned-users page says a database user "can become orphaned after a database is restored or
  attached to a different instance of SQL Server where the login was never created".
- **Creating the missing login.** The `CREATE LOGIN` page says the `SID` option "applies to SQL
  Server authentication logins only, not Windows authentication logins"
  ([CREATE LOGIN](https://learn.microsoft.com/en-us/sql/t-sql/statements/create-login-transact-sql)).
  The tool therefore gives the `SID =` advice for SQL logins and `CREATE LOGIN ... FROM WINDOWS`
  for a Windows user (a name with a backslash) and for a source login of type `U` or `G`.
- **Not covered.** There is no rule for database-level settings after a restore, so a clean verdict
  says nothing about database options. The source notes claimed that a restore wipes them. The
  Microsoft page above says that TRUSTWORTHY is OFF "when a database is attached", that attach and
  detach disable cross-database ownership chaining, and that the Service Broker options are OFF
  "when a database is attached from another server". It states none of this for a restore, so the
  tool ships no rule it cannot support.

## A real run

`after_move` is a synthetic export of an instance after a move, with one fault planted for each
rule. Every name, SID and server in it is made up. The run is on Ubuntu with Python 3.12.3. The
demo directories in this README (`after_move`, `clean`, `empty_dir`, `warn_only`, `header_only`,
`nulltext`, `refused2`, `utf16` and `inject`) are not in this repository, which holds four files, so you
cannot rerun these exact blocks. The self-test builds a similar export in a temporary directory.
The `after_move` run comes from a larger private synthetic export, so its counts are higher than
the self-test's own demo export. For example, `orphan-user` examined 5 rows and failed 3 there.

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
      no login has this SID or this name. Create the login with its SID (CREATE LOGIN ... SID = 0xa004), or confirm the user is stale.

FAIL  orphan-user  CORP\ann
      no login has this SID or this name. Create the login with CREATE LOGIN [CORP\ann] FROM WINDOWS (a Windows login takes its SID from the account, and the SID option is for SQL Server logins only), or confirm the user is stale.

FAIL  version-owner  version DEFAULT (owner sde)
      the owner is an orphaned user and cannot connect. This is the default version. Fix the owner's login (see orphan-user) and leave the version alone.

FAIL  version-owner  version wip (owner edit_b)
      the owner is an orphaned user and cannot connect. Only the owner or the geodatabase administrator can delete it, and deleting a version that was not posted loses its edits. Do not drop the user first: reconcile and post or discard the edits, delete the version as the administrator, then drop the user.
...
FAIL  xdb-server  report_proc -> [srv_old].[geodb].[dbo].[assets]
      server 'srv_old' is not in sys.servers on this instance, so the name cannot resolve. The catalog records such a name without resolving it, so nothing warned at restore time. Use a three-part name, or create the linked server.
...
FAIL  evw-grant  dbo.sites_evw / edit_a
      UPDATE is granted to edit_a on dbo.sites and not on its versioned view dbo.sites_evw. Esri documents the copy to the view for grants made through ArcGIS; the export shows none here. Re-grant as the dataset owner through ArcGIS.

VERDICT: 15 FAIL, 0 WARN. The move is not verified. Fix the FAIL lines, export again and run again.
```

The block is cut at each `...`. The full run lists every finding. `CORP\ann` is a Windows user with
no login row, so it is an orphan whatever a directory lookup says about the account. Its advice is
`FROM WINDOWS`, because `CREATE LOGIN` takes no `SID` for a Windows login.

`report_proc` points at `srv_old`, which exists in no row of `sys.servers`. `xdb-database` does
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

INCOMPLETE: 8 rule(s) checked nothing, so this is not a full verdict. Exit 5. Pass --allow-skipped to accept a partial run as exit 0.
$ echo $?
5
```

**A scheduled job reads a partial verdict as incomplete, not as clean.** The run returns 5, not 0,
when no rule failed and a rule was skipped. A failed rule is still 1, and a run that examined
nothing is still 4. An earlier release returned 0 here unless `--require-all` was set, so a job
that could check one rule in nine read "could not check" as "clean". `--allow-skipped` restores
exit 0 for a run that is meant to be partial. It prints the same report without the `INCOMPLETE`
line:

```
$ python3 sqlmove.py clean --allow-skipped
...
VERDICT: no FAIL in 2 row(s) examined by 1 rule(s), 0 WARN.
8 rule(s) were skipped and checked nothing. Clean means only the rules that ran.
$ echo $?
0
```

**A rule that examined no row is skipped, not passed.** `header_only/` holds clean principals, an
`objects.csv` with a header and no rows, and a `database_permissions.csv` with a header and no
rows. That is what a query run in the wrong database, or with too little permission, returns:

```
$ python3 sqlmove.py header_only
...
  evw-grant        examined no rows

VERDICT: no FAIL in 2 row(s) examined by 1 rule(s), 0 WARN.
8 rule(s) were skipped and checked nothing. Clean means only the rules that ran.
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

**The text NULL is an empty cell.** `nulltext/` holds a table grant whose `column_name` is the text
`NULL`, as `sqlcmd` writes it, and a table with a versioned view and no grant on it:

```
$ python3 sqlmove.py nulltext
...
FAIL  evw-grant  dbo.sites_evw / edit_a
      UPDATE is granted to edit_a on dbo.sites and not on its versioned view dbo.sites_evw. ...
VERDICT: 1 FAIL, 0 WARN. The move is not verified. Fix the FAIL lines, export again and run again.
```

**A warning does not fail the gate.** `warn_only/` holds a reference through the local server's own
name and a `SQLOLEDB` linked server:

```
$ python3 sqlmove.py warn_only --target-major 16 --allow-skipped
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
$ python3 sqlmove.py after_move --target-major 16 --out findings.csv --apply
error: --out findings.csv already exists. Name a new file; nothing is overwritten.
$ python3 sqlmove.py after_move --out after_move/jobs.csv
error: --out after_move/jobs.csv is also an input export. Name a new file.
$ python3 sqlmove.py after_move --ap
sqlmove.py: error: unrecognized arguments: --ap
```

The file has a header and one row per finding: `severity`, `rule`, `subject`, `detail`.

A `subject` or `detail` cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return is
written with one apostrophe in front. The file holds that one apostrophe; the tool was not run in
a spreadsheet (see Limits). The
names in the exports are the source of such a cell: a database user may be called `=cmd|...`.
OWASP's [CSV Injection](https://community.owasp.org/attacks/CSV_Injection) page lists those
characters and names "Prepend each cell field with a single quote" as one mitigation. Line breaks
are collapsed to spaces before the check, so a tab or carriage return cannot lead a cell in a real
run. The check still covers them, and the self-test pins both. The `severity` and `rule` columns
are constants of the tool and are not changed. The file has no numeric column. The tool never
reads its own findings file, so it has no strip on read. An export that holds a name starting with
an apostrophe is read as it is.

```
$ python3 sqlmove.py inject --out inject.csv --apply
...
wrote inject.csv
$ cut -d, -f1-3 inject.csv
severity,rule,subject
FAIL,orphan-user,'=cmd|' /c calc'!A1
FAIL,orphan-user,'+SUM(1;1)
FAIL,orphan-user,'-2+3
FAIL,orphan-user,'@SUM(1)
...
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | At least one row was examined, no rule failed and no rule was skipped. Warnings do not change it. With `--allow-skipped`, skipped rules do not change it either. |
| 1 | At least one rule failed. The move is not verified. |
| 2 | A file or directory could not be read, or `--out` could not be written. A failed `--apply` write after a failing rule also exits 2, not 1 (see Limits). |
| 3 | An export was refused: a missing column, a SID that is not hex, an empty file or a UTF-16 file. |
| 4 | Nothing was examined. Every rule was skipped, or every file held no rows. A rule whose files hold no rows is listed as skipped. |
| 5 | No rule failed, and at least one rule was skipped, including a rule skipped for a partial export. `--allow-skipped` turns this into 0. |
| 64 | Usage error, including an unknown or abbreviated flag, a bad `--target-major`, and an `--out` that is an input or already exists. |
| 70 | An unexpected crash. This is a fault in the tool and not a finding. The traceback is on stderr. |

Exit 0 never covers a run that skipped rules, unless you pass `--allow-skipped`. Exit 3, exit 4 and exit 5 are deliberately not exit 0. "I checked and found nothing" and "I could not
check" are different facts, and a scheduled job must not read one as the other.

## Where each claim was exercised

| Claim | Exercised by |
|---|---|
| Every rule fires and every rule stays quiet on a clean case | 261 self-test assertions and the `after_move` run above |
| Exit codes 0, 1, 2, 3, 4, 5, 64 and 70 | CLI assertions. The real runs above show 0, 1, 3, 4, 5 and 64. |
| 100 percent statement and branch coverage | `coverage run --branch`, 1148 statements, 266 branches, 0 missed |
| Mutation: the assertions fail when the code is wrong | The author made hand-picked edits to the decision core and the CLI on copies, and the self-test failed on every one that changed behaviour. The harness is not shipped, so a reader cannot rerun that sweep and the count is not claimed. The first sweep left one alive, the line number of a record that spans lines. It now has an assertion. |
| Identical on both hosts | The same 261 assertions, line for line, on Windows 3.13.2, 3.12.10 and 3.9.25 and Ubuntu 3.12.3 |
| No cell value from a column the tool does not read reaches stdout or a file; a refused file lists only the header names the tool knows and counts the rest | A canary value in an unread column, searched for in the output and in `findings.csv`. A headerless file with a canary in its first row, and a header name the tool does not read, are pinned too. |
| No network, no subprocess, ASCII only, no f-string | The self-test parses its own source with `ast` and lists the modules it imports |
| A name that starts like a formula is written with one apostrophe | `cell()` on each of `=`, `+`, `-`, `@`, tab and CR, the same for the subject and detail fields, and a CLI run with `--apply` on an export of seven synthetic user names, read back with the `csv` module. A mutation count is not claimed, because the harness is not shipped. The `inject` run above shows four of its seven rows, cut at the `...`. |
| A partial catalog export is skipped, not judged | Core and command-line assertions for an empty or master-less `databases.csv`, a `linked_servers.csv` without `server_id` 0, a user list exported without `ALTER ANY USER`, and a destination with no jobs. The column's text `NULL`, a short row, a value that is not a boolean, and a file without the column are pinned too. The author disabled each guard on a copy and the self-test failed on every copy. |
| Nothing is written without `--apply` | A snapshot of the export directory (names and bytes) before two dry runs and an `--apply` run, compared after. A copy of the tool that writes a stray file into that directory on a dry run fails it. A stray file written elsewhere, for example the working directory, is not watched. |
| Network paths | There are none. The tool imports no module that opens a socket, so there is no stub server to run it against. |
| Credentials | None are read or needed. No password column is read, and a canary in a column the tool does not read is never printed. |

## Limits

- **It reads exports, not an instance.** It cannot see a login that exists on the instance and was
  left out of the export. A stale export gives a stale verdict.
- **The export queries were not run here.** No SQL Server was available to this repository's
  tests. The self-test and the demos run on hand-made CSV files that follow the documented column
  names. Run the queries on your own instance and compare a few rows by hand the first time.
- **`login-missing` reads the one-letter `type` column (S, U, G).** An export of `type_desc`
  skips the rule with the reason `examined no rows`.
- **A row with fewer cells than the header is accepted.** Missing cells read as empty, so a file
  cut off mid-row drops that row silently unless the cut leaves an odd-length hex SID.
- **File names are matched case-sensitively on Linux.** `Server_Principals.csv` is not found, and
  its rules are reported as skipped (exit 5), never as clean.
- **Names compare with Python `casefold`.** That is case-insensitive but not accent-insensitive, so
  it can differ from a SQL Server collation that ignores accents.
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
- **No settings rule.** A clean verdict says nothing about database options. See "Not covered" above.
- **A hole is not a value.** A version with no owner is not examined. A job with no `owner_sid` is
  an export problem and is refused.
- **Output files are written in place**, not through a temporary file. A failed write can leave a
  partial file, and the exit code is 2.
- **The formula guard covers the six characters above.** OWASP's page also lists a line feed and
  full-width variants of `=` and `+`. A line feed cannot lead a cell here, because line breaks are
  collapsed first. A full-width lead is written as it came. No spreadsheet was run, so what one shows for
  the apostrophe was not checked. A program that reads the findings file back must strip one leading apostrophe.
  It cannot tell an added apostrophe from one that was in the name: a user named `'=lit` and a
  user named `=lit` both come out as `'=lit`. The guard also skips a lead of U+FEFF or U+200B.
  The tool does not claim how a spreadsheet reads them.
- **The formula guard was not run in a spreadsheet.** No Excel or LibreOffice was available, and the
  self-test checks only the bytes written. OWASP's page says its quote and escape mitigations "are
  not reliable in Microsoft Excel after saving and re-opening the CSV file", and it names a tab
  prefix as the option that Excel resists. Quote-style mitigations can fail in Excel after a save
  and reopen. The apostrophe is what this repository's spec asks for.
- **A name with a semicolon before a formula**, such as `x;=cmd`, is written unquoted. A
  spreadsheet whose list separator is a semicolon may split it into a second cell that starts with
  `=`, and the guard does not cover that cell.
- **Tab and carriage-return leads are pinned by `cell()` and `findings_rows()` calls**, not by an
  end-to-end run, because the reader strips them first. The tab-then-equals case is covered end to
  end: it comes out as `'=tab`.
- **No mutation count is claimed.** The harness is not shipped, so a mutation sweep cannot be rerun
  from this repository.
- **`--self-test` ignores every other flag.** It writes only to a temporary directory, which it
  removes at the end, even when an assertion raises. A killed process, or Ctrl-C, can leave an
  empty `sqlmove-selftest-*` directory in the temp folder.
- **A failed `--self-test` exits 1**, the same code as "a rule failed". A scheduled job cannot tell
  a broken tool from a finding by the exit code alone.
- **A field over the CSV module's size limit** exits 2. The limit is the module's own default.
- **Only UTF-8 CSV.** A byte that is not UTF-8 becomes U+FFFD. Two different names can then compare
  equal, and the output shows a garbled name. The self-test pins the replacement at the reader. It
  does not run a Windows-1252 export through a full verdict.

- **Exit 0 with `--allow-skipped` does not mean every rule ran.** It means the rules that ran found
  no FAIL. A run with two files, `server_principals.csv` and `database_principals.csv`, reports 8 of 9 rules skipped and exits 5 without the flag. A run with one file skips all 9 rules, examines nothing and exits 4. On Linux,
  a file named `Versions.csv` skips `version-owner` the same way.
- **A `dependencies.csv` with a header and no rows is skipped**, not clean. A database with no
  cross-database references shows `xdb-server` and `xdb-database` as skipped.
- **A truncated final row reads as a row with empty fields.** Short rows are padded with empty
  strings and are not refused. Check the row count of each export against the instance.
- **`login-missing` compares SQL logins (`S`), Windows logins (`U`) and Windows groups (`G`).**
  Microsoft Entra logins (`E`, `X`) and certificate logins are not compared.
- **`FAIL` on `SQLNCLI10` or `SQLNCLI11` means the target version does not ship the provider.** It does not mean
  the link is broken. If you installed the Native Client yourself, treat the finding as stale. The
  export cannot show installed drivers.
- **`evw-grant` treats any DENY as final.** It does not model how a narrower GRANT interacts with a
  wider DENY. Microsoft's permissions pages did not settle this for the author. A schema-wide DENY
  with a GRANT on the view may be reported as a denial when the grant applies.
- **CONTROL on a table is expected as CONTROL on the view.** A grant of SELECT, INSERT, UPDATE and
  DELETE on the view does not satisfy it, and the finding names CONTROL.
- **A loopback linked server passes `xdb-server`.** The tool does not read a linked server's
  `data_source`. A server that is in `sys.servers` but points back at the old host is not caught.
  The tool catches a four-part name whose server is absent, and a name that uses the local server's
  own name (WARN). A linked server copied across with its old host still in `data_source` passes
  and the call reaches the old host. A `dbatools` linked-server copy is the usual way this arises.
- **`dependencies.csv` rows are not de-duplicated.** A procedure that refers to one remote entity
  several times can produce repeated findings and a larger `examined` count.
- **Do not run the tool on an export you do not trust.** Only whitespace is collapsed, so a control
  character in a name, such as an ANSI escape sequence, reaches the terminal as received. Pipe the
  output through `cat -v` if in doubt.
- **A value in the wrong column can reach the screen.** A cell that fails SID, integer or boolean
  parsing is quoted back, up to 24 characters, in the REFUSED message. An integer cell is read with
  Python's `int()`, so `server_id` also accepts underscores and non-ASCII digits, such as `1_0`.
  A real export never holds these. A refused file lists only the header names that
  the tool knows (the column names it reads, in any export) and counts the other columns, so
  neither a header name nor a headerless file's first row reaches the screen. Keep a secret
  column out of an export anyway.
- **Ctrl-C ends the process with the interpreter's own status**, not one of the exit codes above.
- **Read the whole export in memory.** Each file is read whole before it is parsed, so a very large
  export, or a special file linked as an export, can use all memory and exit 70 and is not refused.
  A very large export uses memory in proportion to its size. Output is not capped: 200,000 dependency rows
  print a report of about 60 MB (62.6 MB, which is 59.7 MiB, measured once with 50 procedures that each name one cross-server object, one local server row and a `databases.csv`).
- **Export as a login that sees every login, job, database, linked server and user.** Microsoft
  says any login sees its own entry, the system logins and the fixed server roles in
  `sys.server_principals`, and needs `ALTER ANY LOGIN` or a permission on the login to see the
  rest. The `sys.databases` page names the permissions that show every database. For `sys.servers`
  the page says that with the default login mapping every login sees every linked server, so a
  short list there needs an admin change, and SQL Server 2022 and later require
  `VIEW SERVER SECURITY STATE`. `sys.database_principals` needs `ALTER ANY USER` to show other
  users. The Agent roles page says a member of `SQLAgentUserRole` has permissions on only the jobs
  it owns and a member of `SQLAgentReaderRole` can list all jobs
  ([SQL Server Agent fixed database roles](https://learn.microsoft.com/en-us/ssms/agent/sql-server-agent-fixed-database-roles)).
  It does not say what a direct `SELECT` on `msdb.dbo.sysjobs` returns, so run the job queries as
  a `sysadmin`. The tool detects four partial exports: a login list without `sa`, a `databases.csv`
  without `master`, a `linked_servers.csv` without `server_id` 0, and a `database_principals.csv`
  whose `can_alter_any_user` column holds 0 or is absent. It skips the rules that depend on the file and exits 5.
  It does not detect a short list that still holds the row it looks for. A short `server_principals`
  that holds `sa` gives FAIL lines for objects that exist in `orphan-user`, `job-owner` and
  `login-missing`. A short `databases.csv` that holds `master` does the same in `xdb-database`, and
  a short `linked_servers.csv` that holds the local server does it in `xdb-server`. A
  hidden version owner does give a `version-owner` FAIL, and the message names the cause. A partial export of
  `dependencies`, `objects` or `database_permissions` gives no sign either. A row the exporting
  login cannot see is absent, and the tool cannot detect an absent row. A hidden cross-server
  reference or a hidden `_evw` grant gives no FAIL, and the run can exit 5, or 0 with
  `--allow-skipped`. Compare each export's row count with the instance.
- **Export with a CSV writer that quotes fields.** A comma inside an unquoted name (`sqlcmd -s,`)
  shifts the columns. Most files are then refused with exit 3, but a shifted
  `database_permissions` row can drop out of `evw-grant` silently.
- **A single-line row with an extra unquoted comma is not refused.** Only a record that spans
  lines has its cell count checked, so a name such as `Edit, v1` in `versions.csv` shifts the
  columns and can give a FAIL line for a wrong owner. Export with a CSV writer that quotes fields.
- **A clean run with `--apply --out` writes a findings file that holds only the header.** It exits 0,
  or 5 when a rule was skipped. The self-test runs both cases and compares the bytes.
- **A cell that starts with a double quote that is never closed is refused.** The reader runs in
  strict mode. A quote left open to the end of the file, or followed by other text, is refused
  with exit 3 and the line it starts on. A quote that a later line happens to close folds the
  lines between into one record, which is refused when the record spans lines and its cell count
  differs from the header. A folded record with exactly the header's cell count is not detected.
- **A GRANT row and a DENY row for one grantee, permission and object** (from different grantors)
  give a verdict that depends on row order. `evw-grant` keeps the last row it reads.
- **A dry run does not check that the parent directory of `--out` exists.** The same command with
  `--apply` then exits 2 after it prints the report, and a failing rule set is reported as exit 2,
  not 1.
- **With stdout closed the report is lost**, while the exit code still follows the verdict.
- **Symlinked and network-share export directories were not exercised.** Only the real-path check
  on `--out` is covered.
- **The demo fixtures and the mutation harness are not shipped.** The repository holds four files.
  The mutation results are the author's record and cannot be reproduced from this repository.
- **A cell that starts with an invisible character** such as a zero-width space or a byte-order
  mark is written as it came. The tool does not claim how a spreadsheet reads it.
- **The README "A real run" blocks use fixtures that are not shipped** (after_move, clean,
  empty_dir, warn_only, header_only, nulltext, refused2, utf16, inject), so a reader cannot rerun
  them. The author rebuilt the clean and inject cases by hand and the output matched.
- **The findings file ends each line with CRLF**, as the `csv` module writes it by default.
- **An export with a NULL server principal SID is refused with exit 3.** No documented NULL-SID
  case for fixed server roles was confirmed.
- **Contained Windows database users**, which report authentication `WINDOWS`, are not checked
  for a login.
- **A reader that closes the pipe early**, for example `| head`, makes the run exit 70. Checked on Windows
  and on Ubuntu with a 20,000-row export piped to `head -c 10`. If stderr goes into the same pipe,
  Python can exit 120 on Linux instead. With
  `--apply` the findings file is then not written, because the report is printed first. Redirect
  the report to a file instead.
- **Bracketed names in the advice text are not escaped.** A name that contains a closing bracket
  must be doubled by hand before the `CREATE LOGIN` line is run.
- **A `server_principals.csv` with a header and no rows skips `orphan-user`, `version-owner`,
  `job-owner` and `login-missing`.** A real instance always has the `sa` login, so an empty file
  means too little permission. `job-copy` does not need the list and still runs.
- **A login list with no `sa` row (SID `0x01`) is treated as a partial export.** Microsoft's
  [principals page](https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/principals-database-engine)
  says the `sa` login is created when an instance is installed and "can't be dropped" (it can be
  renamed or disabled, and its row stays). That its SID is `0x01` is a fact seen in practice, not
  one that page states. The `sys.server_principals` page says any login sees its own
  entry and "the system logins", and the tool takes that to include `sa`. A file without `sa` is
  then a short one. Then `orphan-user`, `version-owner`, `job-owner` and `login-missing`
  are skipped when `server_principals.csv` lacks the row, and `login-missing` is also skipped when
  `source_server_principals.csv` lacks it. The run exits 5, or 0 with `--allow-skipped`. A
  platform with no `sa` login, such as Azure SQL Database, is skipped the same way, so this tool
  does not check it. A short list that still holds `sa` is not detected (see the partial-catalog
  limit below).
- **The exit-70 traceback goes to stderr and can quote a cell value**, because the handler prints
  the exception text. Keep stderr from a failed run out of shared logs.
- **The REFUSED text is written to stdout**, so a log that captures stdout keeps the quoted cell.
- **Only the findings file is guarded against formulas.** The report on stdout is printed as it
  is, so do not pipe it into a spreadsheet.
- **A cell led by a character that the guard does not list is written as it came.** Examples are
  `|` and a full-width lead. The tool does not claim that a spreadsheet runs them.
- **A failed `--apply` run can leave a partial findings file.** The file is opened so that it is
  never overwritten, so the next run refuses the same `--out` with exit 64 until you delete the
  file or name a new one.
- **The tool cannot tell a short catalog from a full one when the row it looks for is there.**
  Without `ALTER ANY LOGIN` a login sees only its own entry, the system logins and the fixed
  server roles in `sys.server_principals`, and without the right Agent role it may see only the
  jobs it owns (see the bullet above). A short
  export that still holds `sa` can pass `login-missing`, while `orphan-user` and `job-owner`
  over-report. A destination `jobs.csv` with no row cannot be told from an instance with no job,
  because a restore onto a fresh instance has none. `job-copy` fails each missing job and adds
  a note to confirm that the export could see jobs. A short destination `jobs.csv` with some rows
  makes `job-copy` fail a job that exists on the destination, and a short `source_jobs.csv`
  makes it pass a job that is missing. Run the queries as a `sysadmin`.
- **The statement that `sqlcmd` prints a NULL as the text `NULL` comes from observation**, not
  from Microsoft's `sqlcmd` utility page.
- **The dashed header line and `-h -1` are behaviours seen in practice.** They are not cited to
  Microsoft.
- **A file with no header row is refused.** Its first row is read as the header, so a cell in it
  that is not a column name the tool knows is counted and not printed.
- **A directory named like an export**, for example `server_principals.csv/`, is skipped as if the
  file were absent. The run reports the rule as skipped (exit 4 or 5) and never says that the path
  is a directory.
- **A dry run with `--out` in a directory that does not exist** reports "Check only" and exits 0
  or 1. The missing directory shows only as exit 2 on the later `--apply` run.
- **Spaces around a value are stripped.** A SQL name with trailing spaces compares as the same name
  without them, so two names that differ only in edge spaces compare equal.
- **`findings.csv` is written as UTF-8 without a byte-order mark.** Excel can show non-ASCII names
  garbled. Import the file as UTF-8.
- **An ANSI export (Windows-1252 or OEM) with accented names** compares consistently across files,
  because every file gets the same replacement. The names in the output show the replacement
  character.
- **A `BUILTIN\` login on the source** (for example `BUILTIN\Administrators`) is not in the
  skipped prefixes, so `login-missing` reports it as FAIL when the destination does not hold it.
- **Legacy machine-local Windows groups on the source** (for example
  `HOST\SQLServerMSSQLUser$HOST$INSTANCE`, from SQL Server 2005 era installs) are not in the
  skipped prefixes, so `login-missing` reports them as FAIL although the instance owns them.
- **The `server_principals` query has no type filter.** If a principal has a NULL `sid`, `sqlcmd`
  writes the text `NULL`, and the strict SID parser refuses the whole export with exit 3. The
  author could not confirm from the `sys.server_principals` page whether any fixed server role has
  a NULL `sid`. Run the query on your instance before you rely on it.
- **The Python `csv` module, `os.path.lexists` and Windows file-sharing behaviour** that the code
  relies on are not cited to their documentation here.
- **A line that holds only whitespace is read as a row**, not skipped. Where the file has a
  required SID, integer or boolean column, the run is refused with exit 3. In
  `database_principals.csv` the `sid` column is optional, so the line is read as a user with an
  empty name and no refusal or warning is given. Delete such lines from the export.

- **Exits 1, 3 and 64 are shown by their output in the "A real run" blocks**, not by an echoed
  `$?`. Exit 3 is also pinned in the self-test.
- **Narrative details are not checkable from the repository.** The `SUSER_SID()` rehearsal, the
  repair command's `Status` column and the larger private export behind `after_move` come from the
  author's work and are described with changed details.
- **Export as UTF-8.** A name with bytes that are not valid UTF-8 is compared after replacement
  characters are substituted, so two different names can compare as equal.
- **`--self-test` exits 1 on a failed assertion**, the same code as a rule failure.

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
