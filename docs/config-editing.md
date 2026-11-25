# Checking and editing `config.yaml`

`/etc/mooring/config.yaml` is read when the service starts. Two commands work on it:

- `mooring config check` runs the checks `mooring serve` runs at start, without starting anything.
- `mooring config edit` opens the file in an editor and installs the result only when it is valid.

A file that fails the checks is **refused**: the service does not start with it and does not
reload it. The error names the file, the line and the column, and shows the line.

See also: [the `config.yaml` reference](./host-file.md#the-configyaml-reference) · [Command-line reference](./cli.md#mooring-config-check) · [Install Mooring](./installation.md) · [The `mooring.yaml` file](./definition-file.md)

---

## Check the file

```bash
sudo mooring config check
```

| Flag | Default | Meaning |
|---|---|---|
| `--config PATH` | `/etc/mooring/config.yaml` | The file to check. |
| `--quiet` | off | Print nothing. The exit status is the answer. Cannot be combined with `--errors-only` or `--json`. |
| `--errors-only` | off | Print nothing for a valid file. For any other file the output is the same as without the flag. |
| `--json` | off | Print the result as one line of JSON on stdout. |

| Exit status | Meaning |
|---|---|
| `0` | The file is valid. |
| `78` | The file is refused: an empty file, a YAML mistake, an unknown key, a value of the wrong type, a value the validation refuses, or a wrong owner, group or mode of the file. |
| `2` | The file is missing or cannot be read, the file cannot be judged as this user, or the command was called with wrong arguments (`--quiet` with `--errors-only` or `--json` included). |

The command changes nothing. No value from the file is printed ([masked values](#masked-values)). The file's owner and mode are
checked as at start (see [the files in `/etc/mooring`](#files-in-etcmooring)).

Run as a user who is not root and whose primary group is not the file's group, the command does
not judge a group-readable file and exits with status `2`:

```text
mooring config: can't judge /etc/mooring/config.yaml as this user (the file belongs to another group): run sudo mooring config check
```

Run as the `mooring` user, the same file is refused (status `78`).

Run as root on a host with a `mooring` group, the command also refuses (status `78`) a file that
loads for root and that the service cannot use. On a host with a `mooring` user, the command reads
the file once more as that user (the unit's user, group and supplementary groups) in a child
process, and the result of that read decides: a file the `mooring` user can read through an ACL is
not refused, and a file in a directory the `mooring` user cannot enter is. Without a `mooring`
user, or when the child process gives no answer within 5 seconds, the file's owner, group and mode
decide: a root-owned file without group read, or of another group than `mooring`, is refused.

A file refused for its own owner, group or mode prints one of:

```text
/etc/mooring/config.yaml is readable by root only (mode 0600): the service (user mooring) can't read it
/etc/mooring/config.yaml belongs to group id 0, not to the service's group mooring (id 998): the service (user mooring) can't read it, or refuses it for its group
```

followed by:

```text
What is in the file is valid. To fix its owner and mode:
  sudo chown root:mooring /etc/mooring/config.yaml && sudo chmod 0640 /etc/mooring/config.yaml

/etc/mooring/config.yaml is refused: mooring will not start or reload with it.
```

A file refused for another reason prints the reason the `mooring` user got. For a directory that
user cannot enter:

```text
/etc/mooring/config.yaml can't be used by the service (user mooring): stat /etc/mooring/config.yaml: permission denied
What is in the file is valid. The service must be able to enter /etc/mooring:
  sudo chown root:mooring /etc/mooring && sudo chmod 0750 /etc/mooring

/etc/mooring/config.yaml is refused: mooring will not start or reload with it.
```

The second line names the first directory above the file that is closed to the `mooring` user by
its owner, group and mode. The `chown` and `chmod` command is printed for the file's own directory
only. When no directory is closed by its mode, the second line is `To see the file as the service
does:` with `sudo runuser -u mooring -g mooring -- mooring config check --config <path>`.

With `--json` this is one problem without a position. Its `hint` is `run: ` and the command for a
file refused for its owner, group or mode, and otherwise the second line and its command on one line
(`the service must be able to enter /etc/mooring: sudo chown root:mooring /etc/mooring && sudo chmod 0750 /etc/mooring`).

### A valid file

```console
$ sudo mooring config check
OK: /etc/mooring/config.yaml is valid
warning: security_logs: no archive.s3 configured — security logs are kept only on this host (14 days)
Certificates are requested for (plus one per app route with its own hostname):
  admin.example.com  the dashboard (admin.subdomain)
Changed since /etc/mooring/config.yaml.last-good:
  reload  (sudo systemctl reload mooring): ip_allowlist, retention
  restart (sudo systemctl restart mooring): admin, edge.acme_email, edge.base_domain
  a restart applies both
```

| Part | Shown when |
|---|---|
| `OK: <file> is valid` | Always. With `--errors-only` a valid file prints nothing. |
| `warning: …` | The file is valid and a setting deserves attention. The service logs the same warnings at start. |
| `warning: the dashboard hostname is <a>.<a>.<domain> …` | `admin.subdomain` is the same as the first label of `edge.base_domain`. |
| `Certificates are requested for …` | `edge.mode` is `managed` and the file names the dashboard hostname or a base domain with `dns01` (listed as `*.<domain>`). App routes with their own hostname are not listed. |
| `Changed since <file>.last-good:` | A `config.yaml.last-good` exists beside the file and the command can read it (it is readable by root only). Lists the settings that differ, by how they are applied. `no setting changed; nothing to apply` when none differ. |
| `note: <file>.last-good does not load …` | The `.last-good` file is itself refused, so the difference is not known. |
| `note: an edit that was not installed is kept at <file>.rejected-edit (root only): compare it with the file, then remove it` | A `config.yaml.rejected-edit` exists beside the file (see [what `config edit` refuses](#what-it-refuses)). |

With `--json`, a valid file prints:

```json
{"ok":true,"file":"/etc/mooring/config.yaml","warnings":["…"],"cert_hostnames":[{"host":"admin.example.com","why":"the dashboard (admin.subdomain)"}],"changed":{"since":"/etc/mooring/config.yaml.last-good","reload":["ip_allowlist","retention"],"restart":["admin","edge.acme_email","edge.base_domain"]}}
```

`repeated_label` (the doubled dashboard hostname), `changed` and `rejected_edit` (the path of a
kept `config.yaml.rejected-edit`) are present only when they apply.

### A refused file

The problems are printed on stderr, then one closing line. The exit status is `78`.

```console
$ sudo mooring config check
/etc/mooring/config.yaml:5:5: ip_allowlist[1]: must be an IP address or a CIDR (203.0.113.7, 203.0.113.0/24)
  4 |   - …
  5 |   - …
    |     ^

/etc/mooring/config.yaml:10:9: edge.mode: must be "managed" or "external"
   9 | edge:
  10 |   mode: …
     |         ^

/etc/mooring/config.yaml is refused: mooring will not start or reload with it.
```

`--errors-only` prints the same.

With `--json`, a refused file prints the problems on stdout:

```json
{"file":"/etc/mooring/config.yaml","problems":[{"line":5,"col":5,"kind":"semantic","path":"ip_allowlist[1]","msg":"ip_allowlist[1]: must be an IP address or a CIDR (203.0.113.7, 203.0.113.0/24)","excerpt":"  - …"},{"line":10,"col":9,"kind":"semantic","path":"edge.mode","msg":"edge.mode: must be \"managed\" or \"external\"","excerpt":"  mode: …"}]}
```

| Field | Meaning |
|---|---|
| `file` | The file checked. |
| `problems[].line`, `col` | Position, counted from 1. Absent when the problem has no position (an empty file, a wrong owner, group or mode). |
| `problems[].kind` | `syntax`, `unknown_key`, `duplicate`, `type` or `semantic` (a value the validation refuses). |
| `problems[].path` | The key the problem is about (`edge.base_domains[0].domain`). Absent for a syntax problem. |
| `problems[].msg` | The message. |
| `problems[].hint` | What to change. Absent when there is none. |
| `problems[].excerpt` | The line as shown, with values masked ([masked values](#masked-values)). Absent when the problem has no position. |
| `more` | The number of problems beyond the first 20. Absent when there are none. |

The exit status tells a valid file's JSON from a refused file's. A file that is missing, cannot be
read or cannot be judged as this user prints this object on stdout, with exit status `2`:

```json
{"ok":false,"file":"/etc/mooring/config.yaml","error":"config: stat /etc/mooring/config.yaml: stat /etc/mooring/config.yaml: no such file or directory"}
```

---

## Edit the file

```bash
sudo mooring config edit
```

| Flag | Default | Meaning |
|---|---|---|
| `--config PATH` | `/etc/mooring/config.yaml` | The file to edit. |

| Exit status | Meaning |
|---|---|
| `0` | The new file was installed, or nothing was changed. |
| `1` | Nothing was installed: the edit was discarded, the editor failed, the file is locked or changed underneath, the offer to start from the example was declined, or the run was interrupted. |
| `2` | Not run as root, not on a terminal, or wrong arguments. |

`config edit` never reloads or restarts the service. It prints the command that applies the change.

What it does:

1. Takes the lock `/etc/mooring/.config.lock`. A second `config edit` on the same file stops with
   `already being edited`.
2. Removes editing copies, and editor files for them, that an earlier, killed run left in the
   directory. A kept
   `config.yaml.rejected-edit` is not removed.
3. Reads the file and writes a private copy (mode `0600`, owned by root) into the same directory.
4. Runs the editor on the copy. The editor is the first of these that is installed: `$SUDO_EDITOR`,
   `$VISUAL`, `$EDITOR`, `sensible-editor`, `nano`, `vi`. A variable may hold arguments
   (`EDITOR="vim -u NONE"`); it is split on spaces and run without a shell. The editor runs in
   its own process group, which is the terminal's foreground group while `config edit` is in the
   foreground.
5. When the copy equals the file, prints `<file> unchanged` and stops.
6. Checks the copy with the checks `mooring serve` runs at start. When it is refused, prints the
   problems and asks `(e)dit again / (x) discard:`. `e` reopens the editor on the same copy; `x`
   removes the copy and leaves the file as it was. There is no way to install a refused file.
7. Checks that the file is still the one read in step 3: the same content, owner, group and mode.
8. Writes the previous content to `/etc/mooring/config.yaml.last-good` (mode `0600`, owned by
   root), replacing an older one.
9. Installs the new file with a rename, with the owner, group and mode the file had.
10. Prints what changed and how to apply it.
11. When `mooring serve` will not start with the installed file for its owner, group or mode, or
    because the `mooring` user cannot reach it, prints a warning with the command that fixes that
    (judged as `config check` does when run as root). The owner, group and mode are not changed.
12. Removes the copy and the backup, swap and lock files the editor left for it (`<copy>~`,
    `#<copy>#`, `.#<copy>`, and `<copy>` or `.<copy>` with `.swp`, `.swo` or `.swn`).

```console
$ sudo mooring config edit
/etc/mooring/config.yaml installed; the previous file is kept as /etc/mooring/config.yaml.last-good
To apply (nothing was reloaded or restarted):
  reload  (sudo systemctl reload mooring): ip_allowlist
  restart (sudo systemctl restart mooring): edge.acme_email
  a restart applies both
```

When the previous file was itself refused, the difference is not known and the output names the
restart command only.

The warning of step 11, for a file with mode `0644`:

```console
warning: mooring serve will not start with /etc/mooring/config.yaml as it is now, whatever is in it: config: /etc/mooring/config.yaml must not be world-accessible; got 0644
  Its owner and mode were kept as they were. To fix them:
  sudo chown root:mooring /etc/mooring/config.yaml && sudo chmod 0640 /etc/mooring/config.yaml
```

### When the file does not exist

`config edit` looks for the example at `/usr/share/mooring/config.example.yaml`, then at
`/etc/mooring/config.example.yaml`, and asks `Start from <the first that exists>? (y)es / (n)o:`.
With `y` the editor opens on a copy of the example. With `n` nothing is created and the exit status
is `1`. The new file is created as `root:mooring`, mode `0640`. On a
host without a `mooring` group it is created readable by root only (mode `0600`) and the command
prints the `chgrp` and `chmod` to run after the group exists. After creating the file it prints
`sudo systemctl enable --now mooring`.

The `.deb` and `.rpm` packages install the example at the first path. The
[raw binary install](./installation.md#other-linux-install-the-raw-binary) puts it at the second.
With neither, `config edit` stops with
`there is no example at /usr/share/mooring/config.example.yaml or /etc/mooring/config.example.yaml to start from`.

### What it refuses

| Situation | Message contains | Fix |
|---|---|---|
| Not root, or stdin or stdout is not a terminal | `config edit needs root and a terminal` | Run `sudo mooring config edit` in a terminal. To check only: `sudo mooring config check`. |
| The file is a symlink | `is a symlink; refusing to edit through it` | Pass the real file with `--config`. |
| The file is not a regular file, or has more than one hard link | `is not a regular file` / `has N hard links` | Replace it with a regular file with one name. |
| The directory is not owned by root, or is writable by group or others | `must be owned by root and writable by root only` | `sudo chown root /etc/mooring && sudo chmod 0750 /etc/mooring` |
| Another `config edit` is running | `is already being edited` | Finish or close the other one. |
| The file's content, owner, group or mode changed while it was being edited | `changed while it was being edited (its content, owner or mode); nothing was installed` | The edit is kept as `/etc/mooring/config.yaml.rejected-edit` (`root`, `0600`), replacing an older kept edit. Later runs of `config edit` do not remove it, and `config check` prints a note while it exists. Compare it with the file, run `config edit` again, then remove it. |
| No editor found | `no editor found: set EDITOR, or install nano or vi` | Install an editor or set `EDITOR`. |
| The editor exits with an error | `the editor failed` | Nothing was changed. Run the command again. |
| The file or the edited copy is larger than 4 MiB | `larger than 4194304 bytes` | — |

`SIGINT`, `SIGTERM`, `SIGHUP` and `SIGQUIT` sent to `mooring config edit` stop the editor's
process group with `SIGTERM` (what is left of the group is killed after 3 seconds, including an
editor started by a wrapper such as `sensible-editor`), restore the terminal's settings, remove
the copy and the editor's files for it, and release the lock. The command prints
`mooring config: interrupted; <file> was not changed` and exits with status `1`. When an edit was
kept as `config.yaml.rejected-edit` before the signal arrived, a second line names it
(`mooring config: <file> changed while it was being edited … Your edit is kept at <file>.rejected-edit …`).
A signal that arrives after the new file is installed ends the command with status `0`.

While the editor runs, `Ctrl-C` and `Ctrl-Z` typed on the terminal go to the editor. An editor
that suspends itself on `Ctrl-Z` suspends `mooring config edit` with it; `fg` continues both.
After `bg` the shell keeps the terminal: the editor stops again when it needs the terminal, until
`fg`. A `config edit` started in the background gets the terminal for its editor on `fg`. Where
nothing can continue the command (no shell with job control above it, for example
`ssh -t host 'sudo mooring config edit'`), `Ctrl-Z` does not suspend it: the editor runs on.

### Editing without `config edit`

Any editor works: `sudo nano /etc/mooring/config.yaml`. Run `sudo mooring config check` before
applying the change. An editor run directly does not write `config.yaml.last-good`.

---

## Reading the errors

`config.yaml` and `mooring.yaml` errors have the same two forms.

**One line**, in logs, the deploy error and HTTP error bodies:

```text
<file>:<line>:<col>: <message> (hint: <hint>); N more problems
```

```text
/etc/mooring/config.yaml:3:1: unknown key on this line (hint: did you mean ip_allowlist?)
/etc/mooring/config.yaml:5:5: ip_allowlist[1]: must be an IP address or a CIDR (203.0.113.7, 203.0.113.0/24); 1 more problem
/etc/mooring/config.yaml: the file is empty (hint: it has no settings, only blank lines or comments)
```

`(hint: …)` is present when there is a hint. `; N more problems` is present when the file has more
than one problem; the line shows the first.

**Several lines**, on a terminal (`config check`, `config edit`, `doctor`, `validate`), in the
deploy output and in the setup upload's error. Each problem has the position and message, the line
before, the line itself, a caret under the column, and the hint:

```console
/etc/mooring/config.yaml:3:1: unknown key on this line
  2 | encryption_key: …
  3 | …
    | ^
   hint: did you mean ip_allowlist?
```

Line and column count from 1; a problem that has no column is shown with its line only (`config.yaml:3:`). At most 20 problems are shown; `… and N more` follows when there are
more. A line is cut at 200 bytes. A file larger than 1 MiB gets the parser's message without a
line excerpt.

### Masked values

In `config.yaml` messages and excerpts no value from the file is shown. Every value is replaced
by `…`, on the line of the problem and on the line before it, for every kind of problem and every
key. A comment after the value is left out of the excerpt.

The messages of the validation do not quote the value or a username. An entry of a list is named
by its index, counted from 0 (`ip_allowlist[1]`, `users[0].password_hash`).

A key name is shown only when it is a key of `config.yaml`, spelled as in the
[reference](./host-file.md). Any other text written where a key belongs is not shown in the
message, the excerpt or the JSON `path`: the message is `unknown key on this line`, the excerpt
shows the indentation, the `- ` markers and `…`, and the `path` has `…` in place of the key
(`retention.…`). A misspelled key (`ip_allowlst`, `Bind_Addr`) is not shown either; the hint names
the key of `config.yaml` it is close to (`did you mean ip_allowlist?`). A line on which the parser
read no key, such as a line of a `|` or `>` block, is shown as its indentation and `…`.

A problem in a block that is reached through an alias (`*name`) is placed on the line of the alias,
and a key brought in by a merge (`<<: *name`) on the line of the merge: the message is
`unknown key "<key>" merged into <block>`, or `unknown key merged into <block>` when the key is not
a key of `config.yaml`. An unknown key in an aliased block that is not a key of `config.yaml` reads
`unknown key in <block>, in the block this line refers to`. The name of an anchor or an alias is
never shown. A `<<` line keeps its `<<` in the excerpt. A merge that does not refer to a mapping
reads `a merge (<<) takes a mapping or a list of mappings`.

Only the first YAML document of the file is read. When a later `---` line is followed by settings,
the hint is `only the first document of the file is read; it ends at the "---" on line N`.

The messages for a `config.yaml` value of the wrong type do not quote the value found.
`mooring.yaml` messages do (`(found "3")`).

`mooring.yaml` excerpts are shown as written. The file holds secret names, not values.

### How many problems are listed

| File | Listed |
|---|---|
| `config.yaml` with a YAML syntax problem | The first syntax problem. The rest of the file cannot be read until it is fixed. |
| `config.yaml` that is valid YAML | Every unknown key, duplicate key and wrong type. When there are none of those, every value the validation refuses. |
| `mooring.yaml` with a YAML syntax problem | The first syntax problem. |
| `mooring.yaml` with an anchor, an alias, a merge key or a duplicate key | That problem alone. |
| `mooring.yaml` that is valid YAML | Every unknown key and wrong type. When there are none of those, the **first** value the validation refuses. |

### Mistakes and their messages

YAML syntax:

| Mistake | Message | Hint |
|---|---|---|
| A line indented to a column no block uses | `this line is indented by 1 space, which matches no block above it; it does not match line 10 above (indented by 2 spaces)` | `indent it by 0 or 2 spaces` |
| A tab used to indent | `a tab is used for indentation` | `indent with spaces; YAML does not accept tabs for indentation` |
| `key:value`, also after `- ` and before `\|` or `>` | `there is no space after the ':'` | `put a space between "data_dir:" and its value` |
| A line nested under a key that has a value | `this line is indented under line N, which already has a value` | `start it in column C like line N, or remove the value on line N to nest this line under it` |
| A line nested under a key whose value is text on a later line | `this line is indented under line N, which already has a value (the text that starts on line M)` | `start it in column C like line N, or remove that text to nest this line under line N` |
| A line without a `:` among `key: value` lines | `this line is not in "key: value" form` | `the lines around it are "key: value" entries; add the missing ':' or fix this line's indentation` |
| A `- ` item among `key: value` lines | `a list item ("- ") cannot start here: the block at this indentation is made of "key: value" lines` | `indent the "- " lines under the key they belong to, and give that key no value of its own` |
| A quote that is not closed | `this quote (") is never closed` | `add the closing quote at the end of the value` |
| A `[` or `{` that is not closed | `this [ is never closed` | `add the closing ]` |
| An unquoted value containing `: ` | `the value contains ':' followed by a space, which YAML reads as the start of another key` | `put the whole value in quotes` |
| An unquoted value starting with a reserved character such as `@` | `a value cannot start with @ unless it is in quotes` | `put the value in quotes` |
| A control character in the file | `the file contains a control character` | `remove it; the file must be plain UTF-8 text` |
| An empty file, or one with only blank lines and comments | `the file is empty` (without a line and column) | `it has no settings, only blank lines or comments` |

The second part of the indentation message (`it does not match line N above …`) names the first
line of the block the line is to the left of. It is absent when there is no such block.

A line without a `:` is reported on its own line, also when it is the first entry of its block.

With `key:value` in `config.yaml`, when the key is not a key of `config.yaml`
([masked values](#masked-values)) the hint is `put a space after the ':'`.

Keys and types:

| Mistake | Message | Hint |
|---|---|---|
| A misspelled key (`mooring.yaml`) | `unknown key "servce" in spec.edge.routes[0]` | `did you mean service?` |
| A misspelled key (`config.yaml`) | `unknown key on this line` | `did you mean ip_allowlist?` |
| A misspelled key whose key belongs in another block (`config.yaml`) | `unknown key on this line` | `did you mean idle_timeout? idle_timeout belongs under session:` |
| A key in the wrong block | `unknown key "acme_email"` | `acme_email belongs under edge:` |
| An unknown key in a block with up to 8 keys (`config.yaml`) | `unknown key on this line in retention` | `keys allowed here: interval, events_max_age, events_max_rows, archive_max_mb` |
| Another unknown key (`config.yaml`) | `unknown key on this line` | — |
| A key written twice (`config.yaml`) | `key "bind_addr" is written twice in this block (first on line 1)` | `keep one of the two` |
| A key written twice that is not a key of `config.yaml` | `a key is written twice in this block (first on line N)` | `keep one of the two` |
| A single value where a list belongs | `protected_projects must be a list (lines starting with "- "), found text` | `write the value as "- value" on its own line below the key, or as [value]` |
| A list where a block of keys belongs | `retention must be a mapping (indented "key: value" lines), found a list` | `remove the "- " and write the keys directly under it` |
| A value cut short by ` #` (`enabled: tru #e`) | the message for that value | `everything after " #" is a comment; put the value in quotes if the # is part of it` |

An unknown key inside a block has ` in <block>` after the message (`unknown key on this line in
retention`). In `mooring.yaml` the message names the key as written (`unknown key "servce" in
spec.edge.routes[0]`).

The hint for an unknown key is the first of these that applies:

1. `did you mean …?` for a name close to a key of the block.
2. `<key> belongs under <block>:` (or `<key> belongs at the top level of the file`) when exactly
   one other block has that key, or exactly one inside the block it is written in.
3. In `config.yaml` only: `did you mean <key>?` for a name close to a key of another block,
   followed by `<key> belongs under <block>:` when step 2 gives a place for that key.
4. `keys allowed here: …` for a block with up to 8 keys.

Otherwise there is no hint.

Values of the wrong type:

| Mistake | `config.yaml` | `mooring.yaml` | Hint |
|---|---|---|---|
| A quoted boolean | `trust_proxy must be true or false without quotes` | `spec.compose.services.web.ports[0].publish must be true or false without quotes (found "true")` | `remove the quotes` |
| Another value where a boolean belongs | `trust_proxy must be true or false` | `spec.compose.services.web.ports[1].public must be true or false (found 1)` | — |
| A quoted number | `retention.events_max_rows must be a number without quotes` | `spec.scaling[0].max must be a number without quotes (found "3")` | `remove the quotes` |
| Text where a number belongs | `retention.events_max_rows must be a number` | `spec.scaling[0].max must be a number (found "three")` | — |
| A number too large for the setting | `retention.archive_max_mb is out of range` | `spec.scaling[0].max is out of range (found 99999999999999999999)` | — |
| An invalid duration | `retention.interval is not a valid duration: use a number and a unit like 30s, 5m, 12h or 30d` | — | — |

A boolean is written `true` or `false` without quotes. `"true"` and `"false"` in quotes are
refused in both files.

### Examples

A key indented by one space:

```console
/etc/mooring/config.yaml:11:2: this line is indented by 1 space, which matches no block above it; it does not match line 10 above (indented by 2 spaces)
  10 |   mode: …
  11 |  acme_email: …
     |  ^
   hint: indent it by 0 or 2 spaces
```

A tab:

```console
/etc/mooring/config.yaml:10:1: a tab is used for indentation
   9 | edge:
  10 |  mode: …
     | ^
   hint: indent with spaces; YAML does not accept tabs for indentation
```

A quoted boolean and a key in the wrong block, in one file:

```console
/etc/mooring/config.yaml:14:14: trust_proxy must be true or false without quotes
  13 | data_dir: …
  14 | trust_proxy: …
     |              ^
   hint: remove the quotes

/etc/mooring/config.yaml:15:1: unknown key "acme_email"
  14 | trust_proxy: …
  15 | acme_email: …
     | ^
   hint: acme_email belongs under edge:
```

No space after the colon:

```console
/etc/mooring/config.yaml:13:10: there is no space after the ':'
  12 |   acme_ca: …
  13 | data_dir:…
     |          ^
   hint: put a space between "data_dir:" and its value
```

A key written twice:

```console
/etc/mooring/config.yaml:14:1: key "bind_addr" is written twice in this block (first on line 1)
  13 | data_dir: …
  14 | bind_addr: …
     | ^
   hint: keep one of the two
```

An invalid duration:

```console
/etc/mooring/config.yaml:15:13: retention.interval is not a valid duration: use a number and a unit like 30s, 5m, 12h or 30d
  14 | retention:
  15 |   interval: …
     |             ^
```

A line without a `:`:

```console
/etc/mooring/config.yaml:15:3: this line is not in "key: value" form
  14 | retention:
  15 |   …
     |   ^
   hint: the lines around it are "key: value" entries; add the missing ':' or fix this line's indentation
```

A misspelled key whose key belongs in another block (`idle_timout` at the top level):

```console
/etc/mooring/config.yaml:14:1: unknown key on this line
  13 | data_dir: …
  14 | …
     | ^
   hint: did you mean idle_timeout? idle_timeout belongs under session:
```

An unknown key in a block:

```console
/etc/mooring/config.yaml:15:3: unknown key on this line in retention
  14 | retention:
  15 |   …
     |   ^
   hint: keys allowed here: interval, events_max_age, events_max_rows, archive_max_mb
```

A key that is not close to a key of `config.yaml`:

```console
/etc/mooring/config.yaml:14:1: unknown key on this line
  13 | data_dir: …
  14 | …
     | ^
```

A value the validation refuses, with a comment on the line (`mode: managd  # the mode`):

```console
/etc/mooring/config.yaml:10:9: edge.mode: must be "managed" or "external"
   9 | edge:
  10 |   mode: …
     |         ^
```

The same kind of problem with the list written inline (`ip_allowlist: ["203.0.113.999"]`):

```console
/etc/mooring/config.yaml:3:16: ip_allowlist[0]: must be an IP address or a CIDR (203.0.113.7, 203.0.113.0/24)
  2 | encryption_key: …
  3 | ip_allowlist: …
    |               ^
```

An empty file:

```console
/etc/mooring/config.yaml: the file is empty
   hint: it has no settings, only blank lines or comments
```

Quoted values and wrong types in a `mooring.yaml`:

```console
$ mooring validate
mooring.yaml:13:22: spec.compose.services.web.ports[0].publish must be true or false without quotes (found "true")
  12 |           - internal: 8080
  13 |             publish: "true"
     |                      ^
   hint: remove the quotes

mooring.yaml:14:23: spec.compose.services.web.ports[1].internal must be a number (found "eighty")
  13 |             publish: "true"
  14 |           - internal: eighty
     |                       ^
```

A misspelled key in a `mooring.yaml`:

```console
$ mooring validate
mooring.yaml:17:9: unknown key "servce" in spec.edge.routes[0]
  16 |       - hostname: app.example.com
  17 |         servce: web
     |         ^
   hint: did you mean service?
```

---

## Apply a change: reload or restart

| Changed setting | Apply with |
|---|---|
| `ip_allowlist`, `trust_proxy`, `trusted_proxies`, `auth`, `users`, `retention` | `sudo systemctl reload mooring` |
| Every other setting | `sudo systemctl restart mooring` |

A restart applies everything. During a restart the dashboard is unavailable for a moment; apps
keep running. `config check` (run as root) and `config edit` print which of the two a change needs.

A reload:

- Runs `mooring config check --errors-only` first. When the file is refused, `systemctl reload
  mooring` fails, no signal is sent, and the service keeps the configuration it has.
- Reads `config.yaml` once and applies that one configuration to the dashboard (`ip_allowlist`,
  `trust_proxy`, `trusted_proxies`, `auth`, `users`), to the edge's `ip_allowlist` and to the
  retention policy.
- Applies `ip_allowlist` to the dashboard and, with a dashboard hostname (`admin.hostname` or
  `admin.subdomain`), to the edge route of that hostname. The dashboard's own check uses the new
  list in every case below.
- Signs every session out when `auth` or `users` changed.
- Does not apply a changed restart-only setting. It stays as it was until the next restart.
- Logs its outcome:

  | Level | Log message | Meaning |
  |---|---|---|
  | `INFO` | `config reloaded (allowlist + auth)` | The configuration was applied. The lines about the edge follow ([`ip_allowlist` at the edge](#ip_allowlist-at-the-edge)). |
  | `ERROR` | `config reload rejected; keeping previous` | The file did not load (`err` has the problem). Nothing was applied: the dashboard, the edge and the retention policy keep the previous settings. Fix the file (`sudo mooring config check`) and reload again. |
  | `ERROR` | `config reload: the dashboard refused the config; nothing was applied (the dashboard, the edge's ip_allowlist and the retention policy keep the previous settings)` | The file loaded and the dashboard refused it (`err` has the cause). Nothing was applied. |
- Sent while the service is starting (`SIGHUP` before start-up has finished), is handled once
  start-up finishes.

### `ip_allowlist` at the edge

After a reload the service logs one of these (`sudo journalctl -u mooring -n 20 --no-pager`):

| Level | Log message | Meaning |
|---|---|---|
| `INFO` | `config reload: the edge serves the reloaded ip_allowlist for the dashboard hostname` | The edge route of the dashboard hostname uses the new list. |
| `WARN` | `config reload: the edge serves the reloaded ip_allowlist for the dashboard hostname, but its reconcile reported an error` | The edge uses the new list. The refresh of the edge reported an error (`err`) for another reason. |
| `WARN` | `config reload: the edge has not applied the new ip_allowlist yet; it keeps the previous list for the dashboard hostname, and the new one stays pending until the next reconcile that Caddy accepts (logged then as "ip_allowlist applied at the edge")` | The edge config with the new list was not applied. The edge keeps the previous list, and the new list is applied at the next refresh of the edge that Caddy accepts. |
| `WARN` | `config reload: the edge refused the new ip_allowlist and keeps the previous list for the dashboard hostname; its own line ("edge: the new ip_allowlist was refused") says why` | The new list is given up. The edge keeps the previous list until a reload with a list it accepts, or a restart. The line has `hint="fix ip_allowlist in config.yaml, then: sudo systemctl reload mooring"`. |

Every line has `entries`, the number of entries of the new list, and `err` when the refresh of the
edge returned an error.

`ip_allowlist applied at the edge` is logged each time Caddy accepts a list that differs from the
one in force, at the reload or at a later refresh.

- When Caddy refuses the config with the new list, Mooring loads the same config with the previous
  list. When Caddy accepts that, the new list is tried once more and given up when it is refused
  again. When Caddy refuses both (it has just restarted), or the second try does not reach Caddy,
  the new list stays pending and is applied at the next refresh.
- A list that is given up is logged by the edge as
  `edge: the new ip_allowlist was refused; the dashboard route keeps the previous list`, with the
  cause in `err`. The refresh that gave it up applies its routes with the previous list: a deploy
  or a scaling change that runs at the same time is not failed by it.
- An entry that admits every address (`0.0.0.0/0`, `::/0`, and the IPv4-mapped forms of all of
  IPv4 such as `::ffff:0.0.0.0/96`) is refused by the edge while it serves the dashboard hostname.
  This happens when the `admin` block was removed from the file and the service was reloaded
  instead of restarted. The edge names the entry by its index, counted from 0:
  `ip_allowlist[1] admits every address: refused while the edge serves the dashboard hostname admin.example.com (restrict ip_allowlist, or restart Mooring if the admin block was removed)`.
  The list is given up (the last message of the table). Restart the service, or reload with a list
  without that entry.
- A Caddy that Mooring starts again (after a crash, or on an updated binary) starts with the list
  in force, not the list from when Mooring started.

`ip_allowlist` entries are given to the edge in canonical form: an address without a prefix length
is that one address (`203.0.113.10` is `203.0.113.10/32`), an IPv4-mapped IPv6 address is the IPv4
address (`::ffff:198.51.100.7` is `198.51.100.7/32`), a prefix is masked to its network, and spaces
around an entry are ignored.

---

## A refused file at start, reload and upgrade

| When | What happens | Then |
|---|---|---|
| Start (`systemctl start`, `restart`, boot) | `mooring serve` logs one `ERROR` line and exits with status `78`. systemd does not restart the unit; it stays `failed`. A file the service may not read, or of another group than the service's, is handled the same way. A missing file is not: `mooring serve` exits with status `1` and systemd starts it again every 2 seconds. | Fix the file, `sudo mooring config check`, `sudo systemctl start mooring`. |
| `systemctl reload mooring` | The check fails, the reload fails, and the running service is not touched. | Fix the file, `sudo mooring config check`, reload again. |
| Package upgrade | The new version checks the file before the restart. When it is refused, the service is not restarted. The installer prints the problems. | Fix the file, `sudo mooring config check`, `sudo systemctl restart mooring`. |

### Start

`mooring serve` logs one `ERROR` line and exits in these cases. systemd does not restart the unit
on status `78`. On status `1` it starts the service again every 2 seconds, so a file or a directory
on a volume that attaches late is picked up without a restart.

| Cause | Exit status | `msg` | `hint` |
|---|---|---|---|
| The file does not exist | `1` | `config.yaml not found; not starting` | `create it: sudo mooring config edit (or pass --config); the unit starts the service again every 2s, so a volume that attaches late is picked up without a restart` |
| The file cannot be reached for another reason than its permissions (an I/O error) | `1` | `config.yaml can't be read; not starting` | `the unit starts the service again every 2s, so a volume that attaches late is picked up without a restart` |
| The service may not read the file (permission denied) | `78` | `config.yaml can't be read; not starting` | `the service user must be able to read it: sudo chown root:mooring /etc/mooring/config.yaml && sudo chmod 0640 /etc/mooring/config.yaml` |
| The file is group-readable and its group is neither `root` nor the service's | `78` | `config.yaml belongs to another group than the service's; not starting` | `give it to the service's group: sudo chown root:mooring /etc/mooring/config.yaml && sudo chmod 0640 /etc/mooring/config.yaml` |
| The file is refused (its content, owner or mode) | `78` | `config.yaml is not valid; not starting` | `run: sudo mooring config check` |
| `data_dir`, `<data_dir>-apps` or, with `edge.mode: managed`, `/var/lib/caddy` is missing or not writable | `1` | `a required directory is missing or not writable; not starting` | `make it writable by the service user and list it in the unit's ReadWritePaths (a non-default data_dir must be added there); the unit starts the service again every 2s, so a volume that attaches late is picked up without a restart` |
| `encryption_key` does not open the database | `78` | `encryption_key does not match the database; not starting` | `put back the encryption_key this database was created with (or restore the database that belongs to this key), then: sudo systemctl restart mooring` |
| `setup.enabled: true` on a host without a working sandbox | `78` | `setup.enabled is set but this host has no working sandbox; not starting` | `install what the sandbox needs, or set setup.enabled: false in config.yaml, then: sudo systemctl restart mooring` |

Every line has a `detail` field with the cause. The lines about the file also have `file`. The
line for a refused file has `line` (the first problem's line, when it has one) and `problems` (the
number of problems):

```text
level=ERROR msg="config.yaml is not valid; not starting" file=/etc/mooring/config.yaml line=3 problems=1 detail="/etc/mooring/config.yaml:3:1: unknown key on this line (hint: did you mean ip_allowlist?)" hint="run: sudo mooring config check"
level=ERROR msg="config.yaml not found; not starting" file=/etc/mooring/config.yaml detail="config: stat /etc/mooring/config.yaml: stat /etc/mooring/config.yaml: no such file or directory" hint="create it: sudo mooring config edit (or pass --config); the unit starts the service again every 2s, so a volume that attaches late is picked up without a restart"
level=ERROR msg="config.yaml can't be read; not starting" file=/etc/mooring/config.yaml detail="config: read /etc/mooring/config.yaml: open /etc/mooring/config.yaml: permission denied" hint="the service user must be able to read it: sudo chown root:mooring /etc/mooring/config.yaml && sudo chmod 0640 /etc/mooring/config.yaml"
```

Read it with `sudo journalctl -u mooring -n 20 --no-pager`.

Other start failures (Docker or the database not reachable) also exit with status `1` and are
retried by systemd every 2 seconds.

### Package upgrade

The check runs as the `mooring` user and group (`runuser -u mooring -g mooring --`) when `runuser`
is installed, takes `-g` and the user exists, otherwise as root. In both cases a file the service
cannot read, or of another group than `mooring`, also holds the restart. The installer
prints `mooring: NOT restarted. This version refuses /etc/mooring/config.yaml:`, the output of
`mooring config check`, and one of:

```text
The service that was running keeps running on the previous version until it is
restarted; it will not start again with this file. Fix the file, then run:
  sudo mooring config check
  sudo systemctl restart mooring
```

```text
The service is not running, and it will not start with this file. Fix the file,
then run:
  sudo mooring config check
  sudo systemctl restart mooring
```

The first is printed when the service is running, the second when it is not.

### The unit file

The unit file settings behind this are `RestartPreventExitStatus=78` and this line, which runs
before the `ExecReload=` line that sends `SIGHUP`:

```ini
ExecReload=/usr/local/bin/mooring config check --errors-only --config /etc/mooring/config.yaml
```

The packages install the unit as
`/usr/lib/systemd/system/mooring.service`. A host with its own copy at
`/etc/systemd/system/mooring.service` (the [raw binary install](./installation.md#other-linux-install-the-raw-binary))
keeps the previous behaviour, a restart every 2 seconds and a reload without the check, until that
copy is replaced with the unit from the release and `sudo systemctl daemon-reload` is run.

---

## Files in `/etc/mooring`

| File | Owner and mode | What it is |
|---|---|---|
| `config.yaml` | `root:mooring`, `0640` | The configuration. Refused when it is not owned by root, is group-writable, is accessible by others, or is group-readable with a group that is neither `root` nor the service's. The service cannot read a file without group read (`0600`). |
| `config.yaml.last-good` | `root`, `0600` | The file `config edit` last replaced. To go back: `sudo cp /etc/mooring/config.yaml.last-good /etc/mooring/config.yaml` (the existing file keeps its owner and mode), then check and apply. |
| `config.yaml.rejected-edit` | `root`, `0600` | An edit `config edit` did not install because the file changed while it was being edited. It stays until it is removed by hand; a later kept edit replaces it. |
| `.config.lock` | `root`, `0600` | The lock of `config edit`. Empty. It stays in place between runs. |
| `.config.yaml.edit-*.yaml`, `.config.yaml.new-*` | `root`, `0600` | Copies of a `config edit` in progress, and the editor's backup and swap files for them. Removed when it ends; a later run removes leftovers. |

`config.yaml.last-good`, `config.yaml.rejected-edit` and the editing copies contain the same
secrets as `config.yaml`.
