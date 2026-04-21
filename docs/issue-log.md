# issue log

## closed

### decrypt output could collide with the original file

- status: closed
- fixed: 2026-04-01
- note: decrypting to `notes.txt` when `notes.txt` already existed caused conflicts, so it now falls back to names like `notes.decrypted.txt`

### gui sizing felt cramped on smaller windows

- status: closed
- fixed: 2026-04-01
- note: bumped the minimum window sizing and tightened some spacing in the controls

## open

### pbkdf2 iterations feel slow on older machines

- status: open
- note: `600000` feels okay on my machine, but it is noticeably slower on weaker laptops

### passphrase word list still has some boring picks

- status: open
- note: some outputs still feel a little too plain
