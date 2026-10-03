# AuroraSecret

[![Build and Release](https://github.com/OWNER/AuroraSecret/actions/workflows/build.yml/badge.svg)](https://github.com/OWNER/AuroraSecret/actions/workflows/build.yml)

A small, dependency free command line tool that encrypts **files and whole
folder trees** into a single authenticated archive, and decrypts them back.
Written in C++17, built with CMake, released for Windows, Linux and macOS by
GitHub Actions.

```
aurorasecret encrypt Documents -o Documents.asf
aurorasecret decrypt Documents.asf -o restored/
```

## Highlights

* **Batch encryption** — pass any number of files and folders; a directory is
  stored together with its full tree in one `.asf` archive.
* **Real cryptography** — XChaCha20-Poly1305 for data, Argon2i for the password,
  BLAKE2b for the archive header, all through the audited, single file
  [Monocypher](https://monocypher.org) 4.0.2 library.
* **Everything is authenticated** — every frame carries its own tag and binds an
  entry/chunk counter, so edited, reordered, duplicated or truncated archives
  are rejected instead of silently decrypting to garbage.
* **Streaming** — files are processed in 1 MiB frames, so encrypting a 20 GiB
  file does not need 20 GiB of memory.
* **Safe by default** — refuses to overwrite an existing archive or file,
  refuses archive paths that try to escape the destination (`..`, absolute
  paths, drive letters), and never writes through a symbolic link it just
  extracted. A failed run deletes its half written output.
* **Cross platform** — one code base for Windows, Linux and macOS, with UTF-8
  path handling everywhere (including the Windows wide command line).
* **No dependencies to install** — apart from a C++17 compiler and CMake, the
  only library is the vendored, single file Monocypher 4.0.2; the build never
  needs network access.

## Cryptography

| Purpose | Primitive |
|---------|-----------|
| Key derivation | Argon2i, 64 MiB and 3 passes by default (configurable) |
| Data and metadata | XChaCha20-Poly1305 (AEAD), 24 byte derived nonce per frame |
| Header authenticator | BLAKE2b-128 keyed with the derived key |
| Nonces | BLAKE2b-192 over a domain string plus `entry index` and `chunk index` |
| Randomness | `BCryptGenRandom` (Windows), `getrandom`/`/dev/urandom` (Linux), `arc4random_buf` (macOS) |
| Optional second factor | arbitrary key file, mixed in with a keyed BLAKE2b |

The exact byte layout is documented in [docs/FORMAT.md](docs/FORMAT.md).

Things a user should know:

* There is **no password recovery**. Losing the password (and key file) loses
  the data, by design.
* `--password <text>` exposes the password to anyone who can list processes;
  prefer the interactive prompt, `--password-file`, `--password-env` or the
  `AURORASECRET_PASSWORD` environment variable.
* Entry names and sizes are encrypted, but the archive length and the number of
  entries are visible to an observer.
* The tool protects data at rest. It does not protect against a compromised
  machine, key loggers, or memory dumps taken while it runs.

## Building

Requirements: CMake 3.16 or newer and a C++17 compiler (MSVC 2019+, GCC 9+,
Clang 10+, or AppleClang 12+). Nothing else has to be installed, and no network
access is needed: Monocypher 4.0.2 is vendored in `third_party/monocypher/`.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Windows (Visual Studio), static runtime so no redistributable is required:

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DAURORASECRET_MSVC_STATIC_RUNTIME=ON
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

A fully static Linux binary:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DAURORASECRET_LINUX_STATIC=ON
```

A universal macOS binary:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES="x86_64;arm64"
```

### Build options

| Option | Default | Meaning |
|--------|---------|---------|
| `AURORASECRET_BUILD_TESTS` | `ON` | Build and register the test suite |
| `AURORASECRET_FETCH_MONOCYPHER` | `ON` | Download Monocypher when the vendored copy is missing |
| `AURORASECRET_MONOCYPHER_VERSION` | `4.0.2` | Version to download |
| `AURORASECRET_MONOCYPHER_DIR` | *(empty)* | Use another Monocypher checkout instead |
| `AURORASECRET_MSVC_STATIC_RUNTIME` | `OFF` | Link the MSVC runtime statically |
| `AURORASECRET_LINUX_STATIC` | `OFF` | Produce a fully static Linux binary |
| `AURORASECRET_WARNINGS_AS_ERRORS` | `OFF` | Turn compiler warnings into errors |

### The cryptography dependency

`third_party/monocypher/` holds Monocypher 4.0.2 (BSD-2-Clause OR CC0-1.0) with
the exact checksums recorded in its `README.md`. The build uses that copy, so a
fresh clone builds offline and always against the reviewed code.

If those files are missing, CMake downloads them from GitHub and verifies the
pinned SHA256 sums. To build against a different checkout instead:

```bash
git clone --depth 1 --branch 4.0.2 https://github.com/LoupVaillant/Monocypher
cmake -S . -B build -DAURORASECRET_MONOCYPHER_DIR=$PWD/Monocypher
```

To update the vendored version, replace both files, update the checksums in
`CMakeLists.txt` and in `third_party/monocypher/README.md`.

## Usage

```
aurorasecret encrypt [options] <path>...
aurorasecret decrypt [options] <archive.asf>
aurorasecret list    [options] <archive.asf>
aurorasecret --help | --version
```

### Encrypt

```
aurorasecret encrypt Documents -o Documents.asf
aurorasecret encrypt report.pdf notes.txt -o bundle.asf
aurorasecret encrypt ~/Pictures -o pictures.asf --exclude '*.tmp' --exclude 'Thumbs.db'
aurorasecret encrypt disk.img -o disk.asf --argon2-blocks 262144 --argon2-passes 4
aurorasecret encrypt project -o project.asf --follow-symlinks
```

Exactly one archive is produced. If `-o` is omitted the archive is named after
the first input (`Documents` → `Documents.asf`). Symlinks are stored as symlinks
by default; use `--follow-symlinks` to store their content, or `--no-symlinks`
to skip them.

### Decrypt

```
aurorasecret decrypt Documents.asf -o restored/
aurorasecret decrypt backup.asf                # into the current directory
aurorasecret decrypt backup.asf -o check/ --dry-run    # verify only
aurorasecret decrypt backup.asf -o restored/ --force   # overwrite existing files
```

### Inspect

```
aurorasecret list Documents.asf
```

```
TYPE      SIZE                 MODIFIED             PATH
directory 0 B                  -                    Documents/
file      12 B                 2026-01-31 09:14:22  Documents/notes.txt
file      1.5 MiB              2026-01-30 18:02:10  Documents/report.pdf
```

### Passwords and key files

The password is resolved in this order:

1. `--password <text>`
2. `--password-file <file>` (first line, line endings stripped)
3. `--password-env <VAR>`
4. `AURORASECRET_PASSWORD`
5. `AURORASECRET_PASSWORD_FILE`
6. `--password-stdin`
7. interactive prompt (`Password:` and, when encrypting, `Confirm password:`)

A key file adds a second factor: it is hashed and mixed into the derived key, so
both the password **and** the file are required.

```bash
head -c 32 /dev/urandom > aurora.key          # Linux / macOS
aurorasecret encrypt secrets -o secrets.asf -k aurora.key
aurorasecret decrypt secrets.asf -o out -k aurora.key
```

### Exit codes

| Code | Meaning |
|-----:|---------|
| 0 | success |
| 1 | usage error (bad options, unknown command) |
| 2 | wrong password, wrong key file, or a damaged/forged archive |
| 3 | I/O or filesystem error |
| 4 | partial success: some entries could not be written |
| 5 | unexpected internal failure |

## Tests

The suite is self contained (no test framework, no network) and is registered
with CTest:

* unit tests over the crypto wrappers, key derivation, nonce derivation and the
  AEAD round trip,
* archive round trips: files, nested folders, empty files, empty folders,
  Japanese/accented file names, multi-chunk files, symlinks, key files,
  preserved modification times,
* negative tests: wrong password, wrong key file, a flipped byte in the header
  and in the payload, truncation, trailing data, archives carrying `../escape`,
  absolute and drive-letter paths, writing through a symlinked parent,
  overwrite protection, and "a failed run leaves no archive behind",
* an end to end test of the real executable (`tests/cli_roundtrip.cmake`) that
  encrypts, lists, decrypts and checks the restored bytes on every platform.

```bash
ctest --test-dir build --output-on-failure
```

## Releases

The workflow [`.github/workflows/build.yml`](.github/workflows/build.yml) builds
and tests every push and pull request. Pushing a version tag publishes a release
with three packages plus `SHA256SUMS.txt`:

| Package | Asset |
|---------|-------|
| `aurorasecret-1.0.0-windows-x86_64.zip` | `aurorasecret.exe` (static runtime) |
| `aurorasecret-1.0.0-linux-x86_64.tar.gz` | `aurorasecret` (static binary) |
| `aurorasecret-1.0.0-macos-universal.tar.gz` | `aurorasecret` (arm64 + x86_64) |

```bash
git tag v1.0.0
git push origin v1.0.0
```

The tag can also be created from the GitHub web interface (*Releases → Draft a
new release → Choose a tag*). Each package contains the binary, `README.md`,
`LICENSE` and `docs/FORMAT.md`.

> If the release job fails with a permission error, allow write access under
> *Settings → Actions → General → Workflow permissions → Read and write*.
> Replace `OWNER` in the badge above with your account name.

## Project layout

```
CMakeLists.txt                 build, dependency fetching, install rules
src/aurora.h                   common types and the error/exit code model
src/util.*                     little endian codec, glob, formatting
src/random.*                   operating system entropy
src/crypto.*                   Monocypher wrappers (the only crypto code)
src/fileio.*                       checked binary file I/O
src/fsutil.*                   UTF-8 paths, archive path safety, timestamps
src/entry.h                    one archive entry
src/walk.*                     input tree -> flat entry list
src/container.*                the .asf reader and writer
src/extract.*                  safe extraction into a directory
src/password.*                 password resolution and secure storage
src/log.*                      logging, progress line, console setup
src/cli.*, src/main.cpp        command line interface
tests/                         unit tests and the end to end CLI test
third_party/monocypher/        vendored Monocypher 4.0.2 (BSD-2-Clause / CC0)
docs/FORMAT.md                 byte level container specification
docs/README.zh-CN.md           中文说明
```

## Limitations

* No compression and no incremental/append mode: each archive is written from
  scratch. Use `--force` to replace an old archive.
* Metadata preservation covers modification time and POSIX permission bits (on
  Windows only the read-only attribute); ownership, ACLs, xattrs and hard links
  are not stored.
* Special files (devices, sockets, FIFOs) are skipped with a warning. Skipped
  entries are counted in the exit code.
* Extraction of symbolic links needs `SeCreateSymbolicLinkPrivilege` on Windows
  (developer mode or an elevated shell); otherwise the archive should be created
  with `--follow-symlinks`.

## License

MIT, see [LICENSE](LICENSE). All cryptography is provided by
[Monocypher](https://monocypher.org), dual licensed CC0-1.0 / BSD-2-Clause.