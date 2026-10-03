# AuroraSecret container format (`.asf`), version 1.0

Everything is little endian. Sizes are byte counts. All strings are UTF-8.

An archive is a 64 byte header followed by a sequence of authenticated frames.
Every frame is sealed with XChaCha20-Poly1305 (the RFC 8439 AEAD construction);
the header carries its own keyed BLAKE2b authenticator so a wrong password is
reported before any payload is touched.

```
+---------------------------+
| header (64 bytes)         |
+---------------------------+
| frame: entry metadata     |   entry 0
| frame: data chunk 0       |
| frame: data chunk 1       |
| ...                       |
| frame: entry metadata     |   entry 1
| ...                       |
+---------------------------+
| frame: end marker         |
+---------------------------+
```

## Header

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0 | 6 | magic | `AURSEC` |
| 6 | 1 | version major | `1` |
| 7 | 1 | version minor | `0` |
| 8 | 1 | KDF id | `1` = Argon2i |
| 9 | 1 | AEAD id | `1` = XChaCha20-Poly1305 |
| 10 | 4 | Argon2 blocks | work area size in KiB, 8 … 1048576 |
| 14 | 4 | Argon2 passes | iterations, 1 … 64 |
| 18 | 16 | salt | fresh random salt per archive |
| 34 | 16 | header authenticator | see below |
| 50 | 1 | flags | bit 0: a key file was used |
| 51 | 13 | reserved | must be zero |

### Key schedule

```
kdf_key   = Argon2i(password, salt, blocks, passes, 32 bytes)
key_file_h = BLAKE2b-256(contents of the key file)
key       = key_file_h is present
              ? BLAKE2b-256(key = key_file_h, message = kdf_key)
              : kdf_key
header_mac = BLAKE2b-128(key = key, message = header[0..63] with bytes 34..49 zeroed)
```

The header authenticator covers the KDF parameters, the salt and the flags, so
nobody can weaken the parameters of an archive without knowing the password.
A wrong password (or a wrong key file) fails here with an authentication error.

## Frames

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | frame type: `1` metadata, `2` data, `3` end marker |
| 1 | 1 | flags: bit 0 = last frame of the current entry |
| 2 | 4 | plaintext size in bytes |
| 6 | 16 | Poly1305 authenticator |
| 22 | *n* | ciphertext (same length as the plaintext) |

* **Nonce** = `BLAKE2b-192("AuroraSecret/nonce/v1" ‖ u64 entry_index ‖ u64 chunk_index)`.
  Both counters are little endian. The nonce is never transmitted.
* **Associated data** = the 6 magic bytes, the version bytes `01 00`, then the
  frame type byte (9 bytes in total). This binds every frame to the format and
  makes frame type confusion impossible.
* **Chunk index** is `0` for a metadata frame and `1 + i` for the i-th data
  frame of the same entry. The end marker uses `entry_index` = number of
  entries and chunk index `0`, which no entry can reuse.
* Data frames hold exactly 1 MiB, except the last frame of an entry, which may
  be shorter and is marked with flag bit 0.
* Every file has at least one data frame, so an empty file is a single
  zero-length final frame.
* Anything after the end marker is rejected.

Because the counters are authenticated, reordering frames, duplicating them,
splicing frames from another archive, truncating the archive or removing the end
marker are all detected.

## Entry metadata

The metadata frame plaintext is:

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | entry type: `1` file, `2` directory, `3` symbolic link |
| 1 | 1 | flags, reserved, zero |
| 2 | 4 | path length in bytes |
| 6 | 8 | payload size: file bytes, or symbolic link target length |
| 14 | 8 | modification time, Unix seconds (`0` = unknown) |
| 22 | 4 | POSIX permission bits (`0` = unknown) |
| 26 | 4 | symbolic link target length in bytes |
| 30 | *p* | path |
| 30 + *p* | *l* | symbolic link target |

Rules:

* `path` is relative, uses `/` on every platform, never starts with `/`, never
  contains `\`, `\0`, an empty component, `.`, `..`, and never starts with a
  Windows drive letter. On Windows, reserved device names, illegal characters
  and components ending in a dot or a space are rejected as well.
* A directory has `payload size = 0` and `target length = 0` and no data frames.
* A symbolic link stores its target in the metadata and has no data frames;
  `payload size` equals `target length`.
* A file has `target length = 0`.
* The declared `payload size` must match the number of data bytes exactly.

## Limits

| Item | Limit |
|------|-------|
| Path length | 4096 bytes |
| Path component | 255 bytes |
| Metadata frame plaintext | 64 KiB |
| Data frame plaintext | 1 MiB |
| Argon2 memory | 8 KiB … 1 GiB |
| Argon2 passes | 1 … 64 |

## Notes for implementers

* Encryption is streamed in 1 MiB frames; memory use does not depend on the
  file size, only on the Argon2 work area.
* Extraction writes through a temporary file next to the target and renames it
  into place, so a crash never leaves a half written file behind.
* Extraction refuses to write through a symbolic link that already exists in
  the destination, which keeps a malicious archive from escaping the target
  directory through a link it planted earlier in the same archive.
* The format has no compression and no clear-text filenames: the entry names
  and sizes are only visible after a successful authentication.