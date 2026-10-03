# Monocypher 4.0.2

`monocypher.c` and `monocypher.h` are the upstream Monocypher sources, version
4.0.2, taken verbatim from <https://github.com/LoupVaillant/Monocypher>:

| File | Size | SHA256 |
|------|-----:|--------|
| `monocypher.c` | 100273 | `02174117935699d418443c75a558a287deb06ef8cf7c1adced61d9047d2f323d` |
| `monocypher.h` | 12177 | `fcaf6ed771358bb4f40fba016f6518ae86ec02b1b877d2cc35ad92d3a26fd7b3` |

They are vendored so that AuroraSecret builds without network access and
against exactly the cryptography that was reviewed. `CMakeLists.txt` uses this
copy first; when the files are missing it downloads them, and the SHA256 sums
above are checked in that case.

Monocypher is dual licensed, **BSD-2-Clause OR CC0-1.0**; the full licence text
is at the top of `monocypher.h` and `monocypher.c`. AuroraSecret itself is MIT
(see `../../LICENSE`).

Upgrading: replace both files, update the table above, and update
`AURORASECRET_MONOCYPHER_VERSION` plus the pinned checksums in
`CMakeLists.txt`. AuroraSecret uses `crypto_argon2` (with
`CRYPTO_ARGON2_I`), `crypto_aead_lock`, `crypto_aead_unlock`,
`crypto_blake2b` and `crypto_blake2b_keyed`; anything from Monocypher 4.x
provides those.