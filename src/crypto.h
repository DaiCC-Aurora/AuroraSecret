// Thin, typed wrapper around the Monocypher primitives used by the container
// format: BLAKE2b, Argon2i and XChaCha20-Poly1305 (RFC 8439 construction).
//
// Everything the rest of the program knows about cryptography lives behind
// this header, so the backend can be replaced without touching the format.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace aurora::crypto {

constexpr size_t kKeySize = 32;
constexpr size_t kSaltSize = 16;
constexpr size_t kMacSize = 16;
constexpr size_t kNonceSize = 24;

using Key = std::array<uint8_t, kKeySize>;
using Salt = std::array<uint8_t, kSaltSize>;
using Mac = std::array<uint8_t, kMacSize>;
using Nonce = std::array<uint8_t, kNonceSize>;

// Fills the buffer with operating system entropy.
void random_bytes(void* buffer, size_t length);
Salt random_salt();

// BLAKE2b with an optional key, used for the header authenticator and for
// deriving frame nonces.
void blake2b(uint8_t* out, size_t out_length, const void* message,
             size_t message_length);
void blake2b_keyed(uint8_t* out, size_t out_length, const void* key,
                   size_t key_length, const void* message,
                   size_t message_length);

// Argon2i. 'blocks' is the work area size in kibibytes, 'passes' the number of
// iterations. The returned key is derived from the password and the salt only.
Key derive_key(const std::string& password, const Salt& salt, uint32_t blocks,
               uint32_t passes);

// Mixes a key file into an already derived key: BLAKE2b(key = H(key file),
// message = key). Both factors are required to recover the result.
Key combine_keyfile(const Key& key, const std::vector<uint8_t>& key_file);

// Deterministic, per frame nonce. Unique for every (entry, chunk) pair inside
// a single archive, which is all the AEAD requires.
Nonce frame_nonce(uint64_t entry_index, uint64_t chunk_index);

// XChaCha20-Poly1305. The ciphertext has exactly the same length as the
// plaintext; integrity lives in 'mac'. 'aead_unlock' returns false when the
// message was modified or the key is wrong.
void aead_lock(uint8_t* cipher_out, Mac& mac, const Key& key, const Nonce& nonce,
               const void* associated_data, size_t associated_length,
               const void* plain, size_t plain_length);
bool aead_unlock(void* plain_out, const Mac& mac, const Key& key,
                 const Nonce& nonce, const void* associated_data,
                 size_t associated_length, const void* cipher,
                 size_t cipher_length);

// Best effort secret erasure.
void wipe(void* data, size_t length);
void wipe(std::string& text);

}  // namespace aurora::crypto
