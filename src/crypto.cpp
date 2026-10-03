#include "crypto.h"

#include <cstring>

#include "aurora.h"
#include "random.h"
#include "util.h"

// Monocypher 4.0.2. Vendored in third_party/monocypher/ and, when that copy is
// missing, downloaded at configure time (or supplied through
// -DAURORASECRET_MONOCYPHER_DIR); see CMakeLists.txt.
extern "C" {
#include "monocypher.h"
}

namespace aurora::crypto {
namespace {

// Domain separation string for derived nonces. Bumping it invalidates every
// nonce derived with an older version, so it is part of the format.
constexpr char kNonceDomain[] = "AuroraSecret/nonce/v1";

constexpr uint32_t kArgon2MinBlocks = 8;

}  // namespace

void random_bytes(void* buffer, size_t length) {
  aurora::random_bytes(buffer, length);
}

Salt random_salt() {
  Salt salt{};
  random_bytes(salt.data(), salt.size());
  return salt;
}

void blake2b(uint8_t* out, size_t out_length, const void* message,
             size_t message_length) {
  crypto_blake2b(out, out_length,
                 static_cast<const uint8_t*>(message), message_length);
}

void blake2b_keyed(uint8_t* out, size_t out_length, const void* key,
                   size_t key_length, const void* message,
                   size_t message_length) {
  crypto_blake2b_keyed(out, out_length, static_cast<const uint8_t*>(key),
                       key_length, static_cast<const uint8_t*>(message),
                       message_length);
}

Key derive_key(const std::string& password, const Salt& salt, uint32_t blocks,
               uint32_t passes) {
  if (blocks < kArgon2MinBlocks) {
    fail(ExitCode::kUsage, "Argon2 requires at least " +
                               std::to_string(kArgon2MinBlocks) + " blocks");
  }
  if (passes < 1) {
    fail(ExitCode::kUsage, "Argon2 requires at least one pass");
  }
  // Argon2 work area: one kibibyte per block (Monocypher's `blk` is 1 KiB).
  std::vector<uint8_t> work_area(static_cast<size_t>(blocks) * 1024u, 0);

  // Monocypher 4.x derives every Argon2 variant through one entry point.
  const crypto_argon2_config config = {
      CRYPTO_ARGON2_I,   // algorithm: Argon2i, the data independent variant
      blocks,            // memory hardness, in 1 KiB blocks
      passes,            // time hardness
      1                  // lanes: single threaded
  };
  const crypto_argon2_inputs inputs = {
      reinterpret_cast<const uint8_t*>(password.data()),
      salt.data(),
      static_cast<uint32_t>(password.size()),
      static_cast<uint32_t>(salt.size())
  };
  const crypto_argon2_extras extras = crypto_argon2_no_extras;

  Key key{};
  crypto_argon2(key.data(), static_cast<uint32_t>(key.size()),
                work_area.data(), config, inputs, extras);
  util::wipe_memory(work_area.data(), work_area.size());
  return key;
}

Key combine_keyfile(const Key& key, const std::vector<uint8_t>& key_file) {
  // Hash the key file first so that huge key files stay cheap, then use that
  // digest as the BLAKE2b key for the derived password key.
  uint8_t digest[32];
  blake2b(digest, sizeof(digest), key_file.empty() ? nullptr : key_file.data(),
          key_file.size());
  Key combined{};
  blake2b_keyed(combined.data(), combined.size(), digest, sizeof(digest),
                key.data(), key.size());
  util::wipe_memory(digest, sizeof(digest));
  return combined;
}

Nonce frame_nonce(uint64_t entry_index, uint64_t chunk_index) {
  uint8_t message[sizeof(kNonceDomain) - 1 + 8 + 8];
  std::memcpy(message, kNonceDomain, sizeof(kNonceDomain) - 1);
  util::put_le64(message + sizeof(kNonceDomain) - 1, entry_index);
  util::put_le64(message + sizeof(kNonceDomain) - 1 + 8, chunk_index);
  Nonce nonce{};
  blake2b(nonce.data(), nonce.size(), message, sizeof(message));
  return nonce;
}

void aead_lock(uint8_t* cipher_out, Mac& mac, const Key& key, const Nonce& nonce,
               const void* associated_data, size_t associated_length,
               const void* plain, size_t plain_length) {
  // Monocypher tolerates zero length messages, but never a null pointer.
  uint8_t scratch_cipher = 0;
  uint8_t scratch_plain = 0;
  uint8_t scratch_ad = 0;
  uint8_t* cipher = cipher_out != nullptr ? cipher_out : &scratch_cipher;
  const uint8_t* plain_bytes =
      plain != nullptr ? static_cast<const uint8_t*>(plain) : &scratch_plain;
  const uint8_t* ad_bytes = associated_data != nullptr
                                ? static_cast<const uint8_t*>(associated_data)
                                : &scratch_ad;
  crypto_aead_lock(cipher, mac.data(), key.data(), nonce.data(), ad_bytes,
                   associated_length, plain_bytes, plain_length);
}

bool aead_unlock(void* plain_out, const Mac& mac, const Key& key,
                 const Nonce& nonce, const void* associated_data,
                 size_t associated_length, const void* cipher,
                 size_t cipher_length) {
  uint8_t scratch_plain = 0;
  uint8_t scratch_cipher = 0;
  uint8_t scratch_ad = 0;
  uint8_t* plain = plain_out != nullptr ? static_cast<uint8_t*>(plain_out)
                                        : &scratch_plain;
  const uint8_t* cipher_bytes =
      cipher != nullptr ? static_cast<const uint8_t*>(cipher) : &scratch_cipher;
  const uint8_t* ad_bytes = associated_data != nullptr
                                ? static_cast<const uint8_t*>(associated_data)
                                : &scratch_ad;
  return crypto_aead_unlock(plain, mac.data(), key.data(), nonce.data(), ad_bytes,
                            associated_length, cipher_bytes, cipher_length) == 0;
}

void wipe(void* data, size_t length) {
  util::wipe_memory(data, length);
}

void wipe(std::string& text) {
  if (!text.empty()) {
    util::wipe_memory(&text[0], text.size());
    text.clear();
  }
}

}  // namespace aurora::crypto
