// Password acquisition: options, environment, key files and the terminal.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "aurora.h"

namespace aurora {

// Owns a password and overwrites its storage when it goes away.
class SecureString {
 public:
  SecureString() = default;
  explicit SecureString(std::string value);
  ~SecureString();

  SecureString(const SecureString&) = delete;
  SecureString& operator=(const SecureString&) = delete;
  SecureString(SecureString&& other) noexcept;
  SecureString& operator=(SecureString&& other) noexcept;

  const std::string& str() const { return value_; }
  bool empty() const { return value_.empty(); }
  void clear();

 private:
  std::string value_;
};

struct PasswordOptions {
  std::string password;          // --password
  bool password_given = false;   // --password was used, even when empty
  std::string password_file;     // --password-file
  std::string password_env;      // --password-env
  bool password_stdin = false;   // --password-stdin
  std::string key_file;          // --key-file
};

// Resolution order: --password, --password-file, --password-env,
// AURORASECRET_PASSWORD, AURORASECRET_PASSWORD_FILE, --password-stdin, prompt.
// 'confirm' asks twice, which is what encryption wants.
SecureString resolve_password(const PasswordOptions& options, bool confirm);

// Reads a key file (any bytes). Returns an empty vector when 'path' is empty.
std::vector<uint8_t> read_key_file(const std::string& path);

// True when a password can be typed interactively.
bool can_prompt_for_password();

}  // namespace aurora
