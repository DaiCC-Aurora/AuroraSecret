// Small, dependency free helpers: little endian codec, formatting, globbing.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace aurora::util {

// ---------------------------------------------------------------------------
// Little endian helpers. The on-disk format is little endian everywhere.
// ---------------------------------------------------------------------------
inline void put_le16(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v & 0xFFu);
  p[1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
}

inline void put_le32(uint8_t* p, uint32_t v) {
  for (int i = 0; i < 4; ++i) {
    p[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
  }
}

inline void put_le64(uint8_t* p, uint64_t v) {
  for (int i = 0; i < 8; ++i) {
    p[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
  }
}

inline uint16_t get_le16(const uint8_t* p) {
  return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                               (static_cast<uint16_t>(p[1]) << 8));
}

inline uint32_t get_le32(const uint8_t* p) {
  uint32_t v = 0;
  for (int i = 0; i < 4; ++i) {
    v |= static_cast<uint32_t>(p[i]) << (8 * i);
  }
  return v;
}

inline uint64_t get_le64(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) {
    v |= static_cast<uint64_t>(p[i]) << (8 * i);
  }
  return v;
}

void append_le16(std::vector<uint8_t>& out, uint16_t value);
void append_le32(std::vector<uint8_t>& out, uint32_t value);
void append_le64(std::vector<uint8_t>& out, uint64_t value);

// ---------------------------------------------------------------------------
// Formatting and parsing
// ---------------------------------------------------------------------------
std::string format_size(uint64_t bytes);
std::string format_time(int64_t unix_seconds);
std::string hex_encode(const uint8_t* data, size_t length);
std::string to_lower_ascii(const std::string& text);
bool parse_uint64(const std::string& text, uint64_t& value);

// Shell like glob: '*' matches any run of characters (including '/'), '?'
// matches exactly one character. Everything else is literal.
bool glob_match(const std::string& pattern, const std::string& text);

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------
bool is_tty_stdin();
bool is_tty_stderr();
int64_t now_unix_seconds();
std::string get_env(const char* name);

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------
void wipe_memory(void* data, size_t length);
bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t length);

}  // namespace aurora::util
