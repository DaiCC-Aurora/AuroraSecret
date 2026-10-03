#include "util.h"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <io.h>
#else
#  include <unistd.h>
#endif

namespace aurora::util {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

}  // namespace

void append_le16(std::vector<uint8_t>& out, uint16_t value) {
  uint8_t buffer[2];
  put_le16(buffer, value);
  out.insert(out.end(), buffer, buffer + sizeof(buffer));
}

void append_le32(std::vector<uint8_t>& out, uint32_t value) {
  uint8_t buffer[4];
  put_le32(buffer, value);
  out.insert(out.end(), buffer, buffer + sizeof(buffer));
}

void append_le64(std::vector<uint8_t>& out, uint64_t value) {
  uint8_t buffer[8];
  put_le64(buffer, value);
  out.insert(out.end(), buffer, buffer + sizeof(buffer));
}

std::string format_size(uint64_t bytes) {
  static const char* kUnits[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB"};
  double value = static_cast<double>(bytes);
  int unit = 0;
  while (value >= 1024.0 && unit < 5) {
    value /= 1024.0;
    ++unit;
  }
  char buffer[64];
  if (unit == 0) {
    std::snprintf(buffer, sizeof(buffer), "%llu B",
                  static_cast<unsigned long long>(bytes));
  } else {
    std::snprintf(buffer, sizeof(buffer), "%.1f %s", value, kUnits[unit]);
  }
  return std::string(buffer);
}

std::string format_time(int64_t unix_seconds) {
  if (unix_seconds <= 0) {
    return "-";
  }
  const std::time_t when = static_cast<std::time_t>(unix_seconds);
  std::tm parts{};
#if defined(_WIN32)
  if (localtime_s(&parts, &when) != 0) {
    return "-";
  }
#else
  if (localtime_r(&when, &parts) == nullptr) {
    return "-";
  }
#endif
  char buffer[32];
  if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &parts) == 0) {
    return "-";
  }
  return std::string(buffer);
}

std::string hex_encode(const uint8_t* data, size_t length) {
  std::string out;
  out.reserve(length * 2);
  for (size_t i = 0; i < length; ++i) {
    out.push_back(kHexDigits[(data[i] >> 4) & 0x0F]);
    out.push_back(kHexDigits[data[i] & 0x0F]);
  }
  return out;
}

std::string to_lower_ascii(const std::string& text) {
  std::string out = text;
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c - 'A' + 'a');
    }
  }
  return out;
}

bool parse_uint64(const std::string& text, uint64_t& value) {
  if (text.empty()) {
    return false;
  }
  for (char c : text) {
    if (c < '0' || c > '9') {
      return false;
    }
  }
  errno = 0;
  char* end = nullptr;
  const unsigned long long parsed = std::strtoull(text.c_str(), &end, 10);
  if (errno != 0 || end == nullptr || *end != '\0') {
    return false;
  }
  value = static_cast<uint64_t>(parsed);
  return true;
}

bool glob_match(const std::string& pattern, const std::string& text) {
  size_t p = 0;
  size_t t = 0;
  size_t star = std::string::npos;
  size_t mark = 0;
  while (t < text.size()) {
    if (p < pattern.size() && (pattern[p] == '?' || pattern[p] == text[t])) {
      ++p;
      ++t;
    } else if (p < pattern.size() && pattern[p] == '*') {
      star = p;
      ++p;
      mark = t;
    } else if (star != std::string::npos) {
      // Let the last '*' consume one more character and rematch from there.
      p = star + 1;
      t = ++mark;
    } else {
      return false;
    }
  }
  while (p < pattern.size() && pattern[p] == '*') {
    ++p;
  }
  return p == pattern.size();
}

bool is_tty_stdin() {
#if defined(_WIN32)
  return _isatty(_fileno(stdin)) != 0;
#else
  return isatty(STDIN_FILENO) != 0;
#endif
}

bool is_tty_stderr() {
#if defined(_WIN32)
  return _isatty(_fileno(stderr)) != 0;
#else
  return isatty(STDERR_FILENO) != 0;
#endif
}

int64_t now_unix_seconds() {
  using namespace std::chrono;
  return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

std::string get_env(const char* name) {
  const char* value = std::getenv(name);
  return value == nullptr ? std::string() : std::string(value);
}

void wipe_memory(void* data, size_t length) {
  if (data == nullptr || length == 0) {
    return;
  }
  volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
  while (length-- > 0) {
    *cursor++ = 0;
  }
}

bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t length) {
  uint8_t difference = 0;
  for (size_t i = 0; i < length; ++i) {
    difference = static_cast<uint8_t>(difference | (a[i] ^ b[i]));
  }
  return difference == 0;
}

}  // namespace aurora::util
