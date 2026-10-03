#include "fsutil.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <system_error>

#include "util.h"

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <sys/stat.h>
#endif

namespace aurora::fsutil {
namespace {

void append_utf8(std::string& out, uint32_t code_point) {
  if (code_point <= 0x7F) {
    out.push_back(static_cast<char>(code_point));
  } else if (code_point <= 0x7FF) {
    out.push_back(static_cast<char>(0xC0 | (code_point >> 6)));
    out.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
  } else if (code_point <= 0xFFFF) {
    out.push_back(static_cast<char>(0xE0 | (code_point >> 12)));
    out.push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
  } else {
    out.push_back(static_cast<char>(0xF0 | (code_point >> 18)));
    out.push_back(static_cast<char>(0x80 | ((code_point >> 12) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
  }
}

bool component_is_reserved(const std::string& component) {
  std::string stem = component;
  const size_t dot = stem.find('.');
  if (dot != std::string::npos) {
    stem = stem.substr(0, dot);
  }
  stem = util::to_lower_ascii(stem);
  if (stem == "con" || stem == "prn" || stem == "aux" || stem == "nul") {
    return true;
  }
  if (stem.size() == 4 && (stem.compare(0, 3, "com") == 0 ||
                           stem.compare(0, 3, "lpt") == 0)) {
    return stem[3] >= '1' && stem[3] <= '9';
  }
  return false;
}

}  // namespace

std::string path_to_utf8(const fs::path& path) {
#if defined(_WIN32)
  return wide_to_utf8(path.native());
#else
  return path.native();
#endif
}

fs::path path_from_utf8(const std::string& text) {
#if defined(_WIN32)
  return fs::path(utf8_to_wide(text));
#else
  return fs::path(text);
#endif
}

std::string wide_to_utf8(const std::wstring& text) {
#if defined(_WIN32)
  if (text.empty()) {
    return std::string();
  }
  const int needed = ::WideCharToMultiByte(CP_UTF8, 0, text.data(),
                                           static_cast<int>(text.size()),
                                           nullptr, 0, nullptr, nullptr);
  if (needed <= 0) {
    return std::string();
  }
  std::string out(static_cast<size_t>(needed), '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        &out[0], needed, nullptr, nullptr);
  return out;
#else
  std::string out;
  out.reserve(text.size());
  for (wchar_t character : text) {
    append_utf8(out, static_cast<uint32_t>(character));
  }
  return out;
#endif
}

std::wstring utf8_to_wide(const std::string& text) {
#if defined(_WIN32)
  if (text.empty()) {
    return std::wstring();
  }
  const int needed = ::MultiByteToWideChar(CP_UTF8, 0, text.data(),
                                           static_cast<int>(text.size()),
                                           nullptr, 0);
  if (needed <= 0) {
    return std::wstring();
  }
  std::wstring out(static_cast<size_t>(needed), L'\0');
  ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        &out[0], needed);
  return out;
#else
  std::wstring out;
  out.reserve(text.size());
  size_t index = 0;
  while (index < text.size()) {
    const uint8_t first = static_cast<uint8_t>(text[index]);
    uint32_t code_point = 0;
    size_t extra = 0;
    if (first < 0x80) {
      code_point = first;
    } else if ((first & 0xE0) == 0xC0) {
      code_point = first & 0x1Fu;
      extra = 1;
    } else if ((first & 0xF0) == 0xE0) {
      code_point = first & 0x0Fu;
      extra = 2;
    } else if ((first & 0xF8) == 0xF0) {
      code_point = first & 0x07u;
      extra = 3;
    } else {
      // Invalid leading byte: keep it as a single byte code point.
      out.push_back(static_cast<wchar_t>(first));
      ++index;
      continue;
    }
    if (index + extra >= text.size()) {
      out.push_back(static_cast<wchar_t>(first));
      ++index;
      continue;
    }
    for (size_t i = 1; i <= extra; ++i) {
      code_point = (code_point << 6) |
                   (static_cast<uint8_t>(text[index + i]) & 0x3Fu);
    }
    index += extra + 1;
    out.push_back(static_cast<wchar_t>(code_point));
  }
  return out;
#endif
}

std::string archive_path_string(const fs::path& relative) {
  std::string out;
  for (const fs::path& component : relative) {
    const std::string text = path_to_utf8(component);
    if (text.empty() || text == ".") {
      continue;
    }
    if (!out.empty()) {
      out.push_back('/');
    }
    out += text;
  }
  return out;
}

std::string archive_path_join(const std::string& base, const std::string& name) {
  if (base.empty()) {
    return name;
  }
  if (name.empty()) {
    return base;
  }
  std::string out = base;
  out.push_back('/');
  out += name;
  return out;
}

bool is_safe_archive_path(const std::string& archive_path) {
  try {
    validate_archive_path(archive_path);
    return true;
  } catch (const Error&) {
    return false;
  }
}

void validate_archive_path(const std::string& archive_path) {
  const std::string display =
      archive_path.size() > 200 ? archive_path.substr(0, 200) + "..." : archive_path;
  if (archive_path.empty()) {
    fail(ExitCode::kCrypto, "archive contains an entry with an empty path");
  }
  if (archive_path.size() > kMaxArchivePathLength) {
    fail(ExitCode::kCrypto, "archive path is too long: " + display);
  }
  if (archive_path.find('\0') != std::string::npos) {
    fail(ExitCode::kCrypto, "archive path contains a NUL byte");
  }
  if (archive_path[0] == '/' || archive_path[0] == '\\') {
    fail(ExitCode::kCrypto, "archive path is absolute: " + display);
  }
  if (archive_path.find('\\') != std::string::npos) {
    fail(ExitCode::kCrypto, "archive path contains a backslash: " + display);
  }
  if (archive_path.size() >= 2 && archive_path[1] == ':') {
    fail(ExitCode::kCrypto, "archive path starts with a drive letter: " + display);
  }

  size_t start = 0;
  while (true) {
    const size_t slash = archive_path.find('/', start);
    const std::string component =
        slash == std::string::npos
            ? archive_path.substr(start)
            : archive_path.substr(start, slash - start);
    if (component.empty()) {
      fail(ExitCode::kCrypto, "archive path has an empty component: " + display);
    }
    if (component == "." || component == "..") {
      fail(ExitCode::kCrypto,
           "archive path escapes its destination (\"" + component + "\"): " +
               display);
    }
    if (component.size() > kMaxPathComponentLength) {
      fail(ExitCode::kCrypto, "archive path component is too long: " + display);
    }
#if defined(_WIN32)
    for (char raw : component) {
      const unsigned char c = static_cast<unsigned char>(raw);
      if (c < 0x20 || raw == '<' || raw == '>' || raw == ':' || raw == '"' ||
          raw == '|' || raw == '?' || raw == '*') {
        fail(ExitCode::kCrypto,
             "archive path is not usable on Windows: " + display);
      }
    }
    if (component.back() == ' ' || component.back() == '.') {
      fail(ExitCode::kCrypto,
           "archive path component ends with a space or a dot: " + display);
    }
    if (component_is_reserved(component)) {
      fail(ExitCode::kCrypto,
           "archive path uses a reserved Windows device name: " + display);
    }
#endif
    if (slash == std::string::npos) {
      break;
    }
    start = slash + 1;
  }
}

bool path_is_within(const fs::path& base, const fs::path& candidate) {
  const fs::path normal_base = base.lexically_normal();
  const fs::path normal_candidate = candidate.lexically_normal();
  fs::path::const_iterator base_it = normal_base.begin();
  fs::path::const_iterator candidate_it = normal_candidate.begin();
  for (; base_it != normal_base.end(); ++base_it, ++candidate_it) {
    if (candidate_it == normal_candidate.end()) {
      return false;
    }
    if (*base_it != *candidate_it) {
      return false;
    }
  }
  return true;
}

fs::path absolute_lexical(const fs::path& path) {
  std::error_code ec;
  if (path.is_absolute()) {
    return path.lexically_normal();
  }
  const fs::path current = fs::current_path(ec);
  if (ec) {
    return path.lexically_normal();
  }
  return (current / path).lexically_normal();
}

fs::file_time_type file_time_from_unix(int64_t unix_seconds) {
  using namespace std::chrono;
  const auto system_now = system_clock::now();
  const auto file_now = fs::file_time_type::clock::now();
  const auto target = system_clock::time_point(seconds(unix_seconds));
  return file_now + duration_cast<fs::file_time_type::duration>(target - system_now);
}

int64_t unix_from_file_time(fs::file_time_type time) {
  using namespace std::chrono;
  const auto system_now = system_clock::now();
  const auto file_now = fs::file_time_type::clock::now();
  const auto converted =
      system_now + duration_cast<system_clock::duration>(time - file_now);
  return duration_cast<seconds>(converted.time_since_epoch()).count();
}

uint32_t file_mode(const fs::path& path) {
#if defined(_WIN32)
  (void)path;
  return 0;
#else
  struct stat info {};
  if (::stat(path.c_str(), &info) != 0) {
    return 0;
  }
  return static_cast<uint32_t>(info.st_mode & 07777);
#endif
}

fs::perms perms_from_mode(uint32_t mode) {
  fs::perms result = fs::perms::none;
  if ((mode & 0400u) != 0) result |= fs::perms::owner_read;
  if ((mode & 0200u) != 0) result |= fs::perms::owner_write;
  if ((mode & 0100u) != 0) result |= fs::perms::owner_exec;
  if ((mode & 0040u) != 0) result |= fs::perms::group_read;
  if ((mode & 0020u) != 0) result |= fs::perms::group_write;
  if ((mode & 0010u) != 0) result |= fs::perms::group_exec;
  if ((mode & 0004u) != 0) result |= fs::perms::others_read;
  if ((mode & 0002u) != 0) result |= fs::perms::others_write;
  if ((mode & 0001u) != 0) result |= fs::perms::others_exec;
  return result;
}

std::string top_level_name(const fs::path& input) {
  std::string name;
  if (input.has_filename()) {
    name = path_to_utf8(input.filename());
  }
  if (name == "." || name == "..") {
    name.clear();
  }
  if (name.empty()) {
    std::error_code ec;
    const fs::path canonical = fs::canonical(input, ec);
    if (ec) {
      fail(ExitCode::kIo, "cannot resolve '" + path_to_utf8(input) +
                              "': " + ec.message());
    }
    if (canonical.has_filename()) {
      name = path_to_utf8(canonical.filename());
    }
  }
  if (name.empty() || name == "/" || name == "\\") {
    fail(ExitCode::kUsage,
         "cannot archive '" + path_to_utf8(input) + "': it has no usable name");
  }
  return name;
}

}  // namespace aurora::fsutil
