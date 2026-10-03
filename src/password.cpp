#include "password.h"

#include <cstdio>
#include <cstdlib>
#include <system_error>
#include <utility>

#include "fsutil.h"
#include "fileio.h"
#include "util.h"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <conio.h>
#else
#  include <termios.h>
#  include <unistd.h>
#endif

namespace aurora {
namespace {

constexpr size_t kMaxPasswordFileSize = 1024 * 1024;   // 1 MiB
constexpr size_t kMaxKeyFileSize = 64 * 1024 * 1024;   // 64 MiB

std::string strip_line_endings(std::string line) {
  while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
    line.pop_back();
  }
  return line;
}

std::string read_line_from_stream(std::FILE* stream) {
  std::string line;
  int character = 0;
  while ((character = std::fgetc(stream)) != EOF && character != '\n') {
    line.push_back(static_cast<char>(character));
  }
  return strip_line_endings(std::move(line));
}

std::string read_password_from_stdin() {
  std::string line = read_line_from_stream(stdin);
  if (line.empty()) {
    fail(ExitCode::kUsage, "no password was read from standard input");
  }
  return line;
}

// Reads the first line of a text file, typically used with --password-file.
std::string read_first_line(const fs::path& path) {
  FileReader reader(path);
  std::string line;
  uint8_t byte = 0;
  size_t total = 0;
  while (reader.read(&byte, 1) == 1) {
    if (byte == '\n') {
      break;
    }
    if (++total > kMaxPasswordFileSize) {
      fail(ExitCode::kUsage,
           "password file '" + fsutil::path_to_utf8(path) + "' is too large");
    }
    line.push_back(static_cast<char>(byte));
  }
  return strip_line_endings(std::move(line));
}

#if defined(_WIN32)

std::string prompt_on_console(const std::string& prompt) {
  std::fputs(prompt.c_str(), stderr);
  std::fflush(stderr);
  HANDLE handle = ::GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode = 0;
  if (handle == INVALID_HANDLE_VALUE || ::GetConsoleMode(handle, &mode) == 0) {
    return read_line_from_stream(stdin);
  }
  const DWORD original_mode = mode;
  ::SetConsoleMode(handle, mode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
  std::wstring line;
  for (;;) {
    const wint_t character = ::_getwch();
    if (character == L'\r' || character == L'\n') {
      break;
    }
    if (character == 3) {  // Ctrl+C
      ::SetConsoleMode(handle, original_mode);
      std::fputc('\n', stderr);
      fail(ExitCode::kUsage, "aborted");
    }
    if (character == 8 || character == 127) {
      if (!line.empty()) {
        line.pop_back();
      }
      continue;
    }
    if (character == 0 || character == 0xE0) {  // extended key prefix
      (void)::_getwch();
      continue;
    }
    line.push_back(static_cast<wchar_t>(character));
  }
  ::SetConsoleMode(handle, original_mode);
  std::fputc('\n', stderr);
  return fsutil::wide_to_utf8(line);
}

#else

std::string prompt_on_console(const std::string& prompt) {
  std::FILE* input = stdin;
  bool is_terminal = util::is_tty_stdin();
  if (!is_terminal) {
    // `cmd < file` still needs to be able to ask for a password.
    std::FILE* terminal = std::fopen("/dev/tty", "r");
    if (terminal != nullptr) {
      input = terminal;
      is_terminal = true;
    }
  }

  std::fputs(prompt.c_str(), stderr);
  std::fflush(stderr);

  termios original {};
  bool echo_disabled = false;
  if (is_terminal && ::tcgetattr(::fileno(input), &original) == 0) {
    termios modified = original;
    modified.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    if (::tcsetattr(::fileno(input), TCSAFLUSH, &modified) == 0) {
      echo_disabled = true;
    }
  }

  std::string line = read_line_from_stream(input);

  if (echo_disabled) {
    ::tcsetattr(::fileno(input), TCSAFLUSH, &original);
    std::fputc('\n', stderr);
  }
  if (input != stdin) {
    std::fclose(input);
  }
  return line;
}

#endif

}  // namespace

SecureString::SecureString(std::string value) : value_(std::move(value)) {}

SecureString::~SecureString() { clear(); }

// Copying (and then wiping the source) keeps a moved-from object from holding
// a readable copy of the secret in its small-string buffer.
SecureString::SecureString(SecureString&& other) noexcept
    : value_(other.value_) {
  other.clear();
}

SecureString& SecureString::operator=(SecureString&& other) noexcept {
  if (this != &other) {
    clear();
    value_ = other.value_;
    other.clear();
  }
  return *this;
}

void SecureString::clear() {
  if (!value_.empty()) {
    util::wipe_memory(&value_[0], value_.size());
  }
  value_.clear();
}

bool can_prompt_for_password() {
#if defined(_WIN32)
  HANDLE handle = ::GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode = 0;
  if (handle != INVALID_HANDLE_VALUE && ::GetConsoleMode(handle, &mode) != 0) {
    return true;
  }
  return util::is_tty_stdin();
#else
  if (util::is_tty_stdin()) {
    return true;
  }
  std::FILE* terminal = std::fopen("/dev/tty", "r");
  if (terminal != nullptr) {
    std::fclose(terminal);
    return true;
  }
  return false;
#endif
}

SecureString resolve_password(const PasswordOptions& options, bool confirm) {
  std::string password;
  bool have_password = false;

  if (options.password_given) {
    password = options.password;
    have_password = true;
  } else if (!options.password_file.empty()) {
    password = read_first_line(fsutil::path_from_utf8(options.password_file));
    have_password = true;
  } else if (!options.password_env.empty()) {
    const std::string value = util::get_env(options.password_env.c_str());
    if (value.empty()) {
      fail(ExitCode::kUsage,
           "environment variable " + options.password_env + " is empty or unset");
    }
    password = value;
    have_password = true;
  } else {
    const std::string value = util::get_env("AURORASECRET_PASSWORD");
    if (!value.empty()) {
      password = value;
      have_password = true;
    }
  }

  if (!have_password) {
    const std::string file = util::get_env("AURORASECRET_PASSWORD_FILE");
    if (!file.empty()) {
      password = read_first_line(fsutil::path_from_utf8(file));
      have_password = true;
    }
  }

  if (!have_password && options.password_stdin) {
    password = read_password_from_stdin();
    have_password = true;
  }

  if (!have_password && can_prompt_for_password()) {
    password = prompt_on_console("Password: ");
    if (confirm) {
      const std::string again = prompt_on_console("Confirm password: ");
      if (again != password) {
        fail(ExitCode::kUsage, "the passwords do not match");
      }
    }
    have_password = true;
  }

  if (!have_password) {
    fail(ExitCode::kUsage,
         "no password was provided: use --password, --password-file, "
         "--password-env, --password-stdin or the AURORASECRET_PASSWORD "
         "environment variable");
  }
  if (password.empty()) {
    fail(ExitCode::kUsage, "the password must not be empty");
  }
  return SecureString(std::move(password));
}

std::vector<uint8_t> read_key_file(const std::string& path) {
  if (path.empty()) {
    return std::vector<uint8_t>();
  }
  const fs::path key_path = fsutil::path_from_utf8(path);
  std::error_code ec;
  const uint64_t size = fs::file_size(key_path, ec);
  if (ec) {
    fail(ExitCode::kIo, "cannot read the key file '" + path + "': " + ec.message());
  }
  if (size == 0) {
    fail(ExitCode::kUsage, "the key file '" + path + "' is empty");
  }
  if (size > kMaxKeyFileSize) {
    fail(ExitCode::kUsage, "the key file '" + path + "' is too large");
  }
  std::vector<uint8_t> data(static_cast<size_t>(size));
  FileReader reader(key_path);
  if (!reader.read_exact(data.data(), data.size())) {
    fail(ExitCode::kIo, "cannot read the key file '" + path + "'");
  }
  return data;
}

}  // namespace aurora
