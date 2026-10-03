#include "log.h"

#include <chrono>
#include <cstdio>
#include <utility>

#include "util.h"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

namespace aurora {
namespace log {
namespace {

int g_verbose = 0;
bool g_quiet = false;
bool g_color = false;
bool g_ansi_supported = false;

const char* color_for(Level level) {
  if (!g_color) {
    return "";
  }
  switch (level) {
    case Level::kError:
      return "\x1b[31m";
    case Level::kWarn:
      return "\x1b[33m";
    case Level::kSuccess:
      return "\x1b[32m";
    case Level::kInfo:
    case Level::kVerbose:
    default:
      return "";
  }
}

const char* reset_code() { return g_color ? "\x1b[0m" : ""; }

const char* prefix_for(Level level) {
  switch (level) {
    case Level::kError:
      return "error: ";
    case Level::kWarn:
      return "warning: ";
    default:
      return "";
  }
}

}  // namespace

void set_verbose(int level) { g_verbose = level; }
void set_quiet(bool quiet) { g_quiet = quiet; }
void set_color(bool enabled) {
  g_color = enabled && g_ansi_supported && util::get_env("NO_COLOR").empty();
}
int verbose_level() { return g_verbose; }

bool prepare_console() {
#if defined(_WIN32)
  ::SetConsoleOutputCP(CP_UTF8);
  ::SetConsoleCP(CP_UTF8);
  const HANDLE handle = ::GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD mode = 0;
  if (handle != INVALID_HANDLE_VALUE && ::GetConsoleMode(handle, &mode) != 0) {
    g_ansi_supported =
        ::SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
  } else {
    g_ansi_supported = false;
  }
#else
  g_ansi_supported = true;
#endif
  return g_ansi_supported;
}

void write(Level level, const std::string& message) {
  switch (level) {
    case Level::kVerbose:
      if (g_quiet || g_verbose < 1) {
        return;
      }
      break;
    case Level::kInfo:
      if (g_quiet) {
        return;
      }
      break;
    default:
      break;
  }
  std::fprintf(stderr, "%s%s%s%s\n", color_for(level), prefix_for(level),
               message.c_str(), reset_code());
  std::fflush(stderr);
}

void info(const std::string& message) { write(Level::kInfo, message); }
void verbose(const std::string& message) { write(Level::kVerbose, message); }

void debug(const std::string& message) {
  if (g_verbose >= 2 && !g_quiet) {
    write(Level::kInfo, "debug: " + message);
  }
}

void warn(const std::string& message) { write(Level::kWarn, message); }
void error(const std::string& message) { write(Level::kError, message); }
void success(const std::string& message) { write(Level::kSuccess, message); }

}  // namespace log

namespace {

int64_t monotonic_ms() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch())
      .count();
}

}  // namespace

Progress::Progress(bool enabled, std::string label)
    : enabled_(enabled), label_(std::move(label)) {
  visible_ = enabled_ && util::is_tty_stderr();
}

void Progress::set_total(uint64_t total) { total_ = total; }

void Progress::update(uint64_t done, const std::string& current) {
  last_done_ = done;
  if (!visible_) {
    return;
  }
  const int64_t now = monotonic_ms();
  if (rendered_ && (now - last_render_ms_) < 80) {
    return;
  }
  render(done, current, false);
}

void Progress::finish() {
  if (!visible_ || !rendered_) {
    return;
  }
  render(last_done_, std::string(), true);
  std::fprintf(stderr, "\n");
  std::fflush(stderr);
}

void Progress::render(uint64_t done, const std::string& current, bool final_line) {
  last_render_ms_ = monotonic_ms();
  rendered_ = true;
  int percent = 0;
  if (total_ > 0) {
    percent = static_cast<int>((done * 100) / total_);
    if (percent > 100) {
      percent = 100;
    }
  }
  std::string text;
  if (total_ > 0) {
    char buffer[64];
    std::snprintf(buffer, sizeof(buffer), "%3d%%", percent);
    text = std::string(buffer) + " " + util::format_size(done) + " / " +
           util::format_size(total_);
  } else {
    text = util::format_size(done);
  }
  if (!final_line && !current.empty()) {
    text += "  ";
    text += current.size() > 48 ? "..." + current.substr(current.size() - 45)
                                : current;
  }
  const size_t width = 78;
  if (text.size() < width) {
    text.resize(width, ' ');
  }
  std::fprintf(stderr, "\r%s: %s", label_.c_str(), text.c_str());
  std::fflush(stderr);
}

}  // namespace aurora
