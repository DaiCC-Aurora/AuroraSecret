// Minimal logging plus the single line progress reporter.
#pragma once

#include <cstdint>
#include <string>

namespace aurora {
namespace log {

enum class Level {
  kInfo,
  kVerbose,
  kWarn,
  kError,
  kSuccess,
};

// 0 = normal, 1 = verbose (one line per entry), 2 = debug.
void set_verbose(int level);
void set_quiet(bool quiet);
void set_color(bool enabled);
// Configures the console (UTF-8 code page, ANSI escapes). Returns true when
// colored output is possible on this terminal.
bool prepare_console();

void write(Level level, const std::string& message);

void info(const std::string& message);
void verbose(const std::string& message);
void debug(const std::string& message);
void warn(const std::string& message);
void error(const std::string& message);
void success(const std::string& message);

int verbose_level();

}  // namespace log

// Renders "label: 43% (12.0 MiB / 28.0 MiB) current/path" on stderr, in place,
// but only when stderr is a terminal. Silent otherwise.
class Progress {
 public:
  Progress(bool enabled, std::string label);

  void set_total(uint64_t total);
  void update(uint64_t done, const std::string& current);
  void finish();

 private:
  void render(uint64_t done, const std::string& current, bool final_line);

  bool enabled_ = false;
  bool visible_ = false;
  std::string label_;
  uint64_t total_ = 0;
  uint64_t last_done_ = 0;
  int64_t last_render_ms_ = 0;
  bool rendered_ = false;
};

}  // namespace aurora
