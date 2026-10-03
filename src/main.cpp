// AuroraSecret entry point.
#include <exception>
#include <string>
#include <vector>

#include "aurora.h"
#include "cli.h"
#include "fsutil.h"
#include "log.h"

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <shellapi.h>
#  pragma comment(lib, "shell32.lib")
#endif

namespace {

// The command line is always treated as UTF-8. On Windows the wide command
// line is used so that non-ASCII paths survive.
std::vector<std::string> command_line_arguments(int argc, char** argv) {
  std::vector<std::string> arguments;
#if defined(_WIN32)
  (void)argc;
  (void)argv;
  int wide_count = 0;
  LPWSTR* wide_arguments = ::CommandLineToArgvW(::GetCommandLineW(), &wide_count);
  if (wide_arguments == nullptr) {
    return arguments;
  }
  arguments.reserve(static_cast<size_t>(wide_count));
  for (int index = 0; index < wide_count; ++index) {
    arguments.push_back(aurora::fsutil::wide_to_utf8(wide_arguments[index]));
  }
  ::LocalFree(wide_arguments);
#else
  arguments.reserve(static_cast<size_t>(argc));
  for (int index = 0; index < argc; ++index) {
    arguments.emplace_back(argv[index]);
  }
#endif
  return arguments;
}

}  // namespace

int main(int argc, char** argv) {
  aurora::log::prepare_console();
  const std::vector<std::string> arguments = command_line_arguments(argc, argv);

  try {
    return aurora::run_cli(arguments);
  } catch (const aurora::Error& error) {
    aurora::log::error(error.what());
    return static_cast<int>(error.code());
  } catch (const std::exception& error) {
    aurora::log::error(std::string("unexpected failure: ") + error.what());
    return static_cast<int>(aurora::ExitCode::kInternal);
  } catch (...) {
    aurora::log::error("unexpected failure");
    return static_cast<int>(aurora::ExitCode::kInternal);
  }
}
