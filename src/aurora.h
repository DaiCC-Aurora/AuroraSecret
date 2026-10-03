// AuroraSecret - command line batch file/folder encryption.
//
// Common declarations shared by every translation unit.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>

namespace aurora {

namespace fs = std::filesystem;

// Process exit codes. Kept small and stable so that scripts can rely on them.
enum class ExitCode : int {
  kOk = 0,        // everything succeeded
  kUsage = 1,     // bad command line
  kCrypto = 2,    // wrong password / corrupted or forged archive
  kIo = 3,        // filesystem or I/O problem
  kPartial = 4,   // the work finished but some entries were skipped
  kInternal = 5,  // unexpected internal failure
};

class Error : public std::runtime_error {
 public:
  Error(ExitCode code, const std::string& message)
      : std::runtime_error(message), code_(code) {}

  ExitCode code() const noexcept { return code_; }

 private:
  ExitCode code_;
};

[[noreturn]] inline void fail(ExitCode code, const std::string& message) {
  throw Error(code, message);
}

}  // namespace aurora
