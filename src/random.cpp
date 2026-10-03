#include "random.h"

#include <cstring>

#include "aurora.h"

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <bcrypt.h>
#elif defined(__APPLE__)
#  include <cstdlib>  // arc4random_buf
#elif defined(__linux__)
#  include <cerrno>
#  include <fcntl.h>
#  include <sys/random.h>
#  include <unistd.h>
#else
#  include <cerrno>
#  include <fcntl.h>
#  include <unistd.h>
#endif

namespace aurora {
namespace {

#if !defined(_WIN32) && !defined(__APPLE__)
// Reads from /dev/urandom. Used on every POSIX system except Apple platforms,
// which get arc4random_buf, and as a fallback when getrandom() is unavailable.
void read_urandom(void* buffer, size_t length) {
  int fd = -1;
  do {
    fd = ::open("/dev/urandom", O_RDONLY
#if defined(O_CLOEXEC)
                | O_CLOEXEC
#endif
    );
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    fail(ExitCode::kInternal, "cannot open /dev/urandom for random data");
  }
  uint8_t* cursor = static_cast<uint8_t*>(buffer);
  size_t remaining = length;
  while (remaining > 0) {
    const ssize_t got = ::read(fd, cursor, remaining);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      ::close(fd);
      fail(ExitCode::kInternal, "cannot read random data from /dev/urandom");
    }
    if (got == 0) {
      ::close(fd);
      fail(ExitCode::kInternal, "/dev/urandom returned no data");
    }
    cursor += static_cast<size_t>(got);
    remaining -= static_cast<size_t>(got);
  }
  ::close(fd);
}
#endif

}  // namespace

void random_bytes(void* buffer, size_t length) {
  if (length == 0) {
    return;
  }
#if defined(_WIN32)
  const NTSTATUS status = ::BCryptGenRandom(
      nullptr, static_cast<PUCHAR>(buffer), static_cast<ULONG>(length),
      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (status < 0) {
    fail(ExitCode::kInternal, "BCryptGenRandom failed");
  }
#elif defined(__APPLE__)
  ::arc4random_buf(buffer, length);
#elif defined(__linux__)
  uint8_t* cursor = static_cast<uint8_t*>(buffer);
  size_t remaining = length;
  while (remaining > 0) {
    const ssize_t got = ::getrandom(cursor, remaining, 0);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      // getrandom() can be unavailable in very old containers: fall back.
      read_urandom(cursor, remaining);
      return;
    }
    if (got == 0) {
      read_urandom(cursor, remaining);
      return;
    }
    cursor += static_cast<size_t>(got);
    remaining -= static_cast<size_t>(got);
  }
#else
  read_urandom(buffer, length);
#endif
}

}  // namespace aurora
