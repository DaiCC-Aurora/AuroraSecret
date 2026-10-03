#include "io.h"

#include <cerrno>
#include <cstring>
#include <system_error>

#include "fsutil.h"

namespace aurora {
namespace {

std::string system_error_message() {
  return std::strerror(errno);
}

std::FILE* open_binary(const fs::path& path, const wchar_t* wide_mode,
                       const char* narrow_mode) {
#if defined(_WIN32)
  return _wfopen(path.wstring().c_str(), wide_mode);
#else
  (void)wide_mode;
  return std::fopen(path.c_str(), narrow_mode);
#endif
}

}  // namespace

FileReader::FileReader(const fs::path& path) : path_(path) {
  file_ = open_binary(path, L"rb", "rb");
  if (file_ == nullptr) {
    fail(ExitCode::kIo, "cannot open '" + fsutil::path_to_utf8(path) +
                            "' for reading: " + system_error_message());
  }
}

FileReader::~FileReader() {
  if (file_ != nullptr) {
    std::fclose(file_);
    file_ = nullptr;
  }
}

size_t FileReader::read(void* buffer, size_t length) {
  if (length == 0) {
    return 0;
  }
  const size_t got = std::fread(buffer, 1, length, file_);
  position_ += got;
  return got;
}

bool FileReader::read_exact(void* buffer, size_t length) {
  uint8_t* cursor = static_cast<uint8_t*>(buffer);
  size_t remaining = length;
  while (remaining > 0) {
    const size_t got = read(cursor, remaining);
    if (got == 0) {
      return false;
    }
    cursor += got;
    remaining -= got;
  }
  return true;
}

bool FileReader::has_more() {
  uint8_t byte = 0;
  const size_t got = read(&byte, 1);
  if (got == 0) {
    return false;
  }
  // Put the byte back by rewinding one byte; only used as a growth check.
  if (std::fseek(file_, -1, SEEK_CUR) != 0) {
    fail(ExitCode::kIo, "cannot rewind '" + fsutil::path_to_utf8(path_) + "'");
  }
  position_ -= 1;
  return true;
}

FileWriter::FileWriter(const fs::path& path, bool overwrite) : path_(path) {
  std::error_code ec;
  const fs::file_status status = fs::symlink_status(path, ec);
  if (!ec && fs::exists(status) && !overwrite) {
    fail(ExitCode::kIo, "refusing to overwrite '" + fsutil::path_to_utf8(path) +
                            "' (use --force)");
  }
  file_ = open_binary(path, L"wb", "wb");
  if (file_ == nullptr) {
    fail(ExitCode::kIo, "cannot open '" + fsutil::path_to_utf8(path) +
                            "' for writing: " + system_error_message());
  }
}

FileWriter::~FileWriter() {
  if (file_ != nullptr) {
    std::fclose(file_);
    file_ = nullptr;
  }
}

void FileWriter::write(const void* buffer, size_t length) {
  if (length == 0) {
    return;
  }
  const size_t written = std::fwrite(buffer, 1, length, file_);
  if (written != length) {
    fail(ExitCode::kIo, "cannot write to '" + fsutil::path_to_utf8(path_) +
                            "': " + system_error_message());
  }
  written_ += written;
}

void FileWriter::flush() {
  if (file_ == nullptr) {
    return;
  }
  if (std::fflush(file_) != 0) {
    fail(ExitCode::kIo, "cannot flush '" + fsutil::path_to_utf8(path_) +
                            "': " + system_error_message());
  }
}

void FileWriter::close() {
  if (closed_) {
    return;
  }
  closed_ = true;
  if (file_ == nullptr) {
    return;
  }
  std::FILE* file = file_;
  file_ = nullptr;
  if (std::fflush(file) != 0) {
    std::fclose(file);
    fail(ExitCode::kIo, "cannot flush '" + fsutil::path_to_utf8(path_) +
                            "': " + system_error_message());
  }
  if (std::fclose(file) != 0) {
    fail(ExitCode::kIo, "cannot close '" + fsutil::path_to_utf8(path_) +
                            "': " + system_error_message());
  }
}

}  // namespace aurora
