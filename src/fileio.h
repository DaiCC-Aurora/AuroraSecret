// Buffered binary file I/O with precise error reporting.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

#include "aurora.h"

namespace aurora {

class FileReader {
 public:
  explicit FileReader(const fs::path& path);
  ~FileReader();

  FileReader(const FileReader&) = delete;
  FileReader& operator=(const FileReader&) = delete;

  // Returns the number of bytes read; 0 means end of file. Short reads are
  // possible, callers that need a fixed amount use read_exact().
  size_t read(void* buffer, size_t length);
  // Returns false when the file ends before 'length' bytes were read.
  bool read_exact(void* buffer, size_t length);
  bool has_more();
  uint64_t position() const { return position_; }
  const fs::path& path() const { return path_; }

 private:
  fs::path path_;
  std::FILE* file_ = nullptr;
  uint64_t position_ = 0;
};

class FileWriter {
 public:
  // Opens (and truncates) 'path'. Refuses to replace an existing file unless
  // 'overwrite' is true, so that accidental data loss stays impossible.
  FileWriter(const fs::path& path, bool overwrite);
  ~FileWriter();

  FileWriter(const FileWriter&) = delete;
  FileWriter& operator=(const FileWriter&) = delete;

  void write(const void* buffer, size_t length);
  void flush();
  void close();
  uint64_t tell() const { return written_; }
  const fs::path& path() const { return path_; }

 private:
  fs::path path_;
  std::FILE* file_ = nullptr;
  uint64_t written_ = 0;
  bool closed_ = false;
};

}  // namespace aurora
