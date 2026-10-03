// One entry of an archive (or of the list of entries about to be written).
#pragma once

#include <cstdint>
#include <string>

#include "aurora.h"

namespace aurora {

enum class EntryType : uint8_t {
  kFile = 1,
  kDirectory = 2,
  kSymlink = 3,
};

struct Entry {
  EntryType type = EntryType::kFile;
  // Path inside the archive: relative, UTF-8, always separated by '/'.
  std::string path;
  // Source file on disk (writing side only).
  fs::path source;
  // Symlink target exactly as stored (reading and writing side).
  std::string link_target;
  // Payload length: file size in bytes, or the symlink target length.
  uint64_t size = 0;
  // Modification time in seconds since the Unix epoch; 0 means unknown.
  int64_t mtime = 0;
  // POSIX permission bits; 0 means unknown.
  uint32_t mode = 0;
};

inline const char* entry_type_name(EntryType type) {
  switch (type) {
    case EntryType::kFile:
      return "file";
    case EntryType::kDirectory:
      return "directory";
    case EntryType::kSymlink:
      return "symlink";
  }
  return "unknown";
}

}  // namespace aurora
