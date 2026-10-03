// Turns a list of input paths into a flat, ordered list of archive entries.
#pragma once

#include <string>
#include <vector>

#include "aurora.h"
#include "entry.h"

namespace aurora {

enum class SymlinkMode {
  kStore,  // archive the link itself (default)
  kFollow, // archive the content the link points at
  kSkip,   // ignore symbolic links
};

struct WalkOptions {
  SymlinkMode symlinks = SymlinkMode::kStore;
  std::vector<std::string> exclude_patterns;
  bool include_hidden = true;
  // 1 means "only the inputs themselves", 0 means unlimited.
  int max_depth = 0;
};

// Walks every input (files, directories and symbolic links) and returns the
// entries in the order they must be written: a directory always precedes its
// children. Throws on missing inputs, duplicate archive paths and I/O errors.
std::vector<Entry> collect_entries(const std::vector<fs::path>& inputs,
                                   const WalkOptions& options);

}  // namespace aurora
