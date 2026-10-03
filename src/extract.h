// Extraction of a container into a destination directory.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "aurora.h"
#include "container.h"
#include "entry.h"

namespace aurora {

struct ExtractOptions {
  fs::path destination;
  bool overwrite = false;
  bool dry_run = false;
  bool preserve_times = true;
  bool preserve_permissions = true;
  // When false, the first recoverable I/O error aborts the extraction.
  bool continue_on_error = true;
  ProgressCallback progress;
};

struct ExtractStats {
  uint64_t entries = 0;
  uint64_t files = 0;
  uint64_t directories = 0;
  uint64_t symlinks = 0;
  uint64_t bytes = 0;
  std::vector<std::string> failures;
};

// Reads every entry of 'reader' and writes it below options.destination.
// Paths that would escape the destination, or that would be written through a
// symbolic link, abort the extraction (ExitCode::kCrypto).
ExtractStats extract_archive(ContainerReader& reader, const ExtractOptions& options);

}  // namespace aurora
