#include "walk.h"

#include <algorithm>
#include <set>
#include <system_error>
#include <utility>

#include "fsutil.h"
#include "log.h"
#include "util.h"

namespace aurora {
namespace {

// Hard limit on recursion depth; protects against pathological trees and
// against symlink loops that the visited set cannot see.
constexpr int kMaxRecursionDepth = 512;

struct WalkState {
  const WalkOptions* options = nullptr;
  std::vector<Entry>* entries = nullptr;
  std::set<std::string> visited_directories;
  size_t skipped = 0;
};

bool is_excluded(const std::string& archive_path, const WalkOptions& options) {
  if (options.exclude_patterns.empty()) {
    return false;
  }
  const size_t slash = archive_path.rfind('/');
  const std::string name =
      slash == std::string::npos ? archive_path : archive_path.substr(slash + 1);
  for (const std::string& pattern : options.exclude_patterns) {
    if (util::glob_match(pattern, archive_path) ||
        util::glob_match(pattern, name)) {
      return true;
    }
  }
  return false;
}

void skip(WalkState& state, const std::string& message) {
  log::warn(message);
  ++state.skipped;
}

// Modification time in Unix seconds, or 0 when it cannot be read.
int64_t unix_time_of(const fs::path& path) {
  std::error_code ec;
  const fs::file_time_type time = fs::last_write_time(path, ec);
  if (ec) {
    return 0;
  }
  return fsutil::unix_from_file_time(time);
}

void walk(WalkState& state, const fs::path& path, const std::string& archive_path,
          int depth) {
  const WalkOptions& options = *state.options;
  if (depth > kMaxRecursionDepth) {
    fail(ExitCode::kIo, "directory tree is too deep at '" +
                            fsutil::path_to_utf8(path) + "'");
  }

  std::error_code ec;
  const fs::file_status link_status = fs::symlink_status(path, ec);
  if (ec || !fs::exists(link_status)) {
    skip(state, "cannot inspect '" + fsutil::path_to_utf8(path) +
                    "': " + (ec ? ec.message() : std::string("not found")));
    return;
  }

  const bool is_link = fs::is_symlink(link_status);
  if (is_link && options.symlinks == SymlinkMode::kSkip) {
    log::verbose("skipping symbolic link " + archive_path);
    ++state.skipped;
    return;
  }

  fs::file_status status = link_status;
  if (is_link) {
    if (options.symlinks == SymlinkMode::kFollow) {
      status = fs::status(path, ec);
      if (ec) {
        skip(state, "cannot follow symbolic link '" + fsutil::path_to_utf8(path) +
                        "': " + ec.message());
        return;
      }
    } else {
      // Store the link itself.
      const fs::path target = fs::read_symlink(path, ec);
      if (ec) {
        skip(state, "cannot read symbolic link '" + fsutil::path_to_utf8(path) +
                        "': " + ec.message());
        return;
      }
      const std::string target_text = fsutil::path_to_utf8(target);
      if (target_text.find('\0') != std::string::npos ||
          target_text.size() > fsutil::kMaxArchivePathLength) {
        skip(state, "symbolic link target is unusable: " +
                        fsutil::path_to_utf8(path));
        return;
      }
      Entry link;
      link.type = EntryType::kSymlink;
      link.path = archive_path;
      link.source = path;
      link.link_target = target_text;
      link.size = target_text.size();
      link.mtime = unix_time_of(path);
      link.mode = fsutil::file_mode(path);
      state.entries->push_back(std::move(link));
      log::verbose("link     " + archive_path + " -> " + target_text);
      return;
    }
  }

  if (fs::is_directory(status)) {
    if (is_link) {
      const fs::path canonical = fs::canonical(path, ec);
      if (!ec) {
        const std::string key = fsutil::path_to_utf8(canonical);
        if (!state.visited_directories.insert(key).second) {
          skip(state, "skipping already visited directory '" +
                          fsutil::path_to_utf8(path) + "'");
          return;
        }
      }
    }
    Entry directory;
    directory.type = EntryType::kDirectory;
    directory.path = archive_path;
    directory.source = path;
    directory.mtime = unix_time_of(path);
    directory.mode = fsutil::file_mode(path);
    state.entries->push_back(std::move(directory));
    log::verbose("dir      " + archive_path + "/");

    if (options.max_depth > 0 && depth >= options.max_depth) {
      return;
    }

    std::vector<fs::path> children;
    fs::directory_iterator iterator(
        path, fs::directory_options::skip_permission_denied, ec);
    if (ec) {
      skip(state, "cannot list '" + fsutil::path_to_utf8(path) +
                      "': " + ec.message());
      return;
    }
    for (const fs::directory_entry& child : iterator) {
      children.push_back(child.path());
    }
    std::sort(children.begin(), children.end(),
              [](const fs::path& left, const fs::path& right) {
                return fsutil::path_to_utf8(left) < fsutil::path_to_utf8(right);
              });
    for (const fs::path& child : children) {
      const std::string name = fsutil::path_to_utf8(child.filename());
      if (!options.include_hidden && !name.empty() && name[0] == '.') {
        continue;
      }
      const std::string child_archive =
          fsutil::archive_path_join(archive_path, name);
      if (is_excluded(child_archive, options)) {
        log::verbose("excluded " + child_archive);
        continue;
      }
      walk(state, child, child_archive, depth + 1);
    }
    return;
  }

  if (fs::is_regular_file(status)) {
    const uint64_t size = fs::file_size(path, ec);
    if (ec) {
      skip(state, "cannot read file size of '" + fsutil::path_to_utf8(path) +
                      "': " + ec.message());
      return;
    }
    Entry file;
    file.type = EntryType::kFile;
    file.path = archive_path;
    file.source = path;
    file.size = size;
    file.mtime = unix_time_of(path);
    file.mode = fsutil::file_mode(path);
    state.entries->push_back(std::move(file));
    log::verbose("file     " + archive_path + " (" + util::format_size(size) + ")");
    return;
  }

  skip(state, "skipping unsupported file type: " + fsutil::path_to_utf8(path));
}

}  // namespace

std::vector<Entry> collect_entries(const std::vector<fs::path>& inputs,
                                   const WalkOptions& options) {
  WalkState state;
  state.options = &options;
  std::vector<Entry> entries;
  state.entries = &entries;

  if (inputs.empty()) {
    fail(ExitCode::kUsage, "no input was given");
  }

  for (const fs::path& input : inputs) {
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(input, ec);
    if (ec || !fs::exists(status)) {
      fail(ExitCode::kIo, "no such file or directory: " +
                              fsutil::path_to_utf8(input));
    }
    const std::string name = fsutil::top_level_name(input);
    fsutil::validate_archive_path(name);
    if (is_excluded(name, options)) {
      log::verbose("excluded " + name);
      continue;
    }
    walk(state, input, name, 1);
  }

  // Two inputs must never collide inside the archive: the result would be
  // ambiguous and extraction would overwrite one of them.
  std::vector<std::string> paths;
  paths.reserve(entries.size());
  for (const Entry& entry : entries) {
    paths.push_back(entry.path);
  }
  std::sort(paths.begin(), paths.end());
  const std::vector<std::string>::iterator duplicate =
      std::adjacent_find(paths.begin(), paths.end());
  if (duplicate != paths.end()) {
    fail(ExitCode::kUsage,
         "two inputs would map to the same archive path: '" + *duplicate +
             "' (encrypt them separately)");
  }

  if (state.skipped > 0) {
    log::warn(std::to_string(state.skipped) + " entries were skipped");
  }
  return entries;
}

}  // namespace aurora
