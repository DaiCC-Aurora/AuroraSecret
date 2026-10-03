#include "extract.h"

#include <algorithm>
#include <memory>
#include <system_error>
#include <utility>

#include "crypto.h"
#include "fsutil.h"
#include "fileio.h"
#include "log.h"
#include "util.h"

namespace aurora {
namespace {

constexpr size_t kDrainBufferSize = 64 * 1024;

bool is_fatal(const Error& error) {
  return error.code() == ExitCode::kCrypto || error.code() == ExitCode::kUsage;
}

void remove_quietly(const fs::path& path) {
  std::error_code ec;
  fs::remove(path, ec);
}

// Removes the temporary file of a partially written entry, whatever happens.
class TempFileGuard {
 public:
  ~TempFileGuard() {
    if (armed_ && !path_.empty()) {
      remove_quietly(path_);
    }
  }
  void arm(const fs::path& path) {
    path_ = path;
    armed_ = true;
  }
  void release() { armed_ = false; }

 private:
  fs::path path_;
  bool armed_ = false;
};

// Validates the archive path, makes sure the target stays inside the
// destination, and creates (or checks) every parent directory while refusing to
// follow symbolic links: an archive must never be able to write outside its
// destination through a link it created itself.
fs::path prepare_target(const fs::path& destination,
                        const std::string& archive_path, bool dry_run) {
  fsutil::validate_archive_path(archive_path);
  const fs::path relative = fsutil::path_from_utf8(archive_path);
  const fs::path target = (destination / relative).lexically_normal();
  if (!fsutil::path_is_within(destination, target)) {
    fail(ExitCode::kCrypto, "refusing to extract '" + archive_path +
                                "' outside the destination directory");
  }

  const size_t component_count =
      static_cast<size_t>(std::distance(relative.begin(), relative.end()));
  fs::path current = destination;
  size_t index = 0;
  for (fs::path::const_iterator it = relative.begin(); it != relative.end();
       ++it, ++index) {
    current /= *it;
    if (index + 1 == component_count) {
      break;  // the leaf itself is created by the caller
    }
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(current, ec);
    if (!ec && fs::exists(status)) {
      if (fs::is_symlink(status)) {
        fail(ExitCode::kCrypto, "refusing to write through the symbolic link '" +
                                    fsutil::path_to_utf8(current) + "'");
      }
      if (!fs::is_directory(status)) {
        fail(ExitCode::kIo, "path component is not a directory: " +
                                fsutil::path_to_utf8(current));
      }
    } else if (!dry_run) {
      if (!fs::create_directory(current, ec) && ec) {
        fail(ExitCode::kIo, "cannot create directory '" +
                                fsutil::path_to_utf8(current) +
                                "': " + ec.message());
      }
    }
  }
  return target;
}

void apply_metadata(const fs::path& target, const Entry& entry,
                    const ExtractOptions& options) {
  if (options.dry_run || target.empty()) {
    return;
  }
  std::error_code ec;
  if (options.preserve_times && entry.mtime > 0) {
    fs::last_write_time(target, fsutil::file_time_from_unix(entry.mtime), ec);
    if (ec) {
      log::debug("cannot restore the modification time of '" +
                 fsutil::path_to_utf8(target) + "': " + ec.message());
    }
    ec.clear();
  }
  if (options.preserve_permissions && entry.mode != 0) {
#if defined(_WIN32)
    // Windows only knows the read only attribute; everything else is derived.
    fs::perms permissions = fs::perms::owner_read | fs::perms::group_read |
                            fs::perms::others_read;
    if ((entry.mode & 0200u) != 0) {
      permissions |= fs::perms::owner_write;
    }
    fs::permissions(target, permissions, fs::perm_options::replace, ec);
#else
    fs::permissions(target, fsutil::perms_from_mode(entry.mode),
                    fs::perm_options::replace, ec);
#endif
    if (ec) {
      log::debug("cannot restore the permissions of '" +
                 fsutil::path_to_utf8(target) + "': " + ec.message());
    }
  }
}

std::string temp_suffix() {
  uint8_t random[8] = {};
  crypto::random_bytes(random, sizeof(random));
  return ".aurorasecret-part-" + util::hex_encode(random, sizeof(random));
}

// Discards the remaining payload of the current entry so that the reader stays
// usable after a recoverable error.
void drain_current_entry(ContainerReader& reader) {
  uint8_t sink[kDrainBufferSize];
  while (reader.read_data(sink, sizeof(sink)) > 0) {
  }
}

void extract_file(ContainerReader& reader, const ExtractOptions& options,
                  const Entry& entry, ExtractStats& stats) {
  const fs::path target =
      prepare_target(options.destination, entry.path, options.dry_run);

  TempFileGuard guard;
  fs::path temporary;
  std::unique_ptr<FileWriter> writer;
  if (!options.dry_run) {
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(target, ec);
    if (!ec && fs::exists(status) && !options.overwrite) {
      fail(ExitCode::kIo, "refusing to overwrite '" +
                              fsutil::path_to_utf8(target) + "' (use --force)");
    }
    temporary = target;
    temporary += temp_suffix();
    guard.arm(temporary);
    writer = std::make_unique<FileWriter>(temporary, true);
  }

  uint64_t written = 0;
  uint8_t buffer[kDrainBufferSize];
  for (;;) {
    const size_t got = reader.read_data(buffer, sizeof(buffer));
    if (got == 0) {
      break;
    }
    written += got;
    stats.bytes += got;
    if (writer != nullptr) {
      writer->write(buffer, got);
    }
    if (options.progress) {
      options.progress(stats.bytes, 0, entry.path);
    }
  }
  if (writer != nullptr) {
    writer->close();
    writer.reset();
  }

  if (written != entry.size) {
    fail(ExitCode::kCrypto, "archive is corrupt: '" + entry.path +
                                "' does not match its declared size");
  }
  if (options.dry_run) {
    return;
  }

  std::error_code ec;
  if (options.overwrite) {
    fs::remove(target, ec);
    ec.clear();
  }
  fs::rename(temporary, target, ec);
  if (ec) {
    fail(ExitCode::kIo, "cannot move '" + fsutil::path_to_utf8(temporary) +
                            "' to '" + fsutil::path_to_utf8(target) +
                            "': " + ec.message());
  }
  guard.release();
  apply_metadata(target, entry, options);
}

void extract_directory(const ExtractOptions& options, const Entry& entry,
                       std::vector<Entry>& deferred_metadata) {
  const fs::path target =
      prepare_target(options.destination, entry.path, options.dry_run);
  if (!options.dry_run) {
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(target, ec);
    bool need_create = true;
    if (!ec && fs::exists(status)) {
      if (fs::is_directory(status) && !fs::is_symlink(status)) {
        need_create = false;
      } else if (!options.overwrite) {
        fail(ExitCode::kIo, "refusing to replace '" +
                                fsutil::path_to_utf8(target) +
                                "' with a directory (use --force)");
      } else {
        fs::remove_all(target, ec);
        ec.clear();
      }
    }
    if (need_create) {
      fs::create_directory(target, ec);
      if (ec) {
        fail(ExitCode::kIo, "cannot create directory '" +
                                fsutil::path_to_utf8(target) +
                                "': " + ec.message());
      }
    }
  }
  // Directory timestamps are restored at the very end, deepest directory first,
  // because writing children updates their parent.
  deferred_metadata.push_back(entry);
}

void extract_symlink(const ExtractOptions& options, const Entry& entry) {
  const fs::path target =
      prepare_target(options.destination, entry.path, options.dry_run);
  if (options.dry_run) {
    return;
  }
  std::error_code ec;
  const fs::file_status status = fs::symlink_status(target, ec);
  if (!ec && fs::exists(status)) {
    if (!options.overwrite) {
      fail(ExitCode::kIo, "refusing to overwrite '" +
                              fsutil::path_to_utf8(target) + "' (use --force)");
    }
    fs::remove_all(target, ec);
    ec.clear();
  }
  const fs::path link_target = fsutil::path_from_utf8(entry.link_target);
  fs::create_symlink(link_target, target, ec);
  if (ec) {
    fail(ExitCode::kIo,
         "cannot create the symbolic link '" + fsutil::path_to_utf8(target) +
             "': " + ec.message() +
             " (re-create the archive with --follow-symlinks to store the "
             "content instead)");
  }
  apply_metadata(target, entry, options);
}

size_t path_depth(const std::string& archive_path) {
  return static_cast<size_t>(
      std::count(archive_path.begin(), archive_path.end(), '/'));
}

}  // namespace

ExtractStats extract_archive(ContainerReader& reader,
                             const ExtractOptions& options) {
  ExtractStats stats;
  std::vector<Entry> deferred_metadata;

  Entry entry;
  while (reader.next_entry(entry)) {
    ++stats.entries;
    try {
      switch (entry.type) {
        case EntryType::kFile:
          extract_file(reader, options, entry, stats);
          ++stats.files;
          break;
        case EntryType::kDirectory:
          extract_directory(options, entry, deferred_metadata);
          ++stats.directories;
          break;
        case EntryType::kSymlink:
          extract_symlink(options, entry);
          ++stats.symlinks;
          break;
      }
    } catch (const Error& error) {
      if (is_fatal(error) || !options.continue_on_error) {
        throw;
      }
      // The entry failed halfway through: consume whatever is left of it so
      // that the next entry can still be read.
      drain_current_entry(reader);
      stats.failures.push_back(error.what());
      log::error(error.what());
    }
  }

  // Restore directory metadata deepest first so that parent timestamps survive.
  std::stable_sort(deferred_metadata.begin(), deferred_metadata.end(),
                   [](const Entry& left, const Entry& right) {
                     return path_depth(left.path) > path_depth(right.path);
                   });
  for (const Entry& directory : deferred_metadata) {
    const fs::path target =
        options.destination / fsutil::path_from_utf8(directory.path);
    apply_metadata(target, directory, options);
  }
  return stats;
}

}  // namespace aurora
