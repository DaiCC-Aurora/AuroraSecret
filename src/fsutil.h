// Filesystem helpers: UTF-8 paths, archive path safety, timestamps, modes.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "aurora.h"

namespace aurora::fsutil {

// Upper bound on a single archived path. Anything longer is rejected on both
// the writing and the reading side.
constexpr size_t kMaxArchivePathLength = 4096;
constexpr size_t kMaxPathComponentLength = 255;

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------
std::string path_to_utf8(const fs::path& path);
fs::path path_from_utf8(const std::string& text);
std::string wide_to_utf8(const std::wstring& text);
std::wstring utf8_to_wide(const std::string& text);

// Joins the components of a relative path with '/' (the archive separator,
// always used on every platform).
std::string archive_path_string(const fs::path& relative);
// Appends a single component to an archive path.
std::string archive_path_join(const std::string& base, const std::string& name);

// ---------------------------------------------------------------------------
// Safety
// ---------------------------------------------------------------------------

// Validates an archive path and throws aurora::Error(ExitCode::kCrypto) when it
// must not be extracted: absolute paths, drive letters, backslashes, "..", ".",
// empty components, embedded NUL bytes, and on Windows also reserved device
// names, illegal characters and trailing dots or spaces.
void validate_archive_path(const std::string& archive_path);
bool is_safe_archive_path(const std::string& archive_path);

// True when 'candidate' is 'base' itself or lives underneath it (both are
// compared component by component after lexical normalisation).
bool path_is_within(const fs::path& base, const fs::path& candidate);

// Makes 'path' absolute and lexically normalised without touching the file
// system, so that containment checks and error messages always have a usable
// path.
fs::path absolute_lexical(const fs::path& path);

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------
fs::file_time_type file_time_from_unix(int64_t unix_seconds);
int64_t unix_from_file_time(fs::file_time_type time);
// Permission bits (07777) of a file. Zero on platforms without POSIX modes.
uint32_t file_mode(const fs::path& path);
fs::perms perms_from_mode(uint32_t mode);

// Derives the top level name used inside the archive for an input path.
std::string top_level_name(const fs::path& input);

}  // namespace aurora::fsutil
