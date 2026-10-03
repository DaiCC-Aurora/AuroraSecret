// Self contained test suite: no external framework, no network access.
//
// Everything runs against the library (not the executable); the command line
// interface is exercised separately by tests/cli_roundtrip.cmake.
#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include "container.h"
#include "crypto.h"
#include "extract.h"
#include "fsutil.h"
#include "fileio.h"
#include "util.h"
#include "walk.h"

using namespace aurora;

namespace {

int g_checks = 0;
int g_failures = 0;

const KdfParams kFastKdf{16, 1};

struct TestFailure : std::runtime_error {
  explicit TestFailure(const std::string& message)
      : std::runtime_error(message) {}
};

std::string location(const char* file, int line) {
  return std::string(file) + ":" + std::to_string(line);
}

#define REQUIRE(condition)                                        \
  do {                                                            \
    ++g_checks;                                                   \
    if (!(condition)) {                                           \
      throw TestFailure(location(__FILE__, __LINE__) +            \
                        ": REQUIRE failed: " #condition);         \
    }                                                             \
  } while (false)

#define CHECK(condition)                                          \
  do {                                                            \
    ++g_checks;                                                   \
    if (!(condition)) {                                           \
      ++g_failures;                                               \
      std::fprintf(stderr, "  CHECK failed at %s: %s\n",          \
                   location(__FILE__, __LINE__).c_str(),          \
                   #condition);                                   \
    }                                                             \
  } while (false)

#define CHECK_THROWS(expression)                                   \
  do {                                                             \
    bool threw = false;                                            \
    try {                                                          \
      (void)(expression);                                          \
    } catch (const aurora::Error&) {                               \
      threw = true;                                                \
    }                                                              \
    ++g_checks;                                                    \
    if (!threw) {                                                  \
      ++g_failures;                                                \
      std::fprintf(stderr, "  CHECK_THROWS failed at %s: %s\n",    \
                   location(__FILE__, __LINE__).c_str(),           \
                   #expression);                                   \
    }                                                              \
  } while (false)

class TempDir {
 public:
  TempDir() {
    std::error_code ec;
    fs::path base = fs::temp_directory_path(ec);
    if (ec) {
      base = fs::current_path(ec);
    }
    static int counter = 0;
    for (int attempt = 0; attempt < 200; ++attempt) {
      const std::string name =
          "aurorasecret-test-" + std::to_string(util::now_unix_seconds()) + "-" +
          std::to_string(++counter) + "-" + std::to_string(attempt);
      const fs::path candidate = base / name;
      if (fs::create_directory(candidate, ec)) {
        path_ = candidate;
        return;
      }
      ec.clear();
    }
    throw TestFailure("cannot create a temporary directory");
  }

  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
  }

  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  const fs::path& path() const { return path_; }
  fs::path operator/(const std::string& name) const { return path_ / name; }

 private:
  fs::path path_;
};

void write_file(const fs::path& path, const std::string& content) {
  std::error_code ec;
  if (path.has_parent_path()) {
    fs::create_directories(path.parent_path(), ec);
  }
  FileWriter writer(path, true);
  if (!content.empty()) {
    writer.write(content.data(), content.size());
  }
  writer.close();
}

std::string read_file(const fs::path& path) {
  FileReader reader(path);
  std::string content;
  char buffer[8192];
  for (;;) {
    const size_t got = reader.read(buffer, sizeof(buffer));
    if (got == 0) {
      break;
    }
    content.append(buffer, got);
  }
  return content;
}

std::string pseudo_random_bytes(size_t length) {
  std::string out;
  out.reserve(length);
  uint32_t state = 0x12345678u;
  for (size_t i = 0; i < length; ++i) {
    state = state * 1664525u + 1013904223u;
    out.push_back(static_cast<char>((state >> 16) & 0xFFu));
  }
  return out;
}

void collect_files(const fs::path& root, const fs::path& current,
                   std::vector<std::string>& out) {
  std::error_code ec;
  std::vector<fs::path> children;
  fs::directory_iterator iterator(current, ec);
  if (ec) {
    return;
  }
  for (const fs::directory_entry& child : iterator) {
    children.push_back(child.path());
  }
  std::sort(children.begin(), children.end());
  for (const fs::path& child : children) {
    const fs::file_status status = fs::symlink_status(child, ec);
    if (!ec && fs::is_directory(status) && !fs::is_symlink(status)) {
      collect_files(root, child, out);
    } else if (!ec) {
      out.push_back(
          fsutil::archive_path_string(fs::relative(child, root, ec)));
    }
  }
}

std::vector<std::string> list_files(const fs::path& root) {
  std::vector<std::string> out;
  collect_files(root, root, out);
  std::sort(out.begin(), out.end());
  return out;
}

void create_sample_tree(const fs::path& root) {
  write_file(root / "hello.txt", "hello world\n");
  write_file(root / "empty.bin", "");
  write_file(root / "sub" / "big.bin", pseudo_random_bytes(3 * 1024 * 1024 + 1234));
  // path_from_utf8 so the file really is called that on Windows too: an
  // fs::path built from a narrow literal uses the ANSI code page there.
  write_file(root / "sub" /
                 fsutil::path_from_utf8("unicode-\xE6\x97\xA5\xE6\x9C\xAC\xE8\xAA\x9E.txt"),
             "unicode payload\n");
  std::error_code ec;
  fs::create_directories(root / "emptydir", ec);
}

void compare_trees(const fs::path& left, const fs::path& right) {
  const std::vector<std::string> left_files = list_files(left);
  const std::vector<std::string> right_files = list_files(right);
  REQUIRE(left_files == right_files);
  for (const std::string& relative : left_files) {
    const fs::path left_file = left / fsutil::path_from_utf8(relative);
    const fs::path right_file = right / fsutil::path_from_utf8(relative);
    if (read_file(left_file) != read_file(right_file)) {
      throw TestFailure("file content differs: " + relative);
    }
    ++g_checks;
  }
  REQUIRE(!left_files.empty());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void test_random_and_wipe() {
  uint8_t first[32] = {};
  uint8_t second[32] = {};
  crypto::random_bytes(first, sizeof(first));
  crypto::random_bytes(second, sizeof(second));
  CHECK(std::memcmp(first, second, sizeof(first)) != 0);
  crypto::wipe(first, sizeof(first));
  for (size_t i = 0; i < sizeof(first); ++i) {
    CHECK(first[i] == 0);
  }
  const crypto::Salt salt_a = crypto::random_salt();
  const crypto::Salt salt_b = crypto::random_salt();
  CHECK(std::memcmp(salt_a.data(), salt_b.data(), salt_a.size()) != 0);
}

void test_key_derivation() {
  const crypto::Salt salt = crypto::random_salt();
  const crypto::Key key = crypto::derive_key("correct horse", salt,
                                             kFastKdf.blocks, kFastKdf.passes);
  CHECK(key == crypto::derive_key("correct horse", salt, kFastKdf.blocks,
                                  kFastKdf.passes));
  CHECK(key != crypto::derive_key("Correct horse", salt, kFastKdf.blocks,
                                  kFastKdf.passes));
  const crypto::Salt other_salt = crypto::random_salt();
  CHECK(key != crypto::derive_key("correct horse", other_salt,
                                  kFastKdf.blocks, kFastKdf.passes));
  CHECK(key != crypto::derive_key("correct horse", salt, kFastKdf.blocks + 8,
                                  kFastKdf.passes));

  const std::vector<uint8_t> key_file = {'s', 'e', 'c', 'r', 'e', 't'};
  const crypto::Key combined = crypto::combine_keyfile(key, key_file);
  CHECK(combined != key);
  CHECK(combined == crypto::combine_keyfile(key, key_file));
  const std::vector<uint8_t> other_key_file = {'s', 'e', 'c', 'r', 'e', 'u'};
  CHECK(combined != crypto::combine_keyfile(key, other_key_file));
}

void test_blake2b_and_nonces() {
  const uint8_t message[] = {1, 2, 3, 4, 5};
  uint8_t digest_a[32] = {};
  uint8_t digest_b[32] = {};
  crypto::blake2b(digest_a, sizeof(digest_a), message, sizeof(message));
  crypto::blake2b(digest_b, sizeof(digest_b), message, sizeof(message));
  CHECK(std::memcmp(digest_a, digest_b, sizeof(digest_a)) == 0);
  const uint8_t other_message[] = {1, 2, 3, 4, 6};
  crypto::blake2b(digest_b, sizeof(digest_b), other_message,
                  sizeof(other_message));
  CHECK(std::memcmp(digest_a, digest_b, sizeof(digest_a)) != 0);

  const crypto::Nonce nonce_a = crypto::frame_nonce(1, 1);
  const crypto::Nonce nonce_b = crypto::frame_nonce(1, 2);
  const crypto::Nonce nonce_c = crypto::frame_nonce(2, 1);
  CHECK(std::memcmp(nonce_a.data(), nonce_b.data(), nonce_a.size()) != 0);
  CHECK(std::memcmp(nonce_a.data(), nonce_c.data(), nonce_a.size()) != 0);
  CHECK(nonce_a == crypto::frame_nonce(1, 1));
}

void test_aead_roundtrip() {
  const crypto::Key key =
      crypto::derive_key("pw", crypto::random_salt(), kFastKdf.blocks,
                         kFastKdf.passes);
  const crypto::Nonce nonce = crypto::frame_nonce(3, 7);
  const std::string message = "AuroraSecret authenticates everything it writes";
  const std::string associated = "associated";

  std::vector<uint8_t> cipher(message.size());
  crypto::Mac mac{};
  crypto::aead_lock(cipher.data(), mac, key, nonce, associated.data(),
                    associated.size(), message.data(), message.size());
  CHECK(std::memcmp(cipher.data(), message.data(), message.size()) != 0);

  std::vector<uint8_t> plain(message.size());
  REQUIRE(crypto::aead_unlock(plain.data(), mac, key, nonce, associated.data(),
                              associated.size(), cipher.data(), cipher.size()));
  CHECK(std::memcmp(plain.data(), message.data(), message.size()) == 0);

  cipher[0] = static_cast<uint8_t>(cipher[0] ^ 0x01);
  CHECK(!crypto::aead_unlock(plain.data(), mac, key, nonce, associated.data(),
                             associated.size(), cipher.data(), cipher.size()));
  cipher[0] = static_cast<uint8_t>(cipher[0] ^ 0x01);

  const std::string other_associated = "associated!";
  CHECK(!crypto::aead_unlock(plain.data(), mac, key, nonce,
                             other_associated.data(), other_associated.size(),
                             cipher.data(), cipher.size()));
  CHECK(!crypto::aead_unlock(plain.data(), mac, key, crypto::frame_nonce(3, 8),
                             associated.data(), associated.size(),
                             cipher.data(), cipher.size()));
}

void test_archive_path_validation() {
  CHECK(fsutil::is_safe_archive_path("file.txt"));
  CHECK(fsutil::is_safe_archive_path("a/b/c.txt"));
  CHECK(fsutil::is_safe_archive_path("dir with spaces/\xE6\x97\xA5.txt"));
  CHECK(!fsutil::is_safe_archive_path(""));
  CHECK(!fsutil::is_safe_archive_path("../escape.txt"));
  CHECK(!fsutil::is_safe_archive_path("a/../../escape.txt"));
  CHECK(!fsutil::is_safe_archive_path("./a"));
  CHECK(!fsutil::is_safe_archive_path("a/./b"));
  CHECK(!fsutil::is_safe_archive_path("/absolute"));
  CHECK(!fsutil::is_safe_archive_path("C:/windows"));
  CHECK(!fsutil::is_safe_archive_path("a\\b"));
  CHECK(!fsutil::is_safe_archive_path("a//b"));
  CHECK(!fsutil::is_safe_archive_path("a/"));

  CHECK(util::glob_match("*.log", "server.log"));
  CHECK(!util::glob_match("*.log", "server.txt"));
  CHECK(util::glob_match("build/*", "build/output.txt"));
  CHECK(util::glob_match("a?c", "abc"));
  CHECK(util::glob_match("**", "anything/at/all"));
  CHECK(util::glob_match("*", ""));
  CHECK(util::glob_match("*ab", "aab"));
  CHECK(util::glob_match("a*b*c", "axxbyyc"));
  CHECK(!util::glob_match("a*b*c", "axxbyy"));
  CHECK(util::glob_match("*report*", "2026-report-final.pdf"));
}

void test_container_roundtrip() {
  TempDir temp;
  const fs::path source = temp / "tree";
  const fs::path archive = temp / "archive.asf";
  const fs::path restored = temp / "restored";
  create_sample_tree(source);

  std::vector<fs::path> inputs{source};
  WalkOptions walk_options;
  const std::vector<Entry> entries = collect_entries(inputs, walk_options);
  REQUIRE(!entries.empty());

  WriterOptions writer_options;
  writer_options.kdf = kFastKdf;
  {
    uint64_t expected_total = 0;
    for (const Entry& entry : entries) {
      if (entry.type == EntryType::kFile) {
        expected_total += entry.size;
      }
    }
    uint64_t reported_total = 0;
    ContainerWriter writer(archive, "hunter2", writer_options);
    CHECK(writer.header().argon_blocks == kFastKdf.blocks);
    CHECK(writer.header().argon_passes == kFastKdf.passes);
    CHECK(!writer.header().uses_key_file());
    writer.write_entries(entries,
                         [&reported_total](uint64_t, uint64_t total,
                                           const std::string&) {
                           reported_total = total;
                         });
    CHECK(reported_total == expected_total);
    CHECK(writer.bytes_written() > expected_total);
  }
  REQUIRE(fs::exists(archive));

  {
    ContainerReader reader(archive, "hunter2");
    ExtractOptions options;
    options.destination = fsutil::absolute_lexical(restored);
    const ExtractStats stats = extract_archive(reader, options);
    reader.finish();
    CHECK(stats.failures.empty());
    CHECK(stats.entries == entries.size());
    CHECK(stats.files == 4);
    CHECK(stats.directories == 3);  // tree, tree/sub, tree/emptydir
  }

  compare_trees(source, restored / "tree");
  CHECK(fs::is_directory(restored / "tree" / "emptydir"));

  // Modification times must survive the round trip (within a second or two).
  std::error_code ec;
  const fs::file_time_type original =
      fs::last_write_time(source / "hello.txt", ec);
  REQUIRE(!ec);
  const int64_t original_seconds = fsutil::unix_from_file_time(original);
  const int64_t restored_seconds = fsutil::unix_from_file_time(
      fs::last_write_time(restored / "tree" / "hello.txt", ec));
  REQUIRE(!ec);
  CHECK(std::abs(original_seconds - restored_seconds) <= 2);
}

void test_list_entries() {
  TempDir temp;
  const fs::path source = temp / "tree";
  const fs::path archive = temp / "archive.asf";
  create_sample_tree(source);

  WriterOptions writer_options;
  writer_options.kdf = kFastKdf;
  const std::vector<Entry> entries =
      collect_entries({source}, WalkOptions());
  {
    ContainerWriter writer(archive, "pw", writer_options);
    writer.write_entries(entries);
  }

  ContainerReader reader(archive, "pw");
  std::vector<std::string> listed;
  Entry entry;
  while (reader.next_entry(entry)) {
    uint8_t sink[64 * 1024];
    while (reader.read_data(sink, sizeof(sink)) > 0) {
    }
    listed.push_back(std::string(entry_type_name(entry.type)) + " " + entry.path);
  }
  reader.finish();
  REQUIRE(listed.size() == entries.size());
  CHECK(listed.front() == "directory tree");
  CHECK(std::find(listed.begin(), listed.end(), "file tree/hello.txt") !=
        listed.end());
  CHECK(std::find(listed.begin(), listed.end(),
                  "file tree/sub/unicode-\xE6\x97\xA5\xE6\x9C\xAC\xE8\xAA\x9E.txt") !=
        listed.end());
}

void test_wrong_password_and_damage() {
  TempDir temp;
  const fs::path source = temp / "tree";
  const fs::path archive = temp / "archive.asf";
  create_sample_tree(source);
  const std::vector<Entry> entries =
      collect_entries({source}, WalkOptions());
  WriterOptions writer_options;
  writer_options.kdf = kFastKdf;
  {
    ContainerWriter writer(archive, "right", writer_options);
    writer.write_entries(entries);
  }

  CHECK_THROWS(ContainerReader(archive, "wrong"));
  CHECK_THROWS(ContainerReader(archive, "righ"));

  const std::string original = read_file(archive);

  // Flipping a byte inside the payload must break authentication.
  {
    std::string damaged = original;
    damaged[damaged.size() - 20] =
        static_cast<char>(damaged[damaged.size() - 20] ^ 0x01);
    const fs::path damaged_path = temp / "damaged.asf";
    write_file(damaged_path, damaged);
    ContainerReader reader(damaged_path, "right");
    Entry entry;
    bool threw = false;
    try {
      while (reader.next_entry(entry)) {
        uint8_t sink[64 * 1024];
        while (reader.read_data(sink, sizeof(sink)) > 0) {
        }
      }
    } catch (const Error& error) {
      threw = error.code() == ExitCode::kCrypto;
    }
    CHECK(threw);
  }

  // Flipping a byte inside the header must break authentication as well.
  {
    std::string damaged = original;
    damaged[20] = static_cast<char>(damaged[20] ^ 0x01);
    const fs::path damaged_path = temp / "damaged-header.asf";
    write_file(damaged_path, damaged);
    CHECK_THROWS(ContainerReader(damaged_path, "right"));
  }

  // A truncated archive must be rejected.
  {
    const fs::path truncated_path = temp / "truncated.asf";
    write_file(truncated_path, original.substr(0, original.size() / 2));
    bool threw = false;
    try {
      ContainerReader reader(truncated_path, "right");
      Entry entry;
      while (reader.next_entry(entry)) {
        uint8_t sink[64 * 1024];
        while (reader.read_data(sink, sizeof(sink)) > 0) {
        }
      }
    } catch (const Error& error) {
      threw = error.code() == ExitCode::kCrypto;
    }
    CHECK(threw);
  }

  // Trailing data after the end marker must be rejected.
  {
    const fs::path padded_path = temp / "padded.asf";
    write_file(padded_path, original + "extra");
    bool threw = false;
    try {
      ContainerReader reader(padded_path, "right");
      Entry entry;
      while (reader.next_entry(entry)) {
        uint8_t sink[64 * 1024];
        while (reader.read_data(sink, sizeof(sink)) > 0) {
        }
      }
    } catch (const Error& error) {
      threw = error.code() == ExitCode::kCrypto;
    }
    CHECK(threw);
  }
}

void test_key_file() {
  TempDir temp;
  const fs::path source = temp / "file.txt";
  const fs::path archive = temp / "archive.asf";
  write_file(source, "payload");
  const std::vector<Entry> entries = collect_entries({source}, WalkOptions());

  const std::vector<uint8_t> key_file = {'k', 'e', 'y'};
  WriterOptions writer_options;
  writer_options.kdf = kFastKdf;
  writer_options.key_file = key_file;
  {
    ContainerWriter writer(archive, "pw", writer_options);
    writer.write_entries(entries);
  }

  {
    ContainerReader reader(archive, "pw", key_file);
    CHECK(reader.header().uses_key_file());
    ExtractOptions options;
    options.destination = fsutil::absolute_lexical(temp / "restored");
    const ExtractStats stats = extract_archive(reader, options);
    reader.finish();
    CHECK(stats.failures.empty());
  }
  CHECK(read_file(temp / "restored" / "file.txt") == "payload");

  const std::vector<uint8_t> wrong_key_file = {'k', 'e', 'z'};
  CHECK_THROWS(ContainerReader(archive, "pw", wrong_key_file));
  CHECK_THROWS(ContainerReader(archive, "pw"));
}

void test_overwrite_protection() {
  TempDir temp;
  const fs::path source = temp / "file.txt";
  const fs::path archive = temp / "archive.asf";
  write_file(source, "first");
  const std::vector<Entry> entries = collect_entries({source}, WalkOptions());

  WriterOptions writer_options;
  writer_options.kdf = kFastKdf;
  {
    ContainerWriter writer(archive, "pw", writer_options);
    writer.write_entries(entries);
  }
  // A second encryption must not silently replace the archive.
  CHECK_THROWS(
      ContainerWriter(archive, "pw", writer_options).write_entries(entries));

  writer_options.overwrite = true;
  {
    ContainerWriter writer(archive, "pw", writer_options);
    writer.write_entries(entries);
  }

  // Extraction must not overwrite existing files unless asked to.
  ExtractOptions options;
  options.destination = fsutil::absolute_lexical(temp / "out");
  {
    ContainerReader reader(archive, "pw");
    const ExtractStats stats = extract_archive(reader, options);
    reader.finish();
    CHECK(stats.failures.empty());
  }
  write_file(temp / "out" / "file.txt", "local change");
  {
    ContainerReader reader(archive, "pw");
    const ExtractStats stats = extract_archive(reader, options);
    reader.finish();
    CHECK(!stats.failures.empty());
  }
  CHECK(read_file(temp / "out" / "file.txt") == "local change");

  options.overwrite = true;
  {
    ContainerReader reader(archive, "pw");
    const ExtractStats stats = extract_archive(reader, options);
    reader.finish();
    CHECK(stats.failures.empty());
  }
  CHECK(read_file(temp / "out" / "file.txt") == "first");

  // A failed run must never leave a half written archive behind.
  const fs::path rejected = temp / "rejected.asf";
  const std::vector<Entry> missing = collect_entries({source}, WalkOptions());
  WriterOptions failing;
  failing.kdf = kFastKdf;
  {
    ContainerWriter writer(rejected, "pw", failing);
    std::vector<Entry> broken = missing;
    broken[0].source = temp / "does-not-exist.txt";
    CHECK_THROWS(writer.write_entries(broken));
  }
  CHECK(!fs::exists(rejected));
}

void test_unsafe_paths_are_rejected() {
  TempDir temp;
  const fs::path payload = temp / "payload.txt";
  write_file(payload, "payload");

  const char* unsafe_paths[] = {"../escape.txt", "/etc/passwd", "a/../../b",
                                "a\\b", "C:/windows/system32"};
  for (const char* unsafe : unsafe_paths) {
    const fs::path archive = temp / ("evil-" + std::to_string(std::strlen(unsafe)) + ".asf");
    WriterOptions writer_options;
    writer_options.kdf = kFastKdf;
    // Only the test suite forges archives with unusable paths.
    writer_options.allow_unsafe_paths = true;
    {
      ContainerWriter writer(archive, "pw", writer_options);
      Entry entry;
      entry.type = EntryType::kFile;
      entry.path = unsafe;
      entry.source = payload;
      entry.size = 7;
      writer.write_entries(std::vector<Entry>{entry});
    }
    ContainerReader reader(archive, "pw");
    Entry entry;
    bool threw = false;
    try {
      (void)reader.next_entry(entry);
    } catch (const Error& error) {
      threw = error.code() == ExitCode::kCrypto;
    }
    CHECK(threw);
    CHECK(!fs::exists(temp / "escape.txt"));
  }

  // The writing side refuses unsafe paths by default.
  const fs::path archive = temp / "safe-writer.asf";
  WriterOptions writer_options;
  writer_options.kdf = kFastKdf;
  CHECK_THROWS([&] {
    ContainerWriter writer(archive, "pw", writer_options);
    Entry entry;
    entry.type = EntryType::kFile;
    entry.path = "../escape.txt";
    entry.source = payload;
    writer.write_entries(std::vector<Entry>{entry});
  }());
  CHECK(!fs::exists(archive));
}

void test_no_write_through_symlink() {
  TempDir temp;
  const fs::path payload = temp / "payload.txt";
  const fs::path archive = temp / "archive.asf";
  write_file(payload, "payload");

  WriterOptions writer_options;
  writer_options.kdf = kFastKdf;
  {
    ContainerWriter writer(archive, "pw", writer_options);
    Entry entry;
    entry.type = EntryType::kFile;
    entry.path = "link/payload.txt";
    entry.source = payload;
    entry.size = 7;
    writer.write_entries(std::vector<Entry>{entry});
  }

  const fs::path destination = temp / "out";
  const fs::path outside = temp / "outside";
  std::error_code ec;
  fs::create_directories(destination, ec);
  fs::create_directories(outside, ec);
  fs::create_symlink(outside, destination / "link", ec);
  if (ec) {
    std::printf("  (symbolic links unavailable here, sub test skipped)\n");
    return;
  }

  ContainerReader reader(archive, "pw");
  ExtractOptions options;
  options.destination = fsutil::absolute_lexical(destination);
  bool threw = false;
  try {
    extract_archive(reader, options);
  } catch (const Error& error) {
    threw = error.code() == ExitCode::kCrypto;
  }
  CHECK(threw);
  CHECK(!fs::exists(outside / "payload.txt"));
}

void test_symlink_roundtrip() {
  TempDir temp;
  const fs::path source = temp / "tree";
  const fs::path archive = temp / "archive.asf";
  std::error_code ec;
  fs::create_directories(source, ec);
  write_file(source / "target.txt", "target payload");
  fs::create_symlink("target.txt", source / "link.txt", ec);
  if (ec) {
    std::printf("  (symbolic links unavailable here, test skipped)\n");
    return;
  }

  const std::vector<Entry> entries = collect_entries({source}, WalkOptions());
  bool found_link = false;
  for (const Entry& entry : entries) {
    if (entry.type == EntryType::kSymlink) {
      found_link = true;
      CHECK(entry.link_target == "target.txt");
    }
  }
  CHECK(found_link);

  WriterOptions writer_options;
  writer_options.kdf = kFastKdf;
  {
    ContainerWriter writer(archive, "pw", writer_options);
    writer.write_entries(entries);
  }

  ExtractOptions options;
  options.destination = fsutil::absolute_lexical(temp / "restored");
  ContainerReader reader(archive, "pw");
  const ExtractStats stats = extract_archive(reader, options);
  reader.finish();
  CHECK(stats.failures.empty());
  CHECK(stats.symlinks == 1);
  CHECK(fs::is_symlink(options.destination / "tree" / "link.txt"));
  CHECK(read_file(options.destination / "tree" / "target.txt") == "target payload");

  // --follow-symlinks stores the content instead of the link.
  WalkOptions follow_options;
  follow_options.symlinks = SymlinkMode::kFollow;
  const std::vector<Entry> followed = collect_entries({source}, follow_options);
  for (const Entry& entry : followed) {
    CHECK(entry.type != EntryType::kSymlink);
  }
}

void test_excludes_and_duplicates() {
  TempDir temp;
  const fs::path source = temp / "tree";
  write_file(source / "keep.txt", "keep");
  write_file(source / "drop.log", "drop");
  write_file(source / "sub" / "nested.log", "nested");

  WalkOptions walk_options;
  walk_options.exclude_patterns.push_back("*.log");
  const std::vector<Entry> entries = collect_entries({source}, walk_options);
  REQUIRE(!entries.empty());
  for (const Entry& entry : entries) {
    CHECK(entry.path.find(".log") == std::string::npos);
  }

  // Two inputs that would collide inside the archive must be refused.
  CHECK_THROWS(collect_entries({source, source}, WalkOptions()));
}

void test_empty_file_handling() {
  TempDir temp;
  const fs::path source = temp / "empty.bin";
  const fs::path archive = temp / "archive.asf";
  write_file(source, "");

  const std::vector<Entry> entries = collect_entries({source}, WalkOptions());
  REQUIRE(entries.size() == 1);
  CHECK(entries[0].size == 0);

  WriterOptions writer_options;
  writer_options.kdf = kFastKdf;
  {
    ContainerWriter writer(archive, "pw", writer_options);
    writer.write_entries(entries);
  }

  ExtractOptions options;
  options.destination = fsutil::absolute_lexical(temp / "out");
  ContainerReader reader(archive, "pw");
  const ExtractStats stats = extract_archive(reader, options);
  reader.finish();
  CHECK(stats.failures.empty());
  CHECK(fs::exists(temp / "out" / "empty.bin"));
  CHECK(read_file(temp / "out" / "empty.bin").empty());

  // Missing inputs must be reported, not silently ignored.
  CHECK_THROWS(collect_entries({temp / "missing.txt"}, WalkOptions()));
}

void test_multichunk_file() {
  TempDir temp;
  const fs::path source = temp / "chunked.bin";
  const fs::path archive = temp / "archive.asf";
  // Exactly two full chunks plus one byte: exercises the final short frame.
  const std::string content = pseudo_random_bytes(2 * format::kChunkSize + 1);
  write_file(source, content);

  const std::vector<Entry> entries = collect_entries({source}, WalkOptions());
  WriterOptions writer_options;
  writer_options.kdf = kFastKdf;
  {
    ContainerWriter writer(archive, "pw", writer_options);
    writer.write_entries(entries);
  }

  ExtractOptions options;
  options.destination = fsutil::absolute_lexical(temp / "out");
  ContainerReader reader(archive, "pw");
  const ExtractStats stats = extract_archive(reader, options);
  reader.finish();
  CHECK(stats.failures.empty());
  CHECK(stats.bytes == content.size());
  CHECK(read_file(temp / "out" / "chunked.bin") == content);
}

void test_dry_run_writes_nothing() {
  TempDir temp;
  const fs::path source = temp / "tree";
  create_sample_tree(source);
  const fs::path archive = temp / "archive.asf";
  WriterOptions writer_options;
  writer_options.kdf = kFastKdf;
  {
    ContainerWriter writer(archive, "pw", writer_options);
    writer.write_entries(collect_entries({source}, WalkOptions()));
  }

  ExtractOptions options;
  options.destination = fsutil::absolute_lexical(temp / "out");
  options.dry_run = true;
  ContainerReader reader(archive, "pw");
  const ExtractStats stats = extract_archive(reader, options);
  reader.finish();
  CHECK(stats.failures.empty());
  CHECK(stats.entries > 0);
  CHECK(!fs::exists(temp / "out"));
}

void test_file_time_conversion() {
  const int64_t known = 1700000000;
  const int64_t round_trip =
      fsutil::unix_from_file_time(fsutil::file_time_from_unix(known));
  CHECK(std::abs(round_trip - known) <= 2);
  CHECK(util::format_size(0) == "0 B");
  CHECK(util::format_size(1536) == "1.5 KiB");
  CHECK(util::format_time(0) == "-");
  CHECK(!util::format_time(1700000000).empty());
}

void run(const char* name, void (*test)()) {
  std::printf("[ RUN      ] %s\n", name);
  const int failures_before = g_failures;
  try {
    test();
  } catch (const TestFailure& failure) {
    ++g_failures;
    std::fprintf(stderr, "  FAILED: %s\n", failure.what());
    return;
  } catch (const std::exception& error) {
    ++g_failures;
    std::fprintf(stderr, "  FAILED: unexpected exception: %s\n", error.what());
    return;
  }
  if (g_failures == failures_before) {
    std::printf("[       OK ] %s\n", name);
  }
}

}  // namespace

int main() {
  std::printf("AuroraSecret test suite\n");

  run("random and wipe", test_random_and_wipe);
  run("key derivation", test_key_derivation);
  run("blake2b and nonces", test_blake2b_and_nonces);
  run("aead round trip", test_aead_roundtrip);
  run("archive path validation", test_archive_path_validation);
  run("container round trip", test_container_roundtrip);
  run("list entries", test_list_entries);
  run("wrong password and damage", test_wrong_password_and_damage);
  run("key file", test_key_file);
  run("overwrite protection", test_overwrite_protection);
  run("unsafe paths are rejected", test_unsafe_paths_are_rejected);
  run("no write through symlink", test_no_write_through_symlink);
  run("symlink round trip", test_symlink_roundtrip);
  run("excludes", test_excludes_and_duplicates);
  run("empty files", test_empty_file_handling);
  run("multi chunk file", test_multichunk_file);
  run("dry run", test_dry_run_writes_nothing);
  run("file time conversion", test_file_time_conversion);

  std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
