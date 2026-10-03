// The AuroraSecret container format (.asf).
//
// Layout (all integers little endian):
//
//   header   64 bytes, see docs/FORMAT.md
//   frames   repeated until the end marker
//
// Every frame is independently authenticated with XChaCha20-Poly1305; the
// associated data binds the magic and the frame type, the nonce binds the
// entry and the chunk index. Truncation, reordering, duplication and edits are
// therefore all detected.
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "aurora.h"
#include "crypto.h"
#include "entry.h"
#include "fileio.h"

namespace aurora {

namespace format {

inline constexpr uint8_t kMagic[8] = {'A', 'U', 'R', 'S', 'E', 'C', 0x01, 0x00};

inline constexpr size_t kHeaderSize = 64;
inline constexpr uint8_t kHeaderVersionMajor = 1;
inline constexpr uint8_t kHeaderVersionMinor = 0;

inline constexpr uint8_t kFrameMeta = 1;
inline constexpr uint8_t kFrameData = 2;
inline constexpr uint8_t kFrameEnd = 3;

inline constexpr size_t kFrameHeaderSize = 6;  // type, flags, u32 size
inline constexpr uint8_t kFlagLast = 0x01;

inline constexpr size_t kMetaFixedSize = 30;
inline constexpr size_t kChunkSize = 1024 * 1024;
inline constexpr size_t kMaxMetaSize = 64 * 1024;

inline constexpr uint8_t kKdfArgon2i = 1;
inline constexpr uint8_t kAeadXChaCha20Poly1305 = 1;

inline constexpr uint8_t kHeaderFlagKeyFile = 0x01;

inline constexpr uint32_t kMinArgonBlocks = 8;
inline constexpr uint32_t kMaxArgonBlocks = 1u << 20;  // 1 GiB work area
inline constexpr uint32_t kMinArgonPasses = 1;
inline constexpr uint32_t kMaxArgonPasses = 64;
inline constexpr uint32_t kDefaultArgonBlocks = 65536;  // 64 MiB
inline constexpr uint32_t kDefaultArgonPasses = 3;

}  // namespace format

struct KdfParams {
  uint32_t blocks = format::kDefaultArgonBlocks;
  uint32_t passes = format::kDefaultArgonPasses;
};

void validate_kdf_params(const KdfParams& params);

struct HeaderInfo {
  uint8_t version_major = 0;
  uint8_t version_minor = 0;
  uint8_t kdf_id = 0;
  uint8_t aead_id = 0;
  uint32_t argon_blocks = 0;
  uint32_t argon_passes = 0;
  crypto::Salt salt{};
  uint8_t flags = 0;

  bool uses_key_file() const {
    return (flags & format::kHeaderFlagKeyFile) != 0;
  }
  // Argon2 work area in bytes.
  uint64_t memory_bytes() const {
    return static_cast<uint64_t>(argon_blocks) * 1024u;
  }
};

// done/total are byte counters; 'current' is the entry being processed.
using ProgressCallback =
    std::function<void(uint64_t done, uint64_t total, const std::string& current)>;

struct WriterOptions {
  KdfParams kdf{};
  std::vector<uint8_t> key_file;
  bool overwrite = false;
  // Disables archive path validation. Only used by the test suite to forge
  // archives that a reader must reject.
  bool allow_unsafe_paths = false;
};

class ContainerWriter {
 public:
  ContainerWriter(const fs::path& output_path, const std::string& password,
                  const WriterOptions& options);
  ~ContainerWriter();

  ContainerWriter(const ContainerWriter&) = delete;
  ContainerWriter& operator=(const ContainerWriter&) = delete;

  // Writes every entry and the end marker, then closes the archive. On any
  // failure the partially written archive is deleted.
  void write_entries(const std::vector<Entry>& entries,
                     const ProgressCallback& progress = ProgressCallback());

  const HeaderInfo& header() const { return header_; }
  uint64_t bytes_written() const { return file_.tell(); }

 private:
  void write_header();
  void write_meta_frame(const Entry& entry, uint64_t entry_index);
  void write_data_frame(uint64_t entry_index, uint64_t chunk_index, bool last,
                        const uint8_t* plain, size_t plain_length);
  void write_file_entry(const Entry& entry, uint64_t entry_index, uint64_t& done,
                        uint64_t total, const ProgressCallback& progress);
  void write_end_frame(uint64_t entry_index);
  void write_frame(uint8_t type, bool last, uint32_t size,
                   const crypto::Mac& mac, const uint8_t* cipher);

  fs::path output_path_;
  FileWriter file_;
  WriterOptions options_;
  HeaderInfo header_{};
  crypto::Key key_{};
  bool committed_ = false;
};

class ContainerReader {
 public:
  ContainerReader(const fs::path& input_path, const std::string& password,
                  const std::vector<uint8_t>& key_file = std::vector<uint8_t>());
  ~ContainerReader();

  ContainerReader(const ContainerReader&) = delete;
  ContainerReader& operator=(const ContainerReader&) = delete;

  const HeaderInfo& header() const { return header_; }

  // Advances to the next entry. Returns false once the end marker was read.
  // Any unread data of the previous entry is validated first.
  bool next_entry(Entry& entry);

  // Reads payload bytes of the current file entry. Returns 0 at the end of the
  // current entry's data.
  size_t read_data(void* buffer, size_t length);

  // Drains the remaining entries and requires the end marker. Must be called
  // before the reader is destroyed to prove the archive is complete.
  void finish();

 private:
  struct FrameHeader {
    uint8_t type = 0;
    uint8_t flags = 0;
    uint32_t size = 0;
    crypto::Mac mac{};
  };

  FrameHeader read_frame_header();
  void read_exact_checked(void* buffer, size_t length, const char* what);
  void decrypt_frame(const FrameHeader& frame, uint64_t entry_index,
                     uint64_t chunk_index, uint8_t* out, size_t out_length);
  void load_next_data_frame();
  void finish_current_entry();
  void verify_end_of_file();

  fs::path input_path_;
  FileReader file_;
  HeaderInfo header_{};
  crypto::Key key_{};
  bool ended_ = false;
  bool entry_open_ = false;
  bool chunk_last_ = false;
  bool finished_ = false;
  Entry current_{};
  uint64_t entry_index_ = 0;
  uint64_t chunk_index_ = 0;
  uint64_t consumed_ = 0;
  std::vector<uint8_t> frame_;
  size_t frame_position_ = 0;
};

}  // namespace aurora
