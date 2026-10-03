#include "container.h"

#include <algorithm>
#include <cstring>
#include <system_error>
#include <utility>

#include "fsutil.h"
#include "log.h"
#include "util.h"

namespace aurora {

namespace {

// Header field offsets (see docs/FORMAT.md).
constexpr size_t kOffsetKdf = 8;
constexpr size_t kOffsetAead = 9;
constexpr size_t kOffsetArgonBlocks = 10;
constexpr size_t kOffsetArgonPasses = 14;
constexpr size_t kOffsetSalt = 18;
constexpr size_t kOffsetMac = 34;
constexpr size_t kOffsetFlags = 50;
constexpr size_t kOffsetReserved = 51;

// Associated data of every frame: the magic followed by the frame type. This
// binds the frame to the format and prevents type confusion attacks.
std::array<uint8_t, 9> frame_associated_data(uint8_t frame_type) {
  std::array<uint8_t, 9> data{};
  std::memcpy(data.data(), format::kMagic, sizeof(format::kMagic));
  data[8] = frame_type;
  return data;
}

std::vector<uint8_t> encode_meta(const Entry& entry) {
  std::vector<uint8_t> out;
  out.reserve(format::kMetaFixedSize + entry.path.size() +
              entry.link_target.size());
  out.push_back(static_cast<uint8_t>(entry.type));
  out.push_back(0);  // reserved flags
  util::append_le32(out, static_cast<uint32_t>(entry.path.size()));
  util::append_le64(out, entry.size);
  util::append_le64(out, static_cast<uint64_t>(entry.mtime));
  util::append_le32(out, entry.mode);
  util::append_le32(out, static_cast<uint32_t>(entry.link_target.size()));
  out.insert(out.end(), entry.path.begin(), entry.path.end());
  out.insert(out.end(), entry.link_target.begin(), entry.link_target.end());
  return out;
}

Entry decode_meta(const uint8_t* data, size_t length) {
  if (length < format::kMetaFixedSize) {
    fail(ExitCode::kCrypto, "archive is corrupt: entry metadata is too short");
  }
  const uint8_t type = data[0];
  if (type != static_cast<uint8_t>(EntryType::kFile) &&
      type != static_cast<uint8_t>(EntryType::kDirectory) &&
      type != static_cast<uint8_t>(EntryType::kSymlink)) {
    fail(ExitCode::kCrypto, "archive is corrupt: unknown entry type");
  }
  const uint32_t path_length = util::get_le32(data + 2);
  const uint64_t data_size = util::get_le64(data + 6);
  const uint64_t mtime = util::get_le64(data + 14);
  const uint32_t mode = util::get_le32(data + 22);
  const uint32_t link_length = util::get_le32(data + 26);

  if (path_length == 0 ||
      length != format::kMetaFixedSize + path_length + link_length) {
    fail(ExitCode::kCrypto, "archive is corrupt: entry metadata is malformed");
  }

  Entry entry;
  entry.type = static_cast<EntryType>(type);
  entry.path.assign(reinterpret_cast<const char*>(data) + format::kMetaFixedSize,
                    path_length);
  entry.link_target.assign(
      reinterpret_cast<const char*>(data) + format::kMetaFixedSize + path_length,
      link_length);
  entry.size = data_size;
  entry.mtime = static_cast<int64_t>(mtime);
  entry.mode = mode;

  // Rejects "../", absolute paths, drive letters and platform specific traps.
  fsutil::validate_archive_path(entry.path);

  switch (entry.type) {
    case EntryType::kFile:
      if (link_length != 0) {
        fail(ExitCode::kCrypto,
             "archive is corrupt: file entry carries a link target");
      }
      break;
    case EntryType::kDirectory:
      if (data_size != 0 || link_length != 0) {
        fail(ExitCode::kCrypto,
             "archive is corrupt: directory entry carries data");
      }
      break;
    case EntryType::kSymlink:
      if (link_length == 0 || data_size != link_length) {
        fail(ExitCode::kCrypto,
             "archive is corrupt: symbolic link entry is inconsistent");
      }
      if (entry.link_target.find('\0') != std::string::npos) {
        fail(ExitCode::kCrypto,
             "archive is corrupt: symbolic link target contains a NUL byte");
      }
      break;
  }
  return entry;
}

}  // namespace

void validate_kdf_params(const KdfParams& params) {
  if (params.blocks < format::kMinArgonBlocks ||
      params.blocks > format::kMaxArgonBlocks) {
    fail(ExitCode::kUsage,
         "Argon2 memory must be between " +
             std::to_string(format::kMinArgonBlocks) + " and " +
             std::to_string(format::kMaxArgonBlocks) + " KiB (got " +
             std::to_string(params.blocks) + ")");
  }
  if (params.passes < format::kMinArgonPasses ||
      params.passes > format::kMaxArgonPasses) {
    fail(ExitCode::kUsage,
         "Argon2 passes must be between " +
             std::to_string(format::kMinArgonPasses) + " and " +
             std::to_string(format::kMaxArgonPasses) + " (got " +
             std::to_string(params.passes) + ")");
  }
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

ContainerWriter::ContainerWriter(const fs::path& output_path,
                                 const std::string& password,
                                 const WriterOptions& options)
    : output_path_(output_path),
      file_(output_path, options.overwrite),
      options_(options) {
  try {
    validate_kdf_params(options_.kdf);
    header_.version_major = format::kHeaderVersionMajor;
    header_.version_minor = format::kHeaderVersionMinor;
    header_.kdf_id = format::kKdfArgon2i;
    header_.aead_id = format::kAeadXChaCha20Poly1305;
    header_.argon_blocks = options_.kdf.blocks;
    header_.argon_passes = options_.kdf.passes;
    header_.salt = crypto::random_salt();
    header_.flags = options_.key_file.empty() ? 0 : format::kHeaderFlagKeyFile;

    key_ = crypto::derive_key(password, header_.salt, header_.argon_blocks,
                              header_.argon_passes);
    if (!options_.key_file.empty()) {
      key_ = crypto::combine_keyfile(key_, options_.key_file);
    }
    write_header();
  } catch (...) {
    std::error_code ec;
    fs::remove(output_path_, ec);
    throw;
  }
}

ContainerWriter::~ContainerWriter() {
  // A failed run must never leave a half written archive behind: it looks like
  // a valid file and would silently not contain everything.
  if (!committed_) {
    try {
      file_.close();
    } catch (...) {
    }
    std::error_code ec;
    fs::remove(output_path_, ec);
  }
}

void ContainerWriter::write_header() {
  std::array<uint8_t, format::kHeaderSize> header{};
  std::memcpy(header.data(), format::kMagic, sizeof(format::kMagic));
  header[kOffsetKdf] = header_.kdf_id;
  header[kOffsetAead] = header_.aead_id;
  util::put_le32(header.data() + kOffsetArgonBlocks, header_.argon_blocks);
  util::put_le32(header.data() + kOffsetArgonPasses, header_.argon_passes);
  std::memcpy(header.data() + kOffsetSalt, header_.salt.data(),
              header_.salt.size());
  header[kOffsetFlags] = header_.flags;
  // The authenticator covers the whole header with the MAC field zeroed, so no
  // field (not even the KDF parameters) can be changed without the password.
  crypto::Mac mac{};
  crypto::blake2b_keyed(mac.data(), mac.size(), key_.data(), key_.size(),
                        header.data(), header.size());
  std::memcpy(header.data() + kOffsetMac, mac.data(), mac.size());
  file_.write(header.data(), header.size());
}

void ContainerWriter::write_frame(uint8_t type, bool last, uint32_t size,
                                  const crypto::Mac& mac, const uint8_t* cipher) {
  uint8_t header[format::kFrameHeaderSize];
  header[0] = type;
  header[1] = last ? format::kFlagLast : 0;
  util::put_le32(header + 2, size);
  file_.write(header, sizeof(header));
  file_.write(mac.data(), mac.size());
  if (size > 0) {
    file_.write(cipher, size);
  }
}

void ContainerWriter::write_meta_frame(const Entry& entry,
                                       uint64_t entry_index) {
  if (!options_.allow_unsafe_paths) {
    fsutil::validate_archive_path(entry.path);
  }
  const std::vector<uint8_t> plain = encode_meta(entry);
  if (plain.size() > format::kMaxMetaSize) {
    fail(ExitCode::kIo, "entry metadata is too large: " + entry.path);
  }
  std::vector<uint8_t> cipher(plain.size());
  crypto::Mac mac{};
  const crypto::Nonce nonce = crypto::frame_nonce(entry_index, 0);
  const std::array<uint8_t, 9> ad = frame_associated_data(format::kFrameMeta);
  crypto::aead_lock(cipher.data(), mac, key_, nonce, ad.data(), ad.size(),
                    plain.data(), plain.size());
  write_frame(format::kFrameMeta, true, static_cast<uint32_t>(cipher.size()),
              mac, cipher.data());
}

void ContainerWriter::write_data_frame(uint64_t entry_index,
                                       uint64_t chunk_index, bool last,
                                       const uint8_t* plain,
                                       size_t plain_length) {
  std::vector<uint8_t> cipher(plain_length);
  crypto::Mac mac{};
  const crypto::Nonce nonce = crypto::frame_nonce(entry_index, chunk_index);
  const std::array<uint8_t, 9> ad = frame_associated_data(format::kFrameData);
  crypto::aead_lock(cipher.empty() ? nullptr : cipher.data(), mac, key_, nonce,
                    ad.data(), ad.size(), plain, plain_length);
  write_frame(format::kFrameData, last, static_cast<uint32_t>(plain_length), mac,
              cipher.empty() ? nullptr : cipher.data());
}

void ContainerWriter::write_file_entry(const Entry& entry, uint64_t entry_index,
                                       uint64_t& done, uint64_t total,
                                       const ProgressCallback& progress) {
  std::error_code ec;
  // Re-read the size right before writing so that the declared size and the
  // stored payload agree even when the file changed since the walk.
  const uint64_t size = fs::file_size(entry.source, ec);
  if (ec) {
    fail(ExitCode::kIo, "cannot read '" + fsutil::path_to_utf8(entry.source) +
                            "': " + ec.message());
  }
  Entry meta = entry;
  meta.size = size;
  write_meta_frame(meta, entry_index);

  FileReader source(entry.source);
  std::vector<uint8_t> buffer(format::kChunkSize);
  uint64_t remaining = size;
  uint64_t chunk_index = 1;
  for (;;) {
    const size_t want = remaining > format::kChunkSize
                            ? format::kChunkSize
                            : static_cast<size_t>(remaining);
    if (want > 0 && !source.read_exact(buffer.data(), want)) {
      fail(ExitCode::kIo,
           "file changed while it was encrypted: " +
               fsutil::path_to_utf8(entry.source));
    }
    const bool last = remaining <= format::kChunkSize;
    write_data_frame(entry_index, chunk_index, last, buffer.data(), want);
    ++chunk_index;
    remaining -= want;
    done += want;
    if (progress) {
      progress(done, total, entry.path);
    }
    if (last) {
      break;
    }
  }
  if (source.has_more()) {
    fail(ExitCode::kIo, "file changed while it was encrypted: " +
                            fsutil::path_to_utf8(entry.source));
  }
}

void ContainerWriter::write_end_frame(uint64_t entry_index) {
  crypto::Mac mac{};
  const crypto::Nonce nonce = crypto::frame_nonce(entry_index, 0);
  const std::array<uint8_t, 9> ad = frame_associated_data(format::kFrameEnd);
  crypto::aead_lock(nullptr, mac, key_, nonce, ad.data(), ad.size(), nullptr, 0);
  write_frame(format::kFrameEnd, true, 0, mac, nullptr);
}

void ContainerWriter::write_entries(const std::vector<Entry>& entries,
                                    const ProgressCallback& progress) {
  uint64_t total = 0;
  for (const Entry& entry : entries) {
    if (entry.type == EntryType::kFile) {
      total += entry.size;
    }
  }
  if (progress) {
    progress(0, total, std::string());
  }

  uint64_t done = 0;
  for (size_t index = 0; index < entries.size(); ++index) {
    const Entry& entry = entries[index];
    const uint64_t entry_index = static_cast<uint64_t>(index);
    if (entry.type == EntryType::kFile) {
      write_file_entry(entry, entry_index, done, total, progress);
    } else {
      write_meta_frame(entry, entry_index);
      if (progress) {
        progress(done, total, entry.path);
      }
    }
  }
  write_end_frame(static_cast<uint64_t>(entries.size()));
  file_.flush();
  file_.close();
  committed_ = true;
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

ContainerReader::ContainerReader(const fs::path& input_path,
                                 const std::string& password,
                                 const std::vector<uint8_t>& key_file)
    : input_path_(input_path), file_(input_path) {
  std::array<uint8_t, format::kHeaderSize> header{};
  read_exact_checked(header.data(), header.size(), "header");

  if (std::memcmp(header.data(), format::kMagic, sizeof(format::kMagic)) != 0) {
    fail(ExitCode::kCrypto,
         "'" + fsutil::path_to_utf8(input_path) +
             "' is not an AuroraSecret archive");
  }
  header_.version_major = header[6];
  header_.version_minor = header[7];
  if (header_.version_major != format::kHeaderVersionMajor) {
    fail(ExitCode::kCrypto,
         "unsupported archive version " + std::to_string(header_.version_major) +
             "." + std::to_string(header_.version_minor));
  }
  header_.kdf_id = header[kOffsetKdf];
  header_.aead_id = header[kOffsetAead];
  if (header_.kdf_id != format::kKdfArgon2i) {
    fail(ExitCode::kCrypto, "unsupported key derivation function in archive");
  }
  if (header_.aead_id != format::kAeadXChaCha20Poly1305) {
    fail(ExitCode::kCrypto, "unsupported cipher in archive");
  }
  header_.argon_blocks = util::get_le32(header.data() + kOffsetArgonBlocks);
  header_.argon_passes = util::get_le32(header.data() + kOffsetArgonPasses);
  std::memcpy(header_.salt.data(), header.data() + kOffsetSalt,
              header_.salt.size());
  header_.flags = header[kOffsetFlags];
  if ((header_.flags & ~format::kHeaderFlagKeyFile) != 0) {
    fail(ExitCode::kCrypto, "archive uses unsupported feature flags");
  }
  if (header_.argon_blocks < format::kMinArgonBlocks ||
      header_.argon_blocks > format::kMaxArgonBlocks ||
      header_.argon_passes < format::kMinArgonPasses ||
      header_.argon_passes > format::kMaxArgonPasses) {
    fail(ExitCode::kCrypto, "archive header carries invalid Argon2 parameters");
  }
  for (size_t i = kOffsetReserved; i < header.size(); ++i) {
    if (header[i] != 0) {
      fail(ExitCode::kCrypto, "archive header carries unsupported data");
    }
  }

  key_ = crypto::derive_key(password, header_.salt, header_.argon_blocks,
                            header_.argon_passes);
  if (header_.uses_key_file()) {
    if (key_file.empty()) {
      fail(ExitCode::kCrypto,
           "the archive was encrypted with a key file: pass --key-file");
    }
    key_ = crypto::combine_keyfile(key_, key_file);
  } else if (!key_file.empty()) {
    log::warn("a key file was supplied, but the archive was not encrypted with "
              "one; it is ignored");
  }

  crypto::Mac stored{};
  std::memcpy(stored.data(), header.data() + kOffsetMac, stored.size());
  std::array<uint8_t, format::kHeaderSize> for_mac = header;
  std::memset(for_mac.data() + kOffsetMac, 0, crypto::kMacSize);
  crypto::Mac computed{};
  crypto::blake2b_keyed(computed.data(), computed.size(), key_.data(),
                        key_.size(), for_mac.data(), for_mac.size());
  if (!util::constant_time_equal(computed.data(), stored.data(),
                                 crypto::kMacSize)) {
    fail(ExitCode::kCrypto,
         "wrong password" +
             std::string(header_.uses_key_file() ? ", key file" : "") +
             " or damaged header for '" + fsutil::path_to_utf8(input_path) + "'");
  }
}

ContainerReader::~ContainerReader() = default;

void ContainerReader::read_exact_checked(void* buffer, size_t length,
                                         const char* what) {
  if (!file_.read_exact(buffer, length)) {
    fail(ExitCode::kCrypto, "archive is truncated while reading the " +
                                std::string(what) + ": " +
                                fsutil::path_to_utf8(input_path_));
  }
}

ContainerReader::FrameHeader ContainerReader::read_frame_header() {
  uint8_t raw[format::kFrameHeaderSize];
  read_exact_checked(raw, sizeof(raw), "frame header");
  FrameHeader frame;
  frame.type = raw[0];
  frame.flags = raw[1];
  frame.size = util::get_le32(raw + 2);
  read_exact_checked(frame.mac.data(), frame.mac.size(), "frame authenticator");
  return frame;
}

void ContainerReader::decrypt_frame(const FrameHeader& frame,
                                    uint64_t entry_index, uint64_t chunk_index,
                                    uint8_t* out, size_t out_length) {
  if (out_length < frame.size || (frame.size > 0 && out == nullptr)) {
    fail(ExitCode::kInternal,
         "internal error: buffer too small to hold a frame");
  }
  std::vector<uint8_t> cipher(frame.size);
  if (frame.size > 0) {
    read_exact_checked(cipher.data(), cipher.size(), "frame payload");
  }
  const crypto::Nonce nonce = crypto::frame_nonce(entry_index, chunk_index);
  const std::array<uint8_t, 9> ad = frame_associated_data(frame.type);
  if (!crypto::aead_unlock(out, frame.mac, key_, nonce, ad.data(), ad.size(),
                           cipher.empty() ? nullptr : cipher.data(),
                           cipher.size())) {
    fail(ExitCode::kCrypto,
         "authentication failed: the archive was modified, truncated or the "
         "password is wrong");
  }
}

void ContainerReader::finish_current_entry() {
  if (!entry_open_) {
    return;
  }
  if (!chunk_last_) {
    fail(ExitCode::kCrypto,
         "archive is truncated inside '" + current_.path + "'");
  }
  if (current_.type == EntryType::kFile && consumed_ != current_.size) {
    fail(ExitCode::kCrypto, "archive is corrupt: size mismatch for '" +
                                current_.path + "'");
  }
  entry_open_ = false;
  ++entry_index_;
}

bool ContainerReader::next_entry(Entry& entry) {
  if (ended_) {
    return false;
  }
  finish_current_entry();

  const FrameHeader frame = read_frame_header();
  if (frame.type == format::kFrameEnd) {
    if (frame.size != 0) {
      fail(ExitCode::kCrypto, "archive is corrupt: end marker is not empty");
    }
    decrypt_frame(frame, entry_index_, 0, nullptr, 0);
    ended_ = true;
    verify_end_of_file();
    return false;
  }
  if (frame.type != format::kFrameMeta) {
    fail(ExitCode::kCrypto,
         "archive is corrupt: expected an entry but found another frame");
  }
  if (frame.size == 0 || frame.size > format::kMaxMetaSize) {
    fail(ExitCode::kCrypto, "archive is corrupt: invalid metadata frame size");
  }
  if ((frame.flags & format::kFlagLast) == 0) {
    fail(ExitCode::kCrypto, "archive is corrupt: metadata frame is not final");
  }
  std::vector<uint8_t> plain(frame.size);
  decrypt_frame(frame, entry_index_, 0, plain.data(), plain.size());

  current_ = decode_meta(plain.data(), plain.size());
  frame_.clear();
  frame_position_ = 0;
  consumed_ = 0;
  chunk_index_ = 1;
  chunk_last_ = current_.type != EntryType::kFile;
  entry_open_ = true;
  entry = current_;
  return true;
}

void ContainerReader::load_next_data_frame() {
  const FrameHeader frame = read_frame_header();
  if (frame.type != format::kFrameData) {
    fail(ExitCode::kCrypto,
         "archive is corrupt: missing data for '" + current_.path + "'");
  }
  if (frame.size > format::kChunkSize) {
    fail(ExitCode::kCrypto, "archive is corrupt: data frame is too large");
  }
  const bool last = (frame.flags & format::kFlagLast) != 0;
  if (!last && frame.size != format::kChunkSize) {
    fail(ExitCode::kCrypto, "archive is corrupt: short non final data frame");
  }
  if (consumed_ + frame.size > current_.size) {
    fail(ExitCode::kCrypto, "archive is corrupt: '" + current_.path +
                                "' is larger than declared");
  }
  frame_.assign(frame.size, 0);
  decrypt_frame(frame, entry_index_, chunk_index_, frame_.data(), frame_.size());
  ++chunk_index_;
  chunk_last_ = last;
  frame_position_ = 0;
}

size_t ContainerReader::read_data(void* buffer, size_t length) {
  if (!entry_open_ || current_.type != EntryType::kFile || length == 0) {
    return 0;
  }
  while (frame_position_ >= frame_.size()) {
    if (chunk_last_) {
      return 0;
    }
    load_next_data_frame();
  }
  const size_t available = frame_.size() - frame_position_;
  const size_t copied = std::min(available, length);
  std::memcpy(buffer, frame_.data() + frame_position_, copied);
  frame_position_ += copied;
  consumed_ += copied;
  return copied;
}

void ContainerReader::verify_end_of_file() {
  uint8_t byte = 0;
  if (file_.read(&byte, 1) != 0) {
    fail(ExitCode::kCrypto, "archive carries trailing data after its end marker");
  }
}

void ContainerReader::finish() {
  if (finished_) {
    return;
  }
  finished_ = true;
  if (!ended_) {
    Entry scratch;
    while (next_entry(scratch)) {
      uint8_t sink[64 * 1024];
      while (read_data(sink, sizeof(sink)) > 0) {
      }
    }
  }
  if (!ended_) {
    fail(ExitCode::kCrypto, "archive is truncated: " +
                                fsutil::path_to_utf8(input_path_));
  }
}

}  // namespace aurora
