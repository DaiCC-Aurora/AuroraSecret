#include "cli.h"

#include <cstdio>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "container.h"
#include "extract.h"
#include "fsutil.h"
#include "io.h"
#include "log.h"
#include "password.h"
#include "util.h"
#include "version.h"
#include "walk.h"

namespace aurora {
namespace {

enum class Mode {
  kEncrypt,
  kDecrypt,
  kList,
};

struct Options {
  Mode mode = Mode::kEncrypt;
  std::vector<std::string> inputs;  // encrypt
  std::string archive;              // decrypt, list
  std::string output;               // -o
  PasswordOptions password;
  KdfParams kdf{};
  bool force = false;
  bool dry_run = false;
  bool preserve_times = true;
  bool preserve_permissions = true;
  SymlinkMode symlinks = SymlinkMode::kStore;
  std::vector<std::string> excludes;
  bool quiet = false;
  int verbose = 0;
  bool no_progress = false;
  bool color = true;
  bool help = false;
};

const char* mode_name(Mode mode) {
  switch (mode) {
    case Mode::kEncrypt:
      return "encrypt";
    case Mode::kDecrypt:
      return "decrypt";
    case Mode::kList:
      return "list";
  }
  return "?";
}

void print_usage(std::FILE* out) {
  std::fprintf(
      out,
      "AuroraSecret %s - batch file and folder encryption\n"
      "\n"
      "Usage:\n"
      "  aurorasecret encrypt [options] <path>...\n"
      "  aurorasecret decrypt [options] <archive.asf>\n"
      "  aurorasecret list    [options] <archive.asf>\n"
      "  aurorasecret --help | --version\n"
      "\n"
      "Commands:\n"
      "  encrypt, e    Encrypt files and folders into a single .asf archive\n"
      "  decrypt, d    Decrypt an archive back into files and folders\n"
      "  list, l       Show what an archive contains (the password is needed)\n"
      "\n"
      "Common options:\n"
      "  -p, --password <text>       Password (visible in the process list)\n"
      "      --password-file <file>  Read the password from the first line\n"
      "      --password-env <var>    Read the password from an environment variable\n"
      "      --password-stdin        Read the password from standard input\n"
      "  -k, --key-file <file>       Mix a key file into the key (two factors)\n"
      "  -q, --quiet                 Only report errors\n"
      "  -v, --verbose               Report every entry (repeat for more detail)\n"
      "      --no-progress           Never draw the progress line\n"
      "      --no-color              Disable colored output (also NO_COLOR)\n"
      "  -h, --help                  Show this help\n"
      "\n"
      "encrypt options:\n"
      "  -o, --output <archive>      Output archive (default: <name>.asf)\n"
      "  -f, --force                 Overwrite an existing archive\n"
      "      --follow-symlinks       Store what a symbolic link points at\n"
      "      --no-symlinks           Skip symbolic links\n"
      "      --exclude <pattern>     Skip matching paths ('*' and '?' work)\n"
      "      --argon2-blocks <n>     Argon2i memory in KiB (default %u)\n"
      "      --argon2-passes <n>     Argon2i iterations (default %u)\n"
      "\n"
      "decrypt options:\n"
      "  -o, --output <dir>          Destination directory (default: .)\n"
      "  -f, --force                 Overwrite existing files\n"
      "      --dry-run               Verify the archive, write nothing\n"
      "      --no-preserve-times     Do not restore modification times\n"
      "      --no-preserve-modes     Do not restore permission bits\n"
      "\n"
      "Environment:\n"
      "  AURORASECRET_PASSWORD       Password, used when no option is given\n"
      "  AURORASECRET_PASSWORD_FILE  File holding the password on its first line\n"
      "  NO_COLOR                    Disable colored output\n"
      "\n"
      "Exit codes: 0 ok, 1 usage, 2 wrong password or corrupt archive, 3 I/O\n"
      "            4 partial (some entries were skipped), 5 internal\n"
      "\n"
      "Examples:\n"
      "  aurorasecret encrypt Documents -o Documents.asf\n"
      "  aurorasecret decrypt Documents.asf -o restored/\n"
      "  aurorasecret encrypt photo.jpg notes.txt -o backup.asf -k usb.key\n",
      AURORASECRET_VERSION_STRING,
      static_cast<unsigned>(format::kDefaultArgonBlocks),
      static_cast<unsigned>(format::kDefaultArgonPasses));
}

void print_command_help(Mode mode, std::FILE* out) {
  std::fprintf(out, "aurorasecret %s - see 'aurorasecret --help' for the full list\n",
               mode_name(mode));
}

void print_version() {
  std::printf("AuroraSecret %s\n", AURORASECRET_VERSION_STRING);
  std::printf("commit %s\n", AURORASECRET_GIT_COMMIT);
  std::printf("crypto XChaCha20-Poly1305 (AEAD), Argon2i (KDF), BLAKE2b (MAC)\n");
  std::printf("container format %u.%u\n", static_cast<unsigned>(format::kHeaderVersionMajor),
              static_cast<unsigned>(format::kHeaderVersionMinor));
}

struct ParsedOption {
  std::string name;
  std::string value;
  bool has_value = false;
};

ParsedOption parse_option(const std::string& argument) {
  ParsedOption option;
  option.name = argument;
  if (argument.size() > 1 && argument[0] == '-') {
    const size_t equals = argument.find('=');
    if (equals != std::string::npos && equals > 1) {
      option.name = argument.substr(0, equals);
      option.value = argument.substr(equals + 1);
      option.has_value = true;
    }
  }
  return option;
}

void add_positional(Options& options, const std::string& value) {
  if (options.mode == Mode::kEncrypt) {
    options.inputs.push_back(value);
    return;
  }
  if (!options.archive.empty()) {
    fail(ExitCode::kUsage,
         "only one archive can be given (got '" + options.archive + "' and '" +
             value + "')");
  }
  options.archive = value;
}

Options parse_arguments(const std::vector<std::string>& args, Mode mode,
                        size_t start_index) {
  Options options;
  options.mode = mode;
  bool positional_only = false;

  for (size_t index = start_index; index < args.size(); ++index) {
    const std::string argument = args[index];
    if (positional_only) {
      add_positional(options, argument);
      continue;
    }
    if (argument == "--") {
      positional_only = true;
      continue;
    }
    if (argument.size() < 2 || argument[0] != '-') {
      add_positional(options, argument);
      continue;
    }

    const ParsedOption option = parse_option(argument);
    const std::string& name = option.name;
    const auto value = [&](const char* what) -> std::string {
      if (option.has_value) {
        return option.value;
      }
      if (index + 1 >= args.size()) {
        fail(ExitCode::kUsage,
             std::string("option '") + what + "' requires a value");
      }
      return args[++index];
    };
    const auto number = [&](const char* what, uint64_t minimum,
                            uint64_t maximum) -> uint32_t {
      const std::string text = value(what);
      uint64_t parsed = 0;
      if (!util::parse_uint64(text, parsed) || parsed < minimum ||
          parsed > maximum) {
        fail(ExitCode::kUsage,
             std::string("option '") + what + "' expects a number between " +
                 std::to_string(minimum) + " and " + std::to_string(maximum) +
                 " (got '" + text + "')");
      }
      return static_cast<uint32_t>(parsed);
    };

    if (name == "-h" || name == "--help") {
      options.help = true;
    } else if (name == "-q" || name == "--quiet") {
      options.quiet = true;
    } else if (name == "-v" || name == "--verbose") {
      ++options.verbose;
    } else if (name == "--no-progress") {
      options.no_progress = true;
    } else if (name == "--no-color") {
      options.color = false;
    } else if (name == "-p" || name == "--password") {
      options.password.password = value(name.c_str());
      options.password.password_given = true;
    } else if (name == "--password-file") {
      options.password.password_file = value(name.c_str());
    } else if (name == "--password-env") {
      options.password.password_env = value(name.c_str());
    } else if (name == "--password-stdin") {
      options.password.password_stdin = true;
    } else if (name == "-k" || name == "--key-file") {
      options.password.key_file = value(name.c_str());
    } else if (name == "-o" || name == "--output") {
      options.output = value(name.c_str());
    } else if (name == "-f" || name == "--force") {
      options.force = true;
    } else if (name == "--dry-run") {
      options.dry_run = true;
    } else if (name == "--no-preserve-times") {
      options.preserve_times = false;
    } else if (name == "--no-preserve-modes") {
      options.preserve_permissions = false;
    } else if (name == "--follow-symlinks") {
      options.symlinks = SymlinkMode::kFollow;
    } else if (name == "--no-symlinks") {
      options.symlinks = SymlinkMode::kSkip;
    } else if (name == "--exclude") {
      options.excludes.push_back(value(name.c_str()));
    } else if (name == "--argon2-blocks") {
      options.kdf.blocks = number(name.c_str(), format::kMinArgonBlocks,
                                  format::kMaxArgonBlocks);
    } else if (name == "--argon2-passes") {
      options.kdf.passes = number(name.c_str(), format::kMinArgonPasses,
                                  format::kMaxArgonPasses);
    } else {
      fail(ExitCode::kUsage, "unknown option '" + name + "' (try --help)");
    }
  }

  validate_kdf_params(options.kdf);
  return options;
}

int command_encrypt(const Options& options) {
  if (options.inputs.empty()) {
    fail(ExitCode::kUsage,
         "no input files or folders were given (try 'aurorasecret --help')");
  }

  std::vector<fs::path> inputs;
  inputs.reserve(options.inputs.size());
  for (const std::string& text : options.inputs) {
    inputs.push_back(fsutil::path_from_utf8(text));
  }

  WalkOptions walk_options;
  walk_options.symlinks = options.symlinks;
  walk_options.exclude_patterns = options.excludes;

  log::verbose("scanning " + std::to_string(inputs.size()) + " input(s)");
  const std::vector<Entry> entries = collect_entries(inputs, walk_options);
  if (entries.empty()) {
    fail(ExitCode::kIo, "there is nothing to encrypt");
  }

  fs::path output;
  if (options.output.empty()) {
    output = fsutil::path_from_utf8(fsutil::top_level_name(inputs.front()) +
                                    ".asf");
  } else {
    output = fsutil::path_from_utf8(options.output);
  }

  const SecureString password = resolve_password(options.password, true);
  const std::vector<uint8_t> key_file = read_key_file(options.password.key_file);

  WriterOptions writer_options;
  writer_options.kdf = options.kdf;
  writer_options.key_file = key_file;
  writer_options.overwrite = options.force;

  uint64_t total_bytes = 0;
  uint64_t file_count = 0;
  uint64_t directory_count = 0;
  uint64_t link_count = 0;
  for (const Entry& entry : entries) {
    switch (entry.type) {
      case EntryType::kFile:
        total_bytes += entry.size;
        ++file_count;
        break;
      case EntryType::kDirectory:
        ++directory_count;
        break;
      case EntryType::kSymlink:
        ++link_count;
        break;
    }
  }

  Progress progress(!options.no_progress && !options.quiet, "encrypting");
  progress.set_total(total_bytes);

  ContainerWriter writer(output, password.str(), writer_options);
  writer.write_entries(
      entries, [&progress](uint64_t done, uint64_t, const std::string& current) {
        progress.update(done, current);
      });
  progress.finish();

  log::success("encrypted " + std::to_string(entries.size()) + " entries (" +
               std::to_string(file_count) + " files, " +
               std::to_string(directory_count) + " directories, " +
               std::to_string(link_count) + " links, " +
               util::format_size(total_bytes) + ") into '" +
               fsutil::path_to_utf8(output) + "' (" +
               util::format_size(writer.bytes_written()) + ")");
  return static_cast<int>(ExitCode::kOk);
}

int command_decrypt(const Options& options) {
  if (options.archive.empty()) {
    fail(ExitCode::kUsage, "no archive was given (try 'aurorasecret --help')");
  }
  const fs::path archive = fsutil::path_from_utf8(options.archive);
  const fs::path destination = fsutil::path_from_utf8(
      options.output.empty() ? std::string(".") : options.output);

  const SecureString password = resolve_password(options.password, false);
  const std::vector<uint8_t> key_file = read_key_file(options.password.key_file);

  if (!options.dry_run) {
    std::error_code ec;
    fs::create_directories(destination, ec);
    if (ec) {
      fail(ExitCode::kIo, "cannot create the destination directory '" +
                              fsutil::path_to_utf8(destination) +
                              "': " + ec.message());
    }
  }

  ExtractOptions extract_options;
  extract_options.destination = fsutil::absolute_lexical(destination);
  extract_options.overwrite = options.force;
  extract_options.dry_run = options.dry_run;
  extract_options.preserve_times = options.preserve_times;
  extract_options.preserve_permissions = options.preserve_permissions;

  Progress progress(!options.no_progress && !options.quiet, "decrypting");
  extract_options.progress = [&progress](uint64_t done, uint64_t,
                                         const std::string& current) {
    progress.update(done, current);
  };

  ContainerReader reader(archive, password.str(), key_file);
  const ExtractStats stats = extract_archive(reader, extract_options);
  reader.finish();
  progress.finish();

  if (options.dry_run) {
    log::success("archive verified: " + std::to_string(stats.entries) +
                 " entries, " + util::format_size(stats.bytes));
  } else {
    log::success("extracted " + std::to_string(stats.files) + " files, " +
                 std::to_string(stats.directories) + " directories, " +
                 std::to_string(stats.symlinks) + " links (" +
                 util::format_size(stats.bytes) + ") into '" +
                 fsutil::path_to_utf8(extract_options.destination) + "'");
  }

  if (!stats.failures.empty()) {
    log::warn(std::to_string(stats.failures.size()) +
              " entries could not be written");
    return static_cast<int>(ExitCode::kPartial);
  }
  return static_cast<int>(ExitCode::kOk);
}

int command_list(const Options& options) {
  if (options.archive.empty()) {
    fail(ExitCode::kUsage, "no archive was given (try 'aurorasecret --help')");
  }
  const fs::path archive = fsutil::path_from_utf8(options.archive);
  const SecureString password = resolve_password(options.password, false);
  const std::vector<uint8_t> key_file = read_key_file(options.password.key_file);

  ContainerReader reader(archive, password.str(), key_file);
  const HeaderInfo& header = reader.header();
  log::verbose("Argon2i: " + std::to_string(header.argon_blocks) + " KiB, " +
               std::to_string(header.argon_passes) + " passes, key file: " +
               (header.uses_key_file() ? "yes" : "no"));

  std::printf("%-9s %12s  %-19s  %s\n", "TYPE", "SIZE", "MODIFIED", "PATH");
  uint64_t entries = 0;
  uint64_t files = 0;
  uint64_t bytes = 0;
  Entry entry;
  while (reader.next_entry(entry)) {
    uint8_t sink[64 * 1024];
    while (reader.read_data(sink, sizeof(sink)) > 0) {
    }
    ++entries;
    std::string path = entry.path;
    if (entry.type == EntryType::kDirectory) {
      path += "/";
    } else if (entry.type == EntryType::kSymlink) {
      path += " -> " + entry.link_target;
    } else {
      ++files;
      bytes += entry.size;
    }
    std::printf("%-9s %12s  %-19s  %s\n", entry_type_name(entry.type),
                util::format_size(entry.size).c_str(),
                util::format_time(entry.mtime).c_str(), path.c_str());
  }
  reader.finish();
  std::printf("\n%llu entries (%llu files, %s)\n",
              static_cast<unsigned long long>(entries),
              static_cast<unsigned long long>(files),
              util::format_size(bytes).c_str());
  return static_cast<int>(ExitCode::kOk);
}

}  // namespace

int run_cli(const std::vector<std::string>& arguments) {
  if (arguments.size() <= 1) {
    print_usage(stderr);
    return static_cast<int>(ExitCode::kUsage);
  }

  const std::string command = arguments[1];
  if (command == "-h" || command == "--help" || command == "help") {
    print_usage(stdout);
    return static_cast<int>(ExitCode::kOk);
  }
  if (command == "-V" || command == "--version" || command == "version") {
    print_version();
    return static_cast<int>(ExitCode::kOk);
  }

  Mode mode = Mode::kEncrypt;
  if (command == "encrypt" || command == "enc" || command == "e") {
    mode = Mode::kEncrypt;
  } else if (command == "decrypt" || command == "dec" || command == "d") {
    mode = Mode::kDecrypt;
  } else if (command == "list" || command == "ls" || command == "l") {
    mode = Mode::kList;
  } else if (!command.empty() && command[0] == '-') {
    fail(ExitCode::kUsage, "unknown option '" + command + "' (try --help)");
  } else {
    fail(ExitCode::kUsage, "unknown command '" + command + "' (try --help)");
  }

  const Options options = parse_arguments(arguments, mode, 2);
  if (options.help) {
    print_command_help(mode, stdout);
    return static_cast<int>(ExitCode::kOk);
  }

  log::set_quiet(options.quiet);
  log::set_verbose(options.verbose);
  log::set_color(options.color && util::is_tty_stderr());

  switch (mode) {
    case Mode::kEncrypt:
      return command_encrypt(options);
    case Mode::kDecrypt:
      return command_decrypt(options);
    case Mode::kList:
      return command_list(options);
  }
  fail(ExitCode::kInternal, "unreachable command");
}

}  // namespace aurora
