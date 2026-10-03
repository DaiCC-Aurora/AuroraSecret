# AuroraSecret

[English README](../README.md) · 中文说明

AuroraSecret 是一个纯命令行的批量加密/解密工具：把**一个或多个文件、整个文件夹树**
加密成单个 `.asf` 归档文件，也可以再解密还原。

```
aurorasecret encrypt Documents -o Documents.asf
aurorasecret decrypt Documents.asf -o restored/
```

## 特性

* **批量处理**：一次可以传入任意多个文件/文件夹，目录会连同子目录一起存入同一个归档。
* **正规密码学**：XChaCha20-Poly1305 加密、Argon2i 派生密钥、BLAKE2b 校验归档头，
  全部基于经过审计的单文件库 [Monocypher](https://monocypher.org) 4.0.2。
* **全程认证**：每个数据帧都带有独立的认证标签，并绑定"条目序号 + 分块序号"，
  因此被篡改、重排、截断、拼接的归档会被直接拒绝，而不是解出错误的明文。
* **流式处理**：按 1 MiB 分块读写，加密 20 GiB 的文件也不需要 20 GiB 内存。
* **默认安全**：不覆盖已存在的归档或文件；拒绝 `..`、绝对路径、盘符等会逃出目标目录的
  归档路径；不会通过自己刚解压出的符号链接写文件；失败的加密会删除写了一半的归档。
* **跨平台**：Windows / Linux / macOS 同一套代码，路径一律按 UTF-8 处理
  （Windows 下直接读取宽字符命令行）。
* **零安装依赖**：除 C++17 编译器和 CMake 外，唯一的第三方库在配置阶段自动获取
  （也可以手动放到 `third_party/monocypher/`，见下）。

## 编译

需要 CMake 3.16+、支持 C++17 的编译器（MSVC 2019+ / GCC 9+ / Clang 10+ / AppleClang 12+），
首次配置时需要网络（下载 Monocypher）。

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Windows（静态运行库，不依赖 VC++ 运行时）：

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DAURORASECRET_MSVC_STATIC_RUNTIME=ON
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

Linux 完全静态二进制：加 `-DAURORASECRET_LINUX_STATIC=ON`。
macOS 通用二进制：加 `-DCMAKE_OSX_ARCHITECTURES="x86_64;arm64"`。

离线编译：把 Monocypher 的 `monocypher.c`、`monocypher.h` 放进 `third_party/monocypher/`，
或者用 `-DAURORASECRET_MONOCYPHER_DIR=<Monocypher 目录>`。

## 用法

```
aurorasecret encrypt [选项] <路径>...
aurorasecret decrypt [选项] <归档.asf>
aurorasecret list    [选项] <归档.asf>
aurorasecret --help | --version
```

常用示例：

```bash
# 加密一个文件夹，输出 Documents.asf
aurorasecret encrypt Documents -o Documents.asf

# 多个文件合并成一个归档
aurorasecret encrypt report.pdf notes.txt -o bundle.asf

# 排除临时文件
aurorasecret encrypt ~/Pictures -o pictures.asf --exclude '*.tmp' --exclude 'Thumbs.db'

# 提高 Argon2 代价（内存 KiB / 迭代次数）
aurorasecret encrypt disk.img -o disk.asf --argon2-blocks 262144 --argon2-passes 4

# 解密，只校验不写盘
aurorasecret decrypt backup.asf -o check/ --dry-run

# 查看归档内容
aurorasecret list backup.asf

# 口令 + 密钥文件（两因素）
head -c 32 /dev/urandom > aurora.key
aurorasecret encrypt secrets -o secrets.asf -k aurora.key
aurorasecret decrypt secrets.asf -o out -k aurora.key
```

口令的读取顺序：`--password` → `--password-file` → `--password-env` →
环境变量 `AURORASECRET_PASSWORD` → `AURORASECRET_PASSWORD_FILE` →
`--password-stdin` → 交互式输入（加密时要求输入两次）。

退出码：`0` 成功，`1` 参数错误，`2` 口令错误或归档损坏，
`3` 读写错误，`4` 部分成功（有文件被跳过），`5` 内部错误。

完整选项列表见 `aurorasecret --help`。

## 安全提示

* 没有找回口令的机制：口令（和密钥文件）丢了，数据就解不开了。
* `--password` 会出现在进程列表里，建议改用交互输入、`--password-file`、
  `--password-env` 或环境变量。
* 文件名和大小是加密的，但归档总长度和条目数量对外可见。
* 本工具保护的是"静态数据"（磁盘上的文件），无法防御系统已被入侵、
  键盘记录或运行过程中的内存转储。

## 发布

推送到 `main` / `master` 或提交 PR 时，[GitHub Actions 工作流](../.github/workflows/build.yml)
会自动编译并跑测试；推送 `v*` 标签时会自动创建 Release，包含三个平台的压缩包和
`SHA256SUMS.txt`：

| 压缩包 | 内容 |
|--------|------|
| `aurorasecret-1.0.0-windows-x86_64.zip` | `aurorasecret.exe`（静态运行库） |
| `aurorasecret-1.0.0-linux-x86_64.tar.gz` | `aurorasecret`（静态链接） |
| `aurorasecret-1.0.0-macos-universal.tar.gz` | `aurorasecret`（arm64 + x86_64） |

```bash
git tag v1.0.0
git push origin v1.0.0
```

如果 Release 步骤报权限错误，请在 *Settings → Actions → General →
Workflow permissions* 中选择 *Read and write*。

## 文件格式

归档 `.asf` 的逐字节格式见 [FORMAT.md](FORMAT.md)（英文）。

## 许可

MIT，见 [LICENSE](../LICENSE)。密码学实现来自
[Monocypher](https://monocypher.org)（CC0-1.0 / BSD-2-Clause 双许可）。