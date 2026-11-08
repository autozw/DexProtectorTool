# DexProtectorTool

Windows Python 离线 DEX 解密工具。选择 APK/APKS、保存路径，点击“开始解密”；或选择“仅提取密钥”。

当前版本从输入 ELF 解封装 Native 镜像，分析 ARM64 调用参数，解释引导 DEX，通过认证和数据结构检查筛选派生参数。没有 App 包名白名单、SO 哈希放行表、三个样本的预解析配置或内置最终密钥。

## 安装与启动

推荐 Python 3.12 x64，包含 Tcl/Tk。

1. 完整下载仓库。
2. 首次运行 `install.bat` 安装精简依赖。
3. 双击 `start.bat`。
4. 选择 APK/APKS、保存目录，然后开始。

启动失败会保留控制台，并写入 `startup.log`。批处理使用 Windows CRLF 换行。

单独 APK 没有 ARM64 Native 库时，可指定补充 SO/ABI 分包。工具也会检查 APK 同目录的 `libdexprotector.so` 和 `split_config.arm64_v8a.apk`。APKS 自动读取主包和 ABI 分包。

### 不安装 Frida

工具只使用 Androguard 的离线 DEX 解析模块，精简安装不会安装其 Frida、IPython、Matplotlib、数据库或 NetworkX 依赖。所需导入依赖已明确列在 requirements.txt。

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --no-deps -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

必须保留 `--no-deps`，否则 pip 会补装 Androguard 完整工具链。此环境仅用于本工具；`pip check` 会提示 Androguard 声明但本工具不使用的依赖未安装。实际可用性通过导入测试、单元测试和真实样本回归验证。

## 自动推导流程

1. 根据 ARM64 loader 指令结构定位函数，从 ELF 段表取得 payload。
2. Unicorn 离线仿真，自动识别镜像头部、动态表，并检查返回状态。
3. 常量/地址传播，提取 salt、IKM、包裹材料、info、检查值及 seed 候选。
4. 解析 APK 签名和外层 DEX 前缀，认证 AES-KWP 材料并检查主密钥。
5. ChaCha20-Poly1305 认证目录及引导 DEX。
6. 受限 Dalvik 解释器执行当前输入中的整数/数组变换。
7. 筛选业务 info、seed 和 ChaCha 8/12/20 轮，要求 Zstandard 长度与多 DEX 索引有效。
8. 提取并修复 DEX，验证 SHA-1、Adler32、类、方法及全部指令长度。

## 输出

每次操作创建独立结果目录，不覆盖已有结果。

| 文件 | 内容 |
|---|---|
| `native_unpacked.bin` | 从当前输入实际解封装的 Native 镜像 |
| `keys.json` | salt/IKM、阶段密钥、认证成功的材料、info、key/nonce/counter/rounds |
| `analysis.json` | 识别地址、候选参数、验证证据、错误阶段、输出统计 |
| `manifest.json` | 结果状态与文件哈希、类/方法/指令统计 |
| `protected_*.dex` | 完整解密时输出的业务/备用类 DEX |
| `bootstrap.dex` | 引导 DEX |
| `运行日志.txt` | 进度和异常信息 |

“仅提取密钥”仍验证业务解密、解压和 DEX 索引，但不导出或逐方法验证业务 DEX；报告状态为 `keys_verified`。失败时输出的部分候选不表示整体成功。

## 命令行

```powershell
python app.py --cli --input "D:\samples\sample.apks" --output "D:\results"
python app.py --cli --input "D:\samples\base.apk" --supplement "D:\samples\libdexprotector.so" --output "D:\results"
python app.py --cli --keys-only --input "D:\samples\sample.apks" --output "D:\keys"
```

输出 JSON 事件。退出码 0 成功、1 失败、2 取消。取消在阶段及验证循环中响应，仿真调用有执行预算。

## 结构与验证

| 文件 | 职责 |
|---|---|
| app.py | Tkinter 界面、CLI、后台工作进程、取消 |
| launcher.py | 启动错误与原生异常日志 |
| engine.py | 输入处理、认证派生、解密、导出和验证 |
| inference.py | ELF/loader 识别、Unicorn 仿真、ARM64 参数推导 |
| bootstrap.py | 有步数上限的 Dalvik 整数/数组解释器 |
| crypto_core.py | HKDF/HMAC、Mix、ChaCha |

验证记录见 [验证记录.md](验证记录.md)，详细技术分析见 [DexProtector_静态DEX解密分析报告.md](DexProtector_静态DEX解密分析报告.md)。

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

## 支持边界

自动推导覆盖当前实现的 ARM64 loader、HKDF、AES-KWP、ChaCha、Zstandard 结构族，不等于通用支持任意保护版本。候选不唯一、布局不匹配、引导指令未实现或认证失败时明确停止，没有旧配置回退。

当前已回归 VCB、PGBank 3.4.5、SmartBanking 5.3.14，但这三个名称只记录测试覆盖，不控制放行。

仅处理主 APK 中的 DexProtector 容器；未合并其他功能分包代码。保留稀疏 DEX 布局，内存峰值可能较高。未验证重打包安装，也未解除业务内部其他运行时保护。

## 随仓库保存的分析样本

按仓库所有者要求附带原始 `libdexprotector.so`、`libdexprotector_dump_plaintext.so` 和 `libdexprotector.so_anon_0x767c6d8000_1794122114.elf`，供对应报告复核。它们不作为自动推导的预置配置，实际任务从所选输入取得 SO。

虚拟环境、缓存、运行日志及运行生成的 DEX/密钥文件不进入版本控制。未指定开源许可证。
