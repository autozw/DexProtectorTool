# DexProtector 静态 DEX 解密分析报告

> 文档中的第 19 节是用于解释流程的核心代码，不是当前工具入口。仓库中的完整自动推导实现位于 `inference.py`、`bootstrap.py`、`engine.py`，请从 `app.py` 运行；实际部署采用 README 的精简依赖安装命令。

日期：2026-11-08

本报告对应当前 IDA 打开的样本：

```text
E:\pp\vvccbb\8888\new\libdexprotector_dump_plaintext.so
架构：ARM64
IDA 基址：0
映射大小：0x98000
SHA-256：
613a48998e6b89ddd5f817801380e8e5146c94d614677c9705e526c07c6e9fe5
```

这个 IDA 文件是处理过字符串的代码段 dump，缺少后面的部分配置区。**它适合分析函数，不应直接用于计算 Native 完整性摘要或提取完整密钥材料。**完整解密需要原始 `libdexprotector.so`，从它重新解封装内部镜像。

下文地址分为两类：

- **外层地址**：原始 SO 内 loader 的地址。
- **内部地址**：解封装后的 Native 镜像地址，与当前 IDA 的代码地址对应。

已经验证的流程覆盖 VCB、PGBank 3.4.5、SmartBanking 5.3.14 三个构建。自动化实现不应保存三个 App 的配置或最终密钥，而应从每次输入中重新识别、提取和验证参数。

## 1. 完整解密链

```text
APK / APKS
  │
  ├─ 找到主 APK
  ├─ 找到 ARM64 libdexprotector.so
  │
  ▼
识别外层 loader
  │
  ├─ ELF / PT_LOAD 解析
  ├─ 定位解封装函数
  ├─ Unicorn 仿真
  ├─ 解密内部头部、段描述、段数据
  ├─ 解压并校验内部段
  └─ 检查返回状态
  │
  ▼
完整 Native 镜像
  │
  ├─ ARM64 常量与地址传播
  ├─ 找到 salt / IKM
  ├─ 找到签名包裹材料
  ├─ 找到完整性包裹材料
  ├─ 找到 HKDF info 候选
  ├─ 找到主密钥检查值
  └─ 找到 Java seed 候选
  │
  ▼
派生目录阶段主密钥
  │
  ├─ HKDF-Extract
  ├─ APK 签名绑定
  ├─ 外层 classes*.dex 前缀绑定
  ├─ Native 完整性绑定
  └─ 主密钥检查
  │
  ▼
assets/assets.dat
  │
  ├─ ChaCha20-Poly1305 解密尾部目录
  ├─ 按目录定位数据块
  └─ ChaCha20-Poly1305 解密引导 DEX
  │
  ▼
解释引导代码
  │
  ├─ Native seed
  ├─ 外层 Application 字节替换方法
  ├─ 引导 DEX 整数运算
  └─ 更新主密钥
  │
  ▼
业务子密钥
  │
  ├─ HKDF-Expand
  ├─ ChaCha8 解密
  ├─ Zstandard 解压
  └─ 多 DEX 索引解析
  │
  ▼
DEX 导出
  │
  ├─ 边界检查
  ├─ data_off / data_size 修复
  ├─ SHA-1 修复
  ├─ Adler32 修复
  └─ 类、方法、全部指令验证
```

## 2. APK/APKS 输入处理

Java 层启动逻辑包含：

```java
System.loadLibrary("dexprotector");
```

实际 Native 库可能位于：

```text
普通 APK：
    lib/arm64-v8a/libdexprotector.so

APKS：
    base.apk
    split_config.arm64_v8a.apk
        └── lib/arm64-v8a/libdexprotector.so
```

输入处理需要取得主 APK、ARM64 原始 SO、`assets/assets.dat`、外层 `classes*.dex` 和 APK Signing Block。

这些输入必须配套。即使两个 App 使用同样的保护算法，它们的签名、配置、外层 DEX 和最终密钥也不同。

## 3. Native 解封装

原始 SO 的关键外层函数：

| 外层地址 | 功能 |
|---|---|
| `0x380` | 初始化入口 |
| `0x448` | `JNI_OnLoad` 包装 |
| `0x920` | 解封装状态／密钥生成逻辑 |
| `0x1298` | 内部镜像解封装主函数 |

加密载荷位于第四个 `PT_LOAD`。三个样本中的起点相同：

```text
文件偏移：0x3638
虚拟地址：0xF638
```

长度从 ELF 段表读取，不应写死。外层解封装包含：

```text
生成解密状态
→ 解密内部头部
→ 分配镜像内存
→ 解密段描述
→ 解密段内容
→ 解压
→ 检查长度与段校验
→ 返回镜像信息
```

本次解出的完整镜像为 `0xAC000` 字节。

自动定位可以利用解封装函数开头的输入长度检查特征，但必须继续验证：

- 内部头部、镜像长度、对齐和段数量是否合理。
- 动态表是否位于镜像内。
- 函数是否正常返回，返回值是否表示成功。

**仿真结束不等于解封装成功。**超时、异常停止、错误返回都不能当作有效镜像。

## 4. 自动提取派生参数

当前内部代码中的主要函数：

| 内部地址 | 功能 |
|---|---|
| `0x37AD8` | 主初始化流程 |
| `0x70500` | HKDF-Extract 包装 |
| `0x7054C` | HKDF-Expand 包装 |
| `0x7059C` | 混入新材料、更新主密钥 |
| `0x70640` | 更新主密钥并派生子密钥 |
| `0x6DAE0` | 签名绑定入口 |
| `0x6DB90` | APK Signing Block 材料处理 |
| `0x8BE48` | 外层 DEX 前缀绑定 |
| `0x120C4` | Native 完整性绑定 |
| `0x6E998` | 容器目录解密与解析 |
| `0x25AC8` | 引导 DEX 解密与加载 |
| `0x5ADA0` | 业务 DEX 容器解密 |

自动提取的基本方法是对 ARM64 指令做有限常量传播，处理 `ADR/ADRP`、`MOVZ/MOVK/MOVN`、寄存器 `MOV`、立即数 `ADD/SUB`、`STR/LDR`、栈上常量保存与 `BL` 调用参数快照。

在调用点观察 `X0～X7`、栈上的 8 字节常量、指向镜像数据区的地址，以及输入／输出长度。

初始派生调用具有如下参数形状：

```text
X0 = salt 地址
X1 = 32
X2 = IKM 地址
X3 = 64
X4 = 输出地址
```

Expand 调用常见形状：info 长度为 8 字节，输出长度为 4、44 或 64 字节。

提取出的只是候选参数。必须通过主密钥检查值、AEAD Tag 和业务容器结构确认，不能只凭函数外形直接接受。

## 5. HKDF 与密钥更新规则

底层采用 HMAC-SHA256、HKDF-Extract-SHA256 和 HKDF-Expand-SHA256。

```text
Extract(salt, IKM) = HMAC-SHA256(salt, IKM)

Expand(K, info, L):
    T0 = 空
    Ti = HMAC-SHA256(K, T(i-1) || info || uint8(i))
    返回 T1 || T2 || ... 的前 L 字节
```

`0x7059C` 的混入逻辑：

```text
Mix(K, data):
    salt = Expand(K, mix_info, 32)
    return Extract(salt, data)
```

当前 SO 的 `mix_info` 是 `LE64(0x07FFCFC433E03432)`。

`0x70640` 的分裂派生：

```text
T = Expand(K, info, 64)
K_next = T[0:32]
K_sub  = T[32:64]
```

`info` 是字节串，本次常量按 8 字节小端编码。密钥更新有严格顺序，中间主密钥与最终业务密钥不是同一个值。

## 6. 初始主密钥

当前 SO 的初始调用为：

```text
salt = image[0xA1B79 : 0xA1B99]
IKM  = image[0xA1B30 : 0xA1B70]
K0   = Extract(salt, IKM)
```

这些地址是当前样本的分析结果。自动实现应从调用参数恢复地址，而不是保存为 App 配置。

## 7. 签名绑定

路径：`0x6DAE0 → 0x6DB90`。

APK Signing Block 的条目 ID：

```text
v3：0xF05368C0
v2：0x7109871A
```

对已验证的单证书情况：

```text
cert_hash = SHA256(cert_DER)
KEK       = SHA256(cert_hash)
```

随后先混入签名包裹材料区域，再尝试 AES-KWP 解包：

```text
K = Mix(K, wrapped_material_region)
material = AES_KWP_Unwrap(KEK, wrapped_material)

解包成功：
    K = Mix(K, material)
```

当前构建的材料区域为六个 40 字节条目，共 240 字节。

AES-KWP 的完整性字段、长度字段和 padding 必须全部有效。解出“看起来随机的 32 字节”不算成功。

## 8. 外层 DEX 前缀绑定

调用链：`0x8BE48 → 0x8BF94`。

按配置顺序读取 `classes.dex`、`classes2.dex` 等文件，每个取前至多 `0x400` 字节：

```text
prefix = dex[0 : min(file_size, 1024)]
K = Mix(K, prefix)
```

如果 ZIP 条目被压缩，使用解压后的 DEX 内容。

| 构建 | 前缀绑定的 DEX 数量 |
|---|---:|
| VCB | 12 |
| PGBank | 5 |
| SmartBanking | 15 |

数量必须从当前输入推导。

## 9. Native 完整性绑定

函数：`0x120C4`。

```text
native_hash = SHA256(runtime_image[0:hash_length])
material = AES_KWP_Unwrap(native_hash, wrapped_native_material)
K = Mix(K, material)
```

当前 SO 的摘要覆盖长度为 `0x95660`。

外层 loader 在调用主流程前，会清零部分符号和重定位元数据。当前镜像对应范围为 `0x200 .. 0xA08`。

自动化实现应从动态表取得 `DT_SYMTAB`、`DT_STRTAB`、`DT_STRSZ`、`DT_JMPREL`、`DT_PLTRELSZ`、`DT_RELR`、`DT_RELRSZ`，据此复现清理范围后计算摘要。

不能使用原始 SO 文件摘要、字符串已改写的 IDA dump 摘要，或未复现清理行为的镜像摘要代替。

## 10. 主密钥检查

```text
check = Expand(K, check_info, 4)
```

将结果与当前配置中的检查值比较。当前 SO 的 info 为 `LE64(0x91A4FB076B659459)`。

这一检查确认初始材料、签名处理、DEX 前缀处理、Native 完整性材料与混入顺序是否一致。

绑定分支存在差异时，可以生成有限候选，但必须由检查值确认，不能跳过检查继续解密。

## 11. 容器目录解密

`assets/assets.dat` 尾部布局：

```text
[各类型数据块]
[目录密文 L 字节]
[16 字节 Tag]
[1 字节 L]
```

设长度为 N：

```text
L          = data[N-1]
ciphertext = data[N-17-L : N-17]
tag        = data[N-17 : N-1]
AAD        = data[N-1 : N]

M = Expand(K, directory_info, 44)
key   = M[0:32]
nonce = M[32:44]
```

使用 ChaCha20-Poly1305。当前 SO 的 directory info 为 `LE64(0x5D4E7CCFF0335568)`。

目录明文格式：

```text
ULEB128 条目数量

重复：
    uint8   类型
    ULEB128 数据长度
```

块偏移从文件开头累计。自动识别目录 info 时，只有 Tag 通过的候选才接受。

## 12. 引导 DEX 解密

当前构建的引导块类型为 9：

```text
[引导 DEX 密文][16 字节 Tag]

M = Expand(K, bootstrap_info, 44)
算法：ChaCha20-Poly1305
AAD：空
```

当前 SO 的 bootstrap info 为 `LE64(0x3045C9C1C2460B68)`。

对应实现：`0x7A98C → 0x7A7D4 → 0x16724`。`0x16724` 执行十次双轮，即 ChaCha20。

认证成功后还应检查 DEX magic、file_size、SHA-1、Adler32 和引导方法结构。

## 13. 引导代码参与业务密钥计算

Native 回调提供 32 字节 seed。当前 SO 的来源为 `0xA1AF8 .. 0xA1B18`。

自动化可以通过回调中连续读取 32 个字节的行为识别候选 seed 区域。

```text
Native seed
    ↓
外层 Application 的 byte[] → byte[] 方法
    ↓
查找表替换
    ↓
32 字节转换为 8 个小端 int32
    ↓
引导 DEX 的 XOR、加法、移位、旋转运算
    ↓
32 字节结果
    ↓
K = Mix(K, bootstrap_result)
```

必须保持 Java 的 32 位溢出、有符号 byte 读取、无符号右移 `>>>`、有符号条件比较和数组边界语义。不能把 Java `>>>` 直接写成 Python 对负整数的 `>>`。

## 14. 业务子密钥

```text
T = Expand(K, business_info, 64)
K_next = T[0:32]
K_sub  = T[32:64]

M = Expand(K_sub, 空 info, 44)
business_key   = M[0:32]
business_nonce = M[32:44]
```

当前 SO 的 business info 为 `LE64(0x873552BC11E8FF0E)`。

## 15. 业务块解密与解压

业务块使用 ChaCha8，key 为 32 字节、nonce 为 12 字节，初始 counter 为 0。

| 地址 | 功能 |
|---|---|
| `0x62A18` | 密钥流与异或处理 |
| `0x62CA8` | 四次双轮，即 ChaCha8 |
| `0x81890` | Zstandard 解压入口 |

解密后的格式：

```text
[4 字节小端解压长度]
[Zstandard 数据，magic = 28 B5 2F FD]
```

必须确认 magic、声明长度、实际解压长度和合法 DEX 索引。

轮数不确定时，可以针对支持的 ChaCha 轮数生成候选，再由完整结构验证确认；不能只凭 magic 匹配接受。

## 16. 多 DEX 提取

设解压容器长度为 N：

```text
dex_count  = LE32(container[N-36])
table_start = N-36-dex_count*4
偏移表      = LE32[dex_count]

dex_base = container + offset[i]
dex_size = LE32(dex_base + 0x20)
```

检查 DEX 头部、magic、file_size、整体范围及 map_list 边界。

多个 DEX 的节区在容器中交错分布，不是简单首尾拼接。导出范围可能重叠，所以输出文件总大小大于原容器并不必然表示错误。

## 17. DEX 修复

当前构建的业务 DEX 头部存在：

```text
data_size = 1
data_off  = file_size - 1
```

修复为：

```text
data_off  = map_list 中最早的数据项偏移
data_size = file_size - data_off
```

再按顺序更新：

```python
dex[12:32] = SHA1(dex[32:])
dex[8:12]  = LE32(Adler32(dex[12:]))
```

先 SHA-1，后 Adler32。本次保留稀疏布局，不修改方法指令，不重新排列所有数据项。

## 18. 完整验证标准

| 阶段 | 成功条件 |
|---|---|
| Native 解封装 | 镜像布局合理、段处理完成、函数正常返回成功状态 |
| 签名绑定 | AES-KWP 认证成功 |
| Native 完整性绑定 | 正确摘要对应的 AES-KWP 认证成功 |
| 主密钥 | 派生检查值与配置一致 |
| 容器目录 | ChaCha20-Poly1305 Tag 通过 |
| 引导 DEX | Tag、DEX 头部和校验通过 |
| 业务解密 | Zstandard magic、长度、解压结果一致 |
| DEX 提取 | magic、file_size、map_list 边界正确 |
| DEX 修复 | SHA-1、Adler32 通过 |
| 内容验证 | 类、方法、全部指令可解析，指令长度与声明一致 |

“提取到 key”与“key 已验证”是不同状态。报告应记录每个 key 对应的验证环节。

## 19. Python 核心实现

以下代码实现密码学、容器认证、业务解密、DEX 修复与完整验证部分。它没有预置 App 名称、SO 指纹或最终 key，但**不是包含 Native 自动推导的完整 CLI**。

前半段的 ELF loader 识别、Unicorn 解封装、ARM64 参数传播、签名与完整性材料处理、引导解释器，需要向这些函数提供本次输入实际分析出的参数，不能以三个样本的字典代替。

安装依赖：

```powershell
python -m pip install --no-deps -r requirements.txt
```

```python
from __future__ import annotations

import hashlib
import hmac
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import zstandard as zstd
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap_with_padding
from loguru import logger

logger.remove()

from androguard.core.dex import DEX


MAX_CONTAINER = 512 * 1024 * 1024


class DecryptionError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DecryptionError(message)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def le64(value: int) -> bytes:
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.digest(salt, ikm, "sha256")


def expand(key: bytes, info: bytes, length: int) -> bytes:
    require(0 <= length <= 255 * 32, "HKDF 输出长度无效")
    previous = b""
    result = bytearray()

    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.digest(
            key,
            previous + info + bytes([counter]),
            "sha256",
        )
        result.extend(previous)

    return bytes(result[:length])


def mix(key: bytes, data: bytes, mix_info: int) -> bytes:
    salt = expand(key, le64(mix_info), 32)
    return extract(salt, data)


def unwrap_material(kek: bytes, wrapped: bytes) -> bytes:
    require(len(kek) in (16, 24, 32), "AES KEK 长度无效")
    require(
        len(wrapped) >= 16 and len(wrapped) % 8 == 0,
        "AES-KWP 输入长度无效",
    )
    return aes_key_unwrap_with_padding(kek, wrapped)


def read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    for shift in range(0, 35, 7):
        require(offset < len(data), "ULEB128 越界")
        value = data[offset]
        offset += 1
        result |= (value & 0x7F) << shift
        if value < 0x80:
            require(result <= 0xFFFFFFFF, "ULEB128 超过 uint32")
            return result, offset
    raise DecryptionError("ULEB128 过长")


@dataclass(frozen=True)
class ContainerBlock:
    type_id: int
    offset: int
    length: int


def decrypt_directory(
    assets: bytes,
    master_key: bytes,
    info_candidates: list[int],
) -> tuple[int, dict[int, ContainerBlock]]:
    require(len(assets) > 17, "容器过短")
    directory_length = assets[-1]
    require(0 < directory_length <= len(assets) - 17, "目录长度异常")
    ciphertext_and_tag = assets[-17 - directory_length:-1]
    aad = assets[-1:]
    authenticated = []

    for info in dict.fromkeys(info_candidates):
        material = expand(master_key, le64(info), 44)
        try:
            plaintext = ChaCha20Poly1305(material[:32]).decrypt(
                material[32:], ciphertext_and_tag, aad,
            )
        except InvalidTag:
            continue
        authenticated.append((info, plaintext))

    require(
        len(authenticated) == 1,
        f"目录认证候选数量异常：{len(authenticated)}",
    )
    info, plaintext = authenticated[0]
    count, cursor = read_uleb128(plaintext, 0)
    require(count <= 255, "目录条目数量异常")
    payload_limit = len(assets) - 17 - directory_length
    blocks = {}
    offset = 0

    for _ in range(count):
        require(cursor < len(plaintext), "目录条目截断")
        type_id = plaintext[cursor]
        length, cursor = read_uleb128(plaintext, cursor + 1)
        require(type_id not in blocks, "目录类型重复")
        require(length <= payload_limit - offset, "目录数据块越界")
        blocks[type_id] = ContainerBlock(type_id, offset, length)
        offset += length

    require(cursor == len(plaintext), "目录存在未解析数据")
    return info, blocks


def verify_dex_checksums(data: bytes) -> None:
    require(len(data) >= 112, "DEX 过短")
    require(data[:4] == b"dex\n", "DEX magic 无效")
    declared_size = struct.unpack_from("<I", data, 32)[0]
    header_size = struct.unpack_from("<I", data, 36)[0]
    endian = struct.unpack_from("<I", data, 40)[0]
    require(declared_size == len(data), "DEX file_size 不匹配")
    require(header_size == 112, "DEX header_size 不支持")
    require(endian == 0x12345678, "DEX 字节序不支持")
    require(
        hashlib.sha1(data[32:]).digest() == data[12:32],
        "DEX SHA-1 不匹配",
    )
    require(
        zlib.adler32(data[12:]) == struct.unpack_from("<I", data, 8)[0],
        "DEX Adler32 不匹配",
    )


def decrypt_bootstrap(
    assets: bytes,
    blocks: dict[int, ContainerBlock],
    master_key: bytes,
    info_candidates: list[int],
) -> tuple[int, int, bytes]:
    matches = []
    for block in blocks.values():
        if not 128 <= block.length <= 1024 * 1024:
            continue
        encrypted = assets[block.offset:block.offset + block.length]
        for info in dict.fromkeys(info_candidates):
            material = expand(master_key, le64(info), 44)
            try:
                plaintext = ChaCha20Poly1305(material[:32]).decrypt(
                    material[32:], encrypted, b"",
                )
            except InvalidTag:
                continue

            try:
                verify_dex_checksums(plaintext)
                dex = DEX(plaintext)
                candidates = [
                    method
                    for cls in dex.get_classes()
                    for method in cls.get_methods()
                    if method.get_descriptor() == "([I)V"
                    and method.get_code() is not None
                ]
                require(len(candidates) == 1, "引导方法结构不明确")
            except Exception:
                continue
            matches.append((block.type_id, info, plaintext))

    require(len(matches) == 1, f"引导 DEX 候选数量异常：{len(matches)}")
    return matches[0]


def chacha_xor(
    key: bytes,
    nonce: bytes,
    data: bytes,
    rounds: int,
    counter: int = 0,
) -> bytes:
    require(len(key) == 32, "ChaCha key 必须为 32 字节")
    require(len(nonce) == 12, "ChaCha nonce 必须为 12 字节")
    require(rounds in (8, 12, 20), "ChaCha 轮数不支持")
    block_count = (len(data) + 63) // 64
    require(0 <= counter and counter + block_count <= 2**32, "ChaCha counter 溢出")
    if not data:
        return b""

    initial = np.zeros((16, block_count), dtype=np.uint32)
    initial[:4] = np.frombuffer(b"expand 32-byte k", dtype="<u4")[:, None]
    initial[4:12] = np.frombuffer(key, dtype="<u4")[:, None]
    initial[12] = np.arange(counter, counter + block_count, dtype=np.uint32)
    initial[13:] = np.frombuffer(nonce, dtype="<u4")[:, None]
    state = initial.copy()

    def quarter_round(a: int, b: int, c: int, d: int) -> None:
        state[a] += state[b]
        state[d] ^= state[a]
        state[d] = (state[d] << 16) | (state[d] >> 16)
        state[c] += state[d]
        state[b] ^= state[c]
        state[b] = (state[b] << 12) | (state[b] >> 20)
        state[a] += state[b]
        state[d] ^= state[a]
        state[d] = (state[d] << 8) | (state[d] >> 24)
        state[c] += state[d]
        state[b] ^= state[c]
        state[b] = (state[b] << 7) | (state[b] >> 25)

    for _ in range(rounds // 2):
        for indices in (
            (0, 4, 8, 12), (1, 5, 9, 13),
            (2, 6, 10, 14), (3, 7, 11, 15),
            (0, 5, 10, 15), (1, 6, 11, 12),
            (2, 7, 8, 13), (3, 4, 9, 14),
        ):
            quarter_round(*indices)

    stream = (state + initial).T.astype("<u4").tobytes()[:len(data)]
    return (
        np.frombuffer(data, dtype=np.uint8)
        ^ np.frombuffer(stream, dtype=np.uint8)
    ).tobytes()


def parse_dex_offsets(container: bytes) -> list[int]:
    require(len(container) >= 112, "业务容器过短")
    count = struct.unpack_from("<I", container, len(container) - 36)[0]
    require(1 <= count <= 128, "DEX 数量异常")
    table_start = len(container) - 36 - count * 4
    require(table_start >= 0, "DEX 索引表越界")
    offsets = list(struct.unpack_from(f"<{count}I", container, table_start))

    for offset in offsets:
        require(offset + 112 <= len(container), "DEX 头部越界")
        require(container[offset:offset + 4] == b"dex\n", "索引未指向 DEX")
        size = struct.unpack_from("<I", container, offset + 32)[0]
        require(112 <= size <= len(container) - offset, "DEX file_size 越界")
    return offsets


def find_business_container(
    assets: bytes,
    blocks: dict[int, ContainerBlock],
    master_key: bytes,
    mix_info: int,
    java_results: dict[int, bytes],
    business_info_candidates: list[int],
) -> tuple[bytes, dict]:
    """java_results：seed 地址 -> 当前引导代码计算出的 32 字节结果。"""
    for seed_address, java_result in java_results.items():
        require(len(java_result) == 32, "Java 派生结果长度异常")
        updated_key = mix(master_key, java_result, mix_info)

        for info in dict.fromkeys(business_info_candidates):
            split = expand(updated_key, le64(info), 64)
            subkey = split[32:]
            material = expand(subkey, b"", 44)
            key, nonce = material[:32], material[32:]

            for block in blocks.values():
                if block.length < 8:
                    continue
                encrypted = assets[block.offset:block.offset + block.length]
                for rounds in (8, 12, 20):
                    prefix = chacha_xor(key, nonce, encrypted[:8], rounds)
                    expected = struct.unpack_from("<I", prefix)[0]
                    if prefix[4:8] != b"\x28\xb5\x2f\xfd":
                        continue
                    if not 112 <= expected <= MAX_CONTAINER:
                        continue

                    plaintext = chacha_xor(key, nonce, encrypted, rounds)
                    try:
                        frame_size = zstd.frame_content_size(plaintext[4:])
                        if frame_size not in (expected, zstd.CONTENTSIZE_UNKNOWN):
                            continue
                        container = zstd.ZstdDecompressor().decompress(
                            plaintext[4:], max_output_size=expected,
                        )
                        if len(container) != expected:
                            continue
                        parse_dex_offsets(container)
                    except (zstd.ZstdError, DecryptionError, struct.error):
                        continue

                    evidence = {
                        "seed_address": hex(seed_address),
                        "business_info": hex(info),
                        "business_type": block.type_id,
                        "rounds": rounds,
                        "counter": 0,
                        "java_result": java_result.hex(),
                        "post_java_key": updated_key.hex(),
                        "business_subkey": subkey.hex(),
                        "business_key": key.hex(),
                        "business_nonce": nonce.hex(),
                        "container_size": len(container),
                    }
                    return container, evidence

    raise DecryptionError("所有业务密钥候选均未通过解压与 DEX 索引验证")


def repair_dex(data: bytes) -> bytes:
    require(len(data) >= 112, "DEX 过短")
    require(data[:4] == b"dex\n", "DEX magic 无效")
    dex = bytearray(data)
    require(struct.unpack_from("<I", dex, 32)[0] == len(dex), "DEX file_size 不匹配")
    require(struct.unpack_from("<I", dex, 36)[0] == 112, "DEX header_size 不支持")
    require(struct.unpack_from("<I", dex, 40)[0] == 0x12345678, "DEX 字节序不支持")

    map_offset = struct.unpack_from("<I", dex, 52)[0]
    require(map_offset + 4 <= len(dex), "map_list 越界")
    map_count = struct.unpack_from("<I", dex, map_offset)[0]
    require(0 < map_count <= 256, "map_list 数量异常")
    require(map_offset + 4 + map_count * 12 <= len(dex), "map_list 内容越界")
    data_offsets = []

    for index in range(map_count):
        item_type, unused, count, offset = struct.unpack_from(
            "<HHII", dex, map_offset + 4 + index * 12,
        )
        require(offset < len(dex), "map 项偏移越界")
        if item_type >= 0x1000:
            data_offsets.append(offset)

    require(data_offsets, "DEX 缺少数据区")
    data_offset = min(data_offsets)
    struct.pack_into("<II", dex, 104, len(dex) - data_offset, data_offset)
    dex[12:32] = hashlib.sha1(dex[32:]).digest()
    struct.pack_into("<I", dex, 8, zlib.adler32(dex[12:]))
    result = bytes(dex)
    verify_dex_checksums(result)
    return result


def verify_dex_content(data: bytes) -> dict:
    verify_dex_checksums(data)
    dex = DEX(data)
    classes = dex.get_classes()
    method_count = code_count = instruction_count = 0

    for cls in classes:
        for method in cls.get_methods():
            method_count += 1
            code = method.get_code()
            if code is None:
                continue
            code_count += 1
            decoded_bytes = 0
            for instruction in method.get_instructions():
                name = instruction.get_name()
                require(
                    name not in ("invalid", "unused"),
                    f"无效指令：{cls.get_name()}->{method.get_name()}",
                )
                length = instruction.get_length()
                require(length > 0, "指令长度无效")
                decoded_bytes += length
                instruction_count += 1
            require(
                decoded_bytes == code.get_insns_size() * 2,
                f"方法长度不匹配：{cls.get_name()}->{method.get_name()}",
            )

    return {
        "size": len(data),
        "sha256": sha256(data).hex(),
        "classes": len(classes),
        "methods": method_count,
        "code_items": code_count,
        "instructions": instruction_count,
        "sha1_ok": True,
        "adler32_ok": True,
        "content_ok": True,
    }


def export_dexes(
    container: bytes,
    bootstrap: bytes,
    output: Path,
) -> list[dict]:
    output.mkdir(parents=True, exist_ok=True)
    offsets = parse_dex_offsets(container)
    validated = []

    for index, offset in enumerate(offsets):
        size = struct.unpack_from("<I", container, offset + 32)[0]
        original = container[offset:offset + size]
        repaired = repair_dex(original)
        statistics = verify_dex_content(repaired)
        name = f"protected_{index:02d}.dex"
        statistics.update({
            "name": name,
            "container_offset": offset,
            "original_sha256": sha256(original).hex(),
            "kind": "business" if statistics["methods"] else "fallback",
        })
        validated.append((name, repaired, statistics))

    bootstrap_stats = verify_dex_content(bootstrap)
    bootstrap_stats.update({"name": "bootstrap.dex", "kind": "bootstrap"})
    validated.append(("bootstrap.dex", bootstrap, bootstrap_stats))

    # 全部验证成功后再发布输出。
    for name, data, _ in validated:
        destination = output / name
        require(not destination.exists(), f"输出已存在：{destination}")

    for name, data, _ in validated:
        (output / name).write_bytes(data)

    return [statistics for _, _, statistics in validated]
```

### 实现边界

以上 Python 是报告中的密码学与容器处理核心，不包含前半段自动分析器，也不包含命令行入口。`export_dexes` 为便于展示，在发布前保留所有已验证的 DEX，处理交错布局的大样本时内存开销较高；实际工具可改为临时文件中转。

完整自动化仍需要 ELF loader 识别、Unicorn 解封装、ARM64 参数传播、签名与完整性材料处理，以及引导解释器。Android 项目 `D:\tuoyifu` 中，这些部分分别由 `NativeUnpacker`、`A64Scan`、`NativeAnalysis`、`BootstrapDex`、`DexProtectorEngine` 承担。

不能省略前半段后仍宣称“Python 全流程自动解密”。

## 20. 密钥与分析报告导出字段

`keys.json` 建议包含：

```text
salt
IKM
initial_key

certificate_kek
signature_unwrapped_material
key_after_signature
key_after_dex_prefix

native_digest
native_unwrapped_material
master_key
master_check

directory_info
directory_key
directory_nonce

bootstrap_info
bootstrap_key
bootstrap_nonce

java_seed_address
java_seed
java_result

post_java_key
business_info
business_subkey
business_key
business_nonce
counter
rounds
```

`analysis.json` 建议包含：

```text
输入文件摘要
Native loader 入口
载荷位置和长度
镜像大小、段数量、返回状态

推导出的材料地址
候选 info 数量
候选 seed 数量
最终通过验证的候选

每个验证阶段的状态
失败阶段与错误原因

DEX 名称和文件大小
修复前后摘要
类数、方法数、代码项数量、指令数量
```

## 21. 自动推导的边界

当前实现识别的是这类 ARM64 loader、HKDF、AES-KWP、ChaCha、Zstandard 结构族。它不依赖三个 App 的配置，但不等于任意 DexProtector 版本、任意编译布局和任意引导指令都已支持。

无法唯一定位参数或无法通过认证时，应明确报告失败环节，不回退到旧样本参数。
