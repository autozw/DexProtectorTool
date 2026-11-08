"""Offline recovery using inferred ARM64 parameters and authenticated candidate selection."""
from pathlib import Path
import hashlib
import io
import json
import re
import shutil
import struct
import tempfile
import time
import zipfile
import zlib
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap_with_padding, InvalidUnwrap
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import zstandard
from loguru import logger
logger.remove()
from androguard.core.dex import DEX
from crypto_core import sha, extract, expand, le, mix, chacha
from inference import unpack, infer, InferenceError
from bootstrap import derive_results
LIMIT = 512 * 1024 * 1024
class RecoveryError(Exception):
    """An actionable input or compatibility error."""
class Cancelled(Exception):
    """Cancellation requested by the GUI."""

def require(condition, message):
    if not condition:
        raise RecoveryError(message)

def read_entry(z, name):
    info = z.getinfo(name)
    require(info.file_size <= LIMIT, f'文件过大：{name}')
    return z.read(info)

def native_from_zip(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        name = 'lib/arm64-v8a/libdexprotector.so'
        return read_entry(z, name) if name in z.namelist() else None

def inputs(path, supplement, check):
    require(path.suffix.lower() in ('.apk', '.apks'), '请选择 APK 或 APKS 文件。')
    require(path.stat().st_size <= 2 * 1024**3, '输入文件超过 2 GiB。')
    native = None
    if path.suffix.lower() == '.apks':
        with zipfile.ZipFile(path) as outer:
            names = [n for n in outer.namelist() if n.lower().endswith('.apk')]
            require(len(names) <= 500, 'APKS 分包数量异常。')
            candidates = [n for n in names if Path(n).name in ('base.apk', 'base-master.apk')]
            require(len(candidates) == 1, '无法唯一识别 base.apk；请导入主 APK，并补充 ARM64 SO。')
            base = read_entry(outer, candidates[0])
            native = native_from_zip(base)
            for name in sorted(names, key=lambda n: 'arm64' not in n.lower()):
                check()
                if native is not None:
                    break
                if name != candidates[0]:
                    native = native_from_zip(read_entry(outer, name))
    else:
        base = path.read_bytes()
        native = native_from_zip(base)
    if native is None:
        alternatives = [supplement] if supplement else [
            path.parent / 'libdexprotector.so', path.parent / 'split_config.arm64_v8a.apk']
        for p in alternatives:
            if p and p.is_file():
                require(p.stat().st_size <= LIMIT, '补充文件过大。')
                raw = p.read_bytes()
                native = native_from_zip(raw) if p.suffix.lower() == '.apk' else raw
                if native is not None:
                    break
    require(native is not None, 'APK 缺少 ARM64 libdexprotector.so。请导入完整 APKS，或选择“补充 SO / ABI 分包”。')
    fingerprint = sha(native).hex()
    require(native[:4] == b'\x7fELF', 'Native 文件不是 ELF。')
    with zipfile.ZipFile(io.BytesIO(base)) as z:
        require('assets/assets.dat' in z.namelist(), 'APK 中没有 assets/assets.dat。')
        assets = read_entry(z, 'assets/assets.dat')
        dexes = {n: read_entry(z, n) for n in z.namelist() if re.fullmatch(r'classes(?:\d+)?\.dex', n)}
    require(bool(dexes), 'APK 中没有外层 DEX。')
    return base, native, assets, dexes, fingerprint


def lp(data, pos=0):
    require(0 <= pos <= len(data)-4, '签名字段越界。')
    length = struct.unpack_from('<I', data, pos)[0]
    require(length <= len(data)-pos-4, '签名长度异常。')
    return data[pos+4:pos+4+length], pos+4+length

def signing(data):
    # Match the terminal EOCD, rather than a signature appearing in its comment.
    end = len(data)
    while True:
        eocd = data.rfind(b'PK\x05\x06', max(0, len(data)-65557), end)
        require(eocd >= 0, 'APK ZIP 目录无效。')
        if eocd+22 <= len(data) and eocd+22+struct.unpack_from('<H', data, eocd+20)[0] == len(data):
            break
        end = eocd
    cd = struct.unpack_from('<I', data, eocd+16)[0]
    require(24 <= cd <= eocd and data[cd-16:cd] == b'APK Sig Block 42', '未找到 APK v2/v3 签名块。')
    size = struct.unpack_from('<Q', data, cd-24)[0]
    require(24 <= size <= cd-8, 'APK 签名块长度异常。')
    require(struct.unpack_from('<Q', data, cd-size-8)[0] == size, 'APK 签名块首尾长度不一致。')
    pos, entries = cd-size, {}
    while pos < cd-24:
        require(pos+12 <= cd-24, 'APK 签名条目不完整。')
        length, typ = struct.unpack_from('<QI', data, pos)
        require(4 <= length <= cd-24-pos-8, 'APK 签名条目越界。')
        entries[typ] = data[pos+12:pos+8+length]
        pos += 8+length
    return entries

def master_key(image, base, dexes, p, keys, evidence):
    initial = extract(p.salt, p.ikm)
    keys.update(salt=p.salt.hex(), ikm=p.ikm.hex(), initial_key=initial.hex(),
                native_digest=p.native_digest.hex(), native_unwrapped=p.native_material.hex())
    entries = signing(base)
    bound = None
    for typ in (0xf05368c0, 0x7109871a):
        if typ not in entries:
            continue
        signers, _ = lp(entries[typ]); signer, consumed = lp(signers)
        require(consumed == len(signers), '尚未适配多 signer APK。')
        signed, _ = lp(signer); _, pos = lp(signed); certseq, _ = lp(signed, pos)
        hashes, pos = [], 0
        while pos < len(certseq):
            cert, pos = lp(certseq, pos); hashes.append(sha(cert))
        require(hashes, '签名证书为空。')
        kek = sha(b''.join(sorted(hashes)))
        candidate, unwrapped = mix(initial, p.wraps, p.mix_info), {}
        for offset in range(0, len(p.wraps), 40):
            try:
                value = aes_key_unwrap_with_padding(kek, p.wraps[offset:offset+40])
            except InvalidUnwrap:
                continue
            candidate = mix(candidate, value, p.mix_info)
            unwrapped[str(offset)] = value.hex()
        if unwrapped:
            bound = candidate
            keys.update(certificate_kek=kek.hex(), signature_unwrapped=unwrapped)
            break
    matches = {}
    for use_signature in (True, False):
        if use_signature and bound is None:
            continue
        for use_prefixes in (True, False):
            key = bound if use_signature else initial
            if use_prefixes:
                for i in range(1, p.dex_count+1):
                    name = f'classes{i if i>1 else ""}.dex'
                    require(name in dexes, f'缺少 {name}')
                    key = mix(key, dexes[name][:1024], p.mix_info)
            key = mix(key, p.native_material, p.mix_info)
            if expand(key, le(p.check_info), 4) == p.check_value:
                matches.setdefault(key, (use_signature, use_prefixes))
    require(len(matches) == 1, '主密钥检查未唯一通过，不能继续。')
    key, flags = next(iter(matches.items()))
    evidence.update(signature_binding=flags[0], dex_prefix_binding=flags[1], dex_prefix_count=p.dex_count,
                    signature_unwrap_passed=bound is not None, native_unwrap_passed=True, master_check_passed=True)
    keys.update(master_key=key.hex(), master_check=p.check_value.hex(), mix_info=hex(p.mix_info), check_info=hex(p.check_info))
    return key

def uleb(data, pos):
    value = 0
    for shift in range(0, 35, 7):
        require(pos < len(data), '目录 ULEB128 越界。')
        byte = data[pos]; pos += 1; value |= (byte & 127)<<shift
        if byte < 128:
            return value, pos
    raise RecoveryError('目录 ULEB128 过长。')

def decrypt_blocks(key, assets, p, keys, evidence):
    require(len(assets)>17 and 0<assets[-1]<=len(assets)-17, '容器尾部目录长度异常。')
    length=assets[-1]; candidates=[]
    for info in p.expand44:
        material=expand(key,le(info),44)
        try:
            plain=ChaCha20Poly1305(material[:32]).decrypt(material[32:],assets[-17-length:-1],assets[-1:])
        except InvalidTag:
            continue
        candidates.append((info,material,plain))
    require(len(candidates)==1, '目录 Tag 未唯一通过。')
    info,material,directory=candidates[0]
    keys.update(directory_info=hex(info),directory_key=material[:32].hex(),directory_nonce=material[32:].hex())
    evidence['directory_tag_passed']=True
    count,pos=uleb(directory,0);require(count<=255,'目录条目数量异常。')
    blocks={};offset=0
    for _ in range(count):
        require(pos<len(directory),'目录截断。')
        typ=directory[pos];size,pos=uleb(directory,pos+1)
        require(typ not in blocks and offset+size<=len(assets)-17-length,'目录重复或越界。')
        blocks[typ]=assets[offset:offset+size];offset+=size
    require(pos==len(directory),'目录尾部未解析。')
    boots=[]
    for typ,block in blocks.items():
        if not 128<=len(block)<=1024*1024:
            continue
        for info in p.expand44:
            material=expand(key,le(info),44)
            try:
                plain=ChaCha20Poly1305(material[:32]).decrypt(material[32:],block,b'')
            except InvalidTag:
                continue
            if len(plain)<112 or plain[:4]!=b'dex\n':
                continue
            require(len(plain)==struct.unpack_from('<I',plain,32)[0]
                    and hashlib.sha1(plain[32:]).digest()==plain[12:32]
                    and zlib.adler32(plain[12:])==struct.unpack_from('<I',plain,8)[0], '引导 DEX 校验失败。')
            boots.append((typ,info,material,plain))
    require(len(boots)==1,'引导 DEX 未唯一认证定位。')
    typ,info,material,bootstrap=boots[0]
    evidence.update(bootstrap_type=typ,bootstrap_tag_passed=True)
    keys.update(bootstrap_info=hex(info),bootstrap_key=material[:32].hex(),bootstrap_nonce=material[32:].hex())
    return blocks,bootstrap

def container_offsets(body):
    require(len(body)>=112, '业务容器过短。')
    count=struct.unpack_from('<I',body,len(body)-36)[0]
    require(1<=count<=128 and count*4+36<=len(body),'DEX 索引异常。')
    offsets=struct.unpack_from(f'<{count}I',body,len(body)-36-count*4)
    for offset in offsets:
        require(offset+112<=len(body) and body[offset:offset+4]==b'dex\n','DEX 头部越界或 magic 错误。')
        length=struct.unpack_from('<I',body,offset+32)[0]
        require(112<=length<=len(body)-offset,'DEX 长度越界。')
    return offsets

def decrypt_business(image, blocks, key, bootstrap, dexes, p, keys, evidence, check):
    results=derive_results(image,bootstrap,dexes,p.seeds,check)
    matches=[]
    for address,result in results.items():
        updated=mix(key,result,p.mix_info)
        for info in p.expand64:
            subkey=expand(updated,le(info),64)[32:];material=expand(subkey,b'',44)
            for typ,block in blocks.items():
                if len(block)<8:
                    continue
                for rounds in (8,12,20):
                    check()
                    prefix=chacha(material[:32],material[32:],block[:8],rounds)
                    length=struct.unpack_from('<I',prefix)[0]
                    if prefix[4:8]!=bytes.fromhex('28b52ffd') or not 112<=length<=LIMIT:
                        continue
                    plain=chacha(material[:32],material[32:],block,rounds)
                    try:
                        frame=zstandard.frame_content_size(plain[4:])
                        if frame not in (length,zstandard.CONTENTSIZE_UNKNOWN):
                            continue
                        body=zstandard.ZstdDecompressor().decompress(plain[4:],max_output_size=length)
                        require(len(body)==length,'解压长度不一致。')
                        container_offsets(body)
                    except (zstandard.ZstdError,RecoveryError):
                        continue
                    matches.append((body,address,result,updated,info,subkey,material,typ,rounds))
                    require(len(matches)<=1,'业务密钥候选不唯一。')
    require(len(matches)==1,'没有候选 key / nonce / 轮数通过业务容器验证。')
    body,address,result,updated,info,subkey,material,typ,rounds=matches[0]
    keys.update(java_seed=image[address:address+32].hex(),java_result=result.hex(),post_java_key=updated.hex(),
                business_info=hex(info),business_subkey=subkey.hex(),business_key=material[:32].hex(),
                business_nonce=material[32:].hex(),counter=0,rounds=rounds)
    evidence.update(seed_address=hex(address),business_type=typ,business_rounds=rounds,
                    zstandard_magic_passed=True,decompressed_size=len(body),dex_index_passed=True)
    return body

def verify(data, check):
    require(len(data)>=112 and data[:4]==b'dex\n', 'DEX magic 无效。')
    require(len(data)==struct.unpack_from('<I',data,32)[0], 'DEX 长度不匹配。')
    require(hashlib.sha1(data[32:]).digest()==data[12:32], 'DEX SHA-1 不匹配。')
    require(zlib.adler32(data[12:])==struct.unpack_from('<I',data,8)[0], 'DEX Adler32 不匹配。')
    parsed = DEX(data); classes = parsed.get_classes()
    methods = codes = instructions = 0
    for c in classes:
        check()
        for m in c.get_methods():
            methods += 1
            code = m.get_code()
            if code is None:
                continue
            codes += 1; total = 0
            for ins in m.get_instructions():
                total += ins.get_length(); instructions += 1
                if instructions % 8192 == 0:
                    check()
                require(ins.get_name() not in ('invalid', 'unused'), '存在无效 DEX 指令。')
            require(total == code.get_insns_size()*2, '方法指令长度不匹配。')
    return dict(classes=len(classes), methods=methods, code_items=codes, instructions=instructions,
        sha256=sha(data).hex(), sha1_ok=True, adler32_ok=True, size=len(data))

def recover(source, destination, supplement=None, notify=lambda event: None, cancel=lambda: False, keys_only=False):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    supplement = Path(supplement).resolve() if supplement else None
    require(source.is_file(), '输入文件不存在。')
    if supplement:
        require(supplement.is_file(), '补充文件不存在。')
    destination.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix='dex_'+time.strftime('%Y%m%d_%H%M%S')+'_', dir=destination))
    started = time.monotonic()
    keys, evidence = {}, {}
    current_stage = 'input'
    report = dict(status='running', source=str(source), output=str(run), files=[])
    def check():
        if cancel():
            raise Cancelled('已取消解密。')
    def event(percent, message):
        nonlocal current_stage
        check()
        current_stage = message
        item = dict(kind='progress', percent=percent, message=message, output=str(run))
        with (run/'运行日志.txt').open('a', encoding='utf-8') as f:
            f.write(f'{time.strftime("%H:%M:%S")}  {message}\n')
        notify(item)
    try:
        with tempfile.TemporaryDirectory(prefix='dexprotector_') as temp:
            staging = Path(temp)
            event(3, '读取 APK / APKS，查找 ARM64 Native 库…')
            base, native, assets, dexes, fingerprint = inputs(source, supplement, check)
            report.update(profile='automatic ARM64 inference',base_sha256=sha(base).hex(),native_sha256=fingerprint,
                          keys_only=keys_only,evidence=evidence)
            event(12,'识别 loader 并仿真解封装 Native…')
            image,meta=unpack(native,check);evidence['native_unpack']=meta
            (run/'native_unpacked.bin').write_bytes(image)
            event(24,'分析 ARM64 调用参数，自动推导材料与 info 候选…')
            parameters=infer(image,meta,check);evidence['inference']=parameters.evidence
            event(34,'验证签名与完整性绑定，派生并检查主密钥…')
            key=master_key(image,base,dexes,parameters,keys,evidence)
            event(44,'认证解密容器目录与引导 DEX…')
            blocks,bootstrap=decrypt_blocks(key,assets,parameters,keys,evidence)
            event(54,'解释引导代码，筛选业务 key / nonce / 轮数…')
            body=decrypt_business(image,blocks,key,bootstrap,dexes,parameters,keys,evidence,check)
            offsets=container_offsets(body);count=len(offsets)
            if keys_only:
                report.update(status='keys_verified',content_validation='not_run_keys_only',
                              elapsed_seconds=round(time.monotonic()-started,2))
                event(100,'密钥推导完成，认证与业务解压验证通过。')
                return report
            for i, offset in enumerate(offsets):
                event(65+int(27*i/(count+1)), f'修复并完整验证 DEX {i+1}/{count}…')
                require(offset+112 <= len(body), 'DEX 头部越界。')
                length = struct.unpack_from('<I', body, offset+32)[0]
                require(112 <= length <= len(body)-offset, 'DEX 数据越界。')
                data = bytearray(body[offset:offset+length]); original = sha(data).hex()
                mapoff = struct.unpack_from('<I', data, 52)[0]
                require(mapoff+4 <= length, 'DEX map_list 越界。')
                mapsize = struct.unpack_from('<I', data, mapoff)[0]
                require(mapsize<=256 and mapoff+4+12*mapsize<=length, 'DEX map_list 长度异常。')
                items = [struct.unpack_from('<HHII',data,mapoff+4+12*j) for j in range(mapsize)]
                data_offsets = [o for t,u,s,o in items if t>=0x1000]
                require(data_offsets and all(0<=o<length for o in data_offsets), 'DEX 数据项偏移异常。')
                dataoff = min(data_offsets)
                struct.pack_into('<II',data,104,length-dataoff,dataoff)
                data[12:32] = hashlib.sha1(data[32:]).digest()
                struct.pack_into('<I',data,8,zlib.adler32(data[12:]))
                row = verify(bytes(data), check)
                row.update(name=f'protected_{i:02d}.dex', kind='business' if row['methods'] else 'fallback',
                    container_offset=offset, original_sha256=original)
                (staging/row['name']).write_bytes(data); report['files'].append(row)
            event(94, '验证引导 DEX，写入结果与报告…')
            row = verify(bootstrap, check); row.update(name='bootstrap.dex', kind='bootstrap')
            (staging/row['name']).write_bytes(bootstrap); report['files'].append(row)
            check()
            for row in report['files']:
                shutil.copyfile(staging/row['name'],run/row['name'])
            report.update(status='success', elapsed_seconds=round(time.monotonic()-started,2))
            (run/'使用说明.txt').write_text('优先导入 manifest.json 中 kind=business 的 DEX。\n'
                'fallback 仅含备用类定义；bootstrap 为引导 DEX。\n'
                '保留稀疏节区布局，已修复头部并验证全部指令；未验证 APK 重打包安装。\n',encoding='utf-8')
            event(100, '解密完成，全部 DEX 校验通过。')
    except BaseException as e:
        report['failed_stage'] = current_stage
        report.update(status='cancelled' if isinstance(e,Cancelled) else 'failed', error=str(e),
            elapsed_seconds=round(time.monotonic()-started,2))
        with (run/'运行日志.txt').open('a',encoding='utf-8') as f:
            f.write(f'{report["status"]}: {e}\n')
        raise
    finally:
        (run/'keys.json').write_text(json.dumps(dict(status=report['status'],values=keys),ensure_ascii=False,indent=2),encoding='utf-8')
        (run/'analysis.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        (run/'manifest.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    return report
