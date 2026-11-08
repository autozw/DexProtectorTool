"""Infer parameters from the supplied ARM64 image; no application profiles."""
import io
import struct
from types import SimpleNamespace
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm64_const import (UC_ARM64_REG_SP, UC_ARM64_REG_CPACR_EL1,
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X8, UC_ARM64_REG_LR, UC_ARM64_REG_PC)
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap_with_padding, InvalidUnwrap
from crypto_core import sha

class InferenceError(ValueError):
    """Unsupported or ambiguous inference, never a fallback to sample parameters."""

def need(ok, message):
    if not ok:
        raise InferenceError(message)

def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]

def sign(v, bits):
    return (v ^ (1 << (bits-1))) - (1 << (bits-1))

def unpack(native, check=lambda: None):
    need(64 <= len(native) <= 16*1024**2, 'Native 文件大小不支持。')
    elf = ELFFile(io.BytesIO(native))
    need(elf.elfclass == 64 and elf.little_endian and elf['e_machine'] == 'EM_AARCH64', '仅支持小端 ARM64 ELF。')
    segments, entries = [], []
    for s in elf.iter_segments():
        if s['p_type'] != 'PT_LOAD':
            continue
        need(s['p_filesz'] <= s['p_memsz'] and s['p_vaddr']+s['p_memsz'] <= 0x1000000, 'ELF 段超出仿真范围。')
        need(s['p_offset']+s['p_filesz'] <= len(native), 'ELF 文件段越界。')
        segments.append(s)
        if s['p_flags'] & 1:
            b = s.data()
            for o in range(0, len(b)-15, 4):
                a,c,d,e = struct.unpack_from('<4I',b,o)
                if a == 0xf100a43f and c & 0xff00001f == 0x54000002 and d == 0x2a1f03e0 and e == 0xd65f03c0:
                    entries.append(s['p_vaddr']+o)
    need(len(segments) >= 4 and len(entries) == 1, f'未能唯一识别 loader 结构，候选数 {len(entries)}。')
    payload = segments[-1]
    base, stack, fake, out = 0x1000000, 0x3000000, 0x3400000, 0x5000000
    stop = fake+0x4000
    errors = []
    for breakpoint in (0xd65f03c0, 0xd503201f):
        check()
        u = Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        for address,size in ((base,0x1000000),(stack,0x400000),(fake,0x100000),(out,0x2000000)):
            u.mem_map(address,size)
        for s in segments:
            u.mem_write(base+s['p_vaddr'],s.data())
        u.mem_write(fake+0x1010,struct.pack('<Q',fake+0x2000))
        u.mem_write(fake+0x2000,struct.pack('<I',breakpoint))
        for reg,value in ((UC_ARM64_REG_SP,stack+0x3f0000),(UC_ARM64_REG_CPACR_EL1,3<<20),
            (UC_ARM64_REG_X0,base+payload['p_vaddr']),(UC_ARM64_REG_X1,payload['p_filesz']),
            (UC_ARM64_REG_X2,fake+0x1000),(UC_ARM64_REG_X3,fake+0x3000),(UC_ARM64_REG_LR,stop)):
            u.reg_write(reg,value)
        headers=[]
        def interrupt(uc, number, data):
            nr = uc.reg_read(UC_ARM64_REG_X8)
            if nr == 222:
                frame=bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_SP),0x400)); candidates=[]
                for pos in range(0,len(frame)-35,4):
                    h=struct.unpack_from('<9I',frame,pos)
                    if (0x10000<=h[0]<=0x1000000 and h[0]&4095==0 and h[7] in (4096,16384)
                        and 0<h[8]<=8 and h[1]<h[0] and h[4]<h[0] and h[5]<h[0] and h[6]<=h[0]):
                        candidates.append(h)
                need(len(candidates)==1,'镜像头部不唯一或布局不支持。')
                headers.append(candidates[0]);uc.reg_write(UC_ARM64_REG_X0,out)
            elif nr in (226,167,215):
                uc.reg_write(UC_ARM64_REG_X0,0)
            else:
                raise InferenceError(f'不支持 loader 系统调用 {nr}')
        u.hook_add(UC_HOOK_INTR,interrupt)
        try:
            u.emu_start(base+entries[0],stop,timeout=15000000,count=100000000)
            need(headers and u.reg_read(UC_ARM64_REG_PC)==stop and u.reg_read(UC_ARM64_REG_X0)==1,'loader 超时或返回失败。')
            state=bytes(u.mem_read(fake+0x3000,32));mapped,dynamic=struct.unpack_from('<QQ',state,16)
            size=headers[-1][0]
            need(out<=mapped and mapped+size<=out+0x2000000 and mapped<=dynamic<mapped+size,'内部映射或动态表越界。')
            image=bytes(u.mem_read(mapped,size))
            return image,dict(loader_entry=entries[0],payload_address=payload['p_vaddr'],payload_size=payload['p_filesz'],
                image_size=size,segment_count=headers[-1][8],dynamic_offset=dynamic-mapped,return_status=1)
        except (UcError,InferenceError) as e:
            errors.append(str(e))
        finally:
            del u
    raise InferenceError('Native 解封装失败：'+'; '.join(errors))

def scan(image, check=lambda: None):
    r=[None]*32;r[31]=0x10000000;memory={};calls=[];loads=[]
    def val(i):return 0 if i==31 else r[i]
    for pc in range(0,len(image)-3,4):
        if pc%0x4000==0:check()
        w=u32(image,pc);rd=w&31;rn=(w>>5)&31
        if w&0xfffffc1f==0xd65f0000:
            r=[None]*32;r[31]=0x10000000;memory={};continue
        if w&0xfc000000==0x94000000:
            calls.append(dict(pc=pc,target=pc+(sign(w&0x3ffffff,26)<<2),args=r[:8],
                info1=memory.get(r[1]),info2=memory.get(r[2]),info3=memory.get(r[3])))
            r[:19]=[None]*19;continue
        if w&0xfffffc1f==0xd63f0000:r[:19]=[None]*19;continue
        if w&0x1f000000==0x10000000:
            imm=sign(((w>>5)&0x7ffff)<<2|((w>>29)&3),21)
            if rd!=31:r[rd]=(pc&~4095)+(imm<<12) if w>>31 else pc+imm
            continue
        if w&0x1f800000==0x12800000:
            opc=(w>>29)&3;shift=((w>>21)&3)*16;imm=((w>>5)&65535)<<shift
            if rd!=31:
                if opc==2:r[rd]=imm
                elif opc==0:r[rd]=~imm
                elif opc==3:r[rd]=None if r[rd] is None else (r[rd]&~(65535<<shift))|imm
                else:r[rd]=None
                if r[rd] is not None:r[rd]&=(1<<(64 if w>>31 else 32))-1
            continue
        if w&0x7fe0ffe0==0x2a0003e0:
            if rd!=31:
                r[rd]=val((w>>16)&31)
                if r[rd] is not None and not w>>31:r[rd]&=0xffffffff
            continue
        if w&0x1f000000==0x11000000:
            if rd==31 and w&0x20000000:continue
            v=r[rn];imm=((w>>10)&4095)<<(12 if w&0x400000 else 0)
            if rd==31 and v is None:v=0x10000000
            r[rd]=None if v is None else v+(-imm if w&0x40000000 else imm)
            if rd!=31 and r[rd] is not None and not w>>31:r[rd]&=0xffffffff
            continue
        unsigned=w&0x3b000000==0x39000000;unscaled=w&0x3b200c00==0x38000000
        if unsigned or unscaled:
            if w&0x04000000:continue
            size=(w>>30)&3;op=(w>>22)&3;disp=((w>>10)&4095)<<size if unsigned else sign((w>>12)&511,9)
            address=None if r[rn] is None else r[rn]+disp
            if op==0:
                if address is not None and val(rd) is not None and size==3:memory[address]=val(rd)
            elif rd!=31:
                r[rd]=None
                if address is not None and 0<=address<=len(image)-(1<<size):
                    r[rd]=int.from_bytes(image[address:address+(1<<size)],'little')
                    if size==0 and op==1:loads.append((pc,address))
            continue
        if w&0x3a000000==0x28000000:
            if not w&0x04000000 and w&0x400000:
                if rd!=31:r[rd]=None
                rt2=(w>>10)&31
                if rt2!=31:r[rt2]=None
            continue
        if (w&0x7c000000==0x14000000 or w&0xff000000==0x54000000 or w&0x7e000000 in (0x34000000,0x36000000)
            or w&0x1e000000 in (0x0e000000,0x1e000000) or w&0xff000000==0xd5000000):continue
        if rd!=31:r[rd]=None
    return calls,loads

def unique(values,label):
    need(len(values)==1,f'{label} 无法唯一定位，候选数 {len(values)}。')
    return next(iter(values))

def infer(image, meta, check=lambda: None):
    calls,loads=scan(image,check)
    def inside(o,n):return o is not None and 0<=o<=len(image)-n
    roots={(c['args'][0],c['args'][2]):c for c in calls if c['args'][1]==32 and c['args'][3]==64
        and inside(c['args'][0],32) and inside(c['args'][2],64)}
    salt,ikm=unique(roots,'初始 HKDF 材料')
    # Infer wrapped-region length from a data mixing call with AES-KWP-sized entries.
    ranges={}
    unwrap_addresses={c['args'][1] for c in calls if c['args'][2]==40 and c['args'][4]==32 and inside(c['args'][1],40)}
    for c in calls:
        a=c['args'];n=a[2]
        if n is not None and 40<=n<=2560 and n%40==0 and inside(a[1],n) and all(a[1]+i in unwrap_addresses for i in range(0,n,40)):
            # This must be a Mix call, not the unwrap function itself.
            matches=[q['info3'] for q in calls if c['target']<=q['pc']<c['target']+256 and q['args'][2]==32
                and q['args'][4]==8 and q['args'][6]==32 and q['info3'] is not None]
            if len(set(matches))==1:ranges[(a[1],n)]=matches[0]
    start,length=unique(ranges,'签名材料区域');mix_info=ranges[(start,length)]
    checks={}
    for c in calls:
        if c['args'][2]!=8 or c['args'][4]!=4 or c['info1'] is None:continue
        near=[a for pc,a in loads if c['pc']<pc<c['pc']+180]
        for i in range(len(near)-3):
            a=near[i]
            if near[i:i+4]==list(range(a,a+4)) and inside(a,8):checks[(a,c['info1'])]=u32(image,a+4)
    check_address,check_info=unique(checks,'主密钥检查');dex_count=checks[(check_address,check_info)]
    need(0<=dex_count<=100,'DEX 前缀数量不支持。')
    runtime=bytearray(image);dyn={};offset=meta['dynamic_offset']
    for i in range(256):
        need(inside(offset,16),'动态表越界。');tag,value=struct.unpack_from('<QQ',image,offset);offset+=16
        if tag==0:break
        dyn[tag]=value
    else:raise InferenceError('动态表未终止。')
    def zero(o,n):
        if o is None or n is None:return
        need(n>=0 and inside(o,n),'动态元数据清理越界。');runtime[o:o+n]=bytes(n)
    if all(t in dyn for t in (6,5,10)):zero(dyn[6],dyn[5]+dyn[10]-dyn[6])
    for address,size in ((23,2),(36,35),(7,8)):zero(dyn.get(address),dyn.get(size))
    native_matches={}
    for index,c in enumerate(calls):
        if c['args'][2]!=40 or c['args'][4]!=32 or not inside(c['args'][1],40) or not index:continue
        prev=calls[index-1]
        if prev['pc']<c['pc']-128:continue
        positions=[]
        for pc in range(max(0,prev['pc']-32),prev['pc'],4):
            w=u32(image,pc)
            if w&0xffc003e0==0x39400000 and (w>>10)&4095<64:positions.append((w>>10)&4095)
        if len(positions)!=3:continue
        size=sum(image[o]<<(8*i) for i,o in enumerate(positions))
        if not 4096<=size<=len(image):continue
        digest=sha(runtime[:size]);wrapped=image[c['args'][1]:c['args'][1]+40]
        try:material=aes_key_unwrap_with_padding(digest,wrapped)
        except InvalidUnwrap:continue
        native_matches[c['args'][1]]=(digest,material,size)
    native_address=unique(native_matches,'Native 完整性材料');digest,material,hash_size=native_matches[native_address]
    seeds=[];i=0
    while i<len(loads):
        end=i+1
        while end<len(loads) and loads[end][1]==loads[end-1][1]+1 and loads[end][0]-loads[end-1][0]<64:end+=1
        if end-i>=32:seeds.append(loads[i][1])
        i=end
    e44=sorted({c['info1'] for c in calls if c['args'][2]==8 and c['args'][4]==44 and c['info1'] is not None})
    e64=sorted({c['info2'] for c in calls if c['args'][3]==8 and c['info2'] is not None})
    need(e44 and e64 and seeds and len(e44)<=64 and len(e64)<=64 and len(seeds)<=64,'候选缺失或数量超限。')
    return SimpleNamespace(salt=image[salt:salt+32],ikm=image[ikm:ikm+64],wraps=image[start:start+length],
        mix_info=mix_info,check_info=check_info,check_value=image[check_address:check_address+4],dex_count=dex_count,
        native_digest=digest,native_material=material,expand44=e44,expand64=e64,seeds=seeds,
        evidence=dict(salt_address=hex(salt),ikm_address=hex(ikm),signature_address=hex(start),signature_length=length,
            check_address=hex(check_address),native_address=hex(native_address),native_hash_length=hash_size,
            expand44_candidates=[hex(x) for x in e44],expand64_candidates=[hex(x) for x in e64],seed_candidates=[hex(x) for x in seeds]))
