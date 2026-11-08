"""Restricted Dalvik interpreter for offline seed derivation, with no framework execution."""
import re
import struct
from androguard.core.dex import DEX
from inference import need, InferenceError

def i32(x):
    x &= 0xffffffff
    return x if x < 0x80000000 else x-0x100000000

def interpret(method, argument, check=lambda: None, invoke=None):
    body=method.get_code()
    need(body and body.get_ins_size()==1 and method.get_access_flags()&8,'引导方法必须为单参数 static 方法。')
    need(body.get_registers_size()<=256,'引导寄存器数量异常。')
    r=[0]*body.get_registers_size();r[-1]=argument
    code=dict(method.get_instructions_idx());pc=0;result=None
    for step in range(100000):
        if step%1024==0:check()
        need(pc in code,'引导跳转越界。')
        ins=code[pc];name=ins.get_name();ops=ins.get_operands();a=[o[1] for o in ops];next_pc=pc+ins.get_length()
        if name=='nop':pass
        elif name.startswith('const') and not name.startswith(('const-string','const-class','const-wide')):r[a[0]]=i32(a[1])
        elif name in ('move-result','move-result-object'):r[a[0]]=result
        elif name.split('/')[0] in ('move','move-object'):r[a[0]]=r[a[1]]
        elif name=='new-array':
            count=r[a[1]];kind=ops[-1][2];need(0<=count<=65536 and kind in ('[B','[I'),'引导数组不支持。')
            r[a[0]]=bytearray(count) if kind=='[B' else [0]*count
        elif name=='array-length':r[a[0]]=len(r[a[1]])
        elif name=='fill-array-data':
            payload=code.get(pc+a[1]*2);need(payload is not None and payload.get_name()=='fill-array-data-payload','数组载荷缺失。')
            data=payload.get_data();array=r[a[0]]
            if isinstance(array,bytearray):need(len(data)>=len(array) and len(data)-len(array)<=1,'字节表长度不匹配。');array[:]=data[:len(array)]
            else:need(len(data)==len(array)*4,'整数表长度不匹配。');array[:]=struct.unpack('<'+'i'*len(array),data)
        elif name in ('aget','aget-byte','aput','aput-byte'):
            array=r[a[1]];idx=r[a[2]];need(isinstance(array,(list,bytearray)) and 0<=idx<len(array),'引导数组越界。')
            if name.startswith('aget'):
                v=array[idx];r[a[0]]=v-256 if name=='aget-byte' and v>=128 else v
            else:array[idx]=r[a[0]]&255 if name=='aput-byte' else i32(r[a[0]])
        elif name=='int-to-byte':r[a[0]]=((r[a[1]]&255)^128)-128
        elif name.startswith('goto'):next_pc=pc+a[0]*2
        elif name.startswith('if-'):
            cond=name[3:];zero=cond.endswith('z');cond=cond.rstrip('z')
            left=r[a[0]];right=0 if zero else r[a[1]]
            comparisons={'eq':left==right,'ne':left!=right,'ge':left>=right,'gt':left>right,'le':left<=right,'lt':left<right}
            need(cond in comparisons,'条件指令不支持。')
            if comparisons[cond]:next_pc=pc+a[-1]*2
        elif name in ('return','return-object'):return r[a[0]]
        elif name=='return-void':return None
        elif name.startswith('invoke-static'):
            need(invoke is not None,'替换方法包含未支持调用。');ref=ops[-1][2];regs=[o[1] for o in ops[:-1]]
            result=invoke(ref,[r[x] for x in regs])
        elif '-int' in name:
            op=name.split('-int')[0];dest=a[0]
            if '/2addr' in name:left,right=r[dest],r[a[1]]
            elif '/lit' in name:left,right=r[a[1]],a[2]
            else:left,right=r[a[1]],r[a[2]]
            if op=='add':v=left+right
            elif op=='sub':v=left-right
            elif op=='xor':v=left^right
            elif op=='and':v=left&right
            elif op=='or':v=left|right
            elif op=='shl':v=left<<(right&31)
            elif op=='shr':v=i32(left)>>(right&31)
            elif op=='ushr':v=(left&0xffffffff)>>(right&31)
            else:raise InferenceError('未支持的整数指令：'+name)
            r[dest]=i32(v)
        else:raise InferenceError('未支持的引导指令：'+name)
        pc=next_pc
    raise InferenceError('引导代码超过执行步数上限。')

def derive_results(image, bootstrap, dexes, seeds, check=lambda: None):
    d=DEX(bootstrap)
    methods=[m for c in d.get_classes() for m in c.get_methods() if m.get_descriptor()=='([I)V' and m.get_code()]
    need(len(methods)==1,'引导 int[] 方法不唯一。');boot=methods[0]
    refs={o[-1][2] for i in boot.get_instructions() if i.get_name().startswith('invoke-static')
          and (o:=i.get_operands()) and o[-1][2].endswith('([B)[B')}
    need(len(refs)==1,'外层替换方法不唯一。');target=next(iter(refs))
    match=re.fullmatch(r'(L[^;]+;)->([^ (]+)\(\[B\)\[B',target);need(match,'替换方法引用格式不支持。')
    class_name,method_name=match.groups();outer=None
    for raw in dexes.values():
        check()
        if class_name.encode() not in raw:continue
        parsed=DEX(raw)
        found=[m for c in parsed.get_classes() if c.get_name()==class_name for m in c.get_methods()
            if m.get_name()==method_name and m.get_descriptor()=='([B)[B']
        if found:need(len(found)==1,'替换方法重复。');outer=found[0];break
    need(outer is not None,'未找到外层替换方法。')
    results={}
    for address in seeds:
        seed=bytearray(image[address:address+32]);need(len(seed)==32,'seed 越界。')
        def invoke(ref,args):
            if ref==target:
                need(len(args)==1,'替换方法参数异常。');return interpret(outer,args[0],check)
            if ref.endswith('()[B'):
                need(not args and ref.startswith(boot.get_class_name()+'->'),'未知 Native seed 回调。');return seed.copy()
            raise InferenceError('未支持的调用：'+ref)
        words=[0]*8;interpret(boot,words,check,invoke)
        results[address]=struct.pack('<8I',*(x&0xffffffff for x in words))
    return results
