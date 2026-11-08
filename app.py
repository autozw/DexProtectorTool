"""Windows GUI and CLI entry point. Heavy dependencies load only in the worker."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

HERE = Path(__file__).resolve().parent
MODULES = {'elftools':'pyelftools', 'unicorn':'unicorn', 'cryptography':'cryptography',
           'numpy':'numpy', 'zstandard':'zstandard', 'androguard':'androguard', 'loguru':'loguru',
           'apkInspector':'apkInspector', 'asn1crypto':'asn1crypto', 'lxml':'lxml',
           'mutf8':'mutf8', 'cffi':'cffi', 'pycparser':'pycparser', 'colorama':'colorama'}
if os.name == 'nt':
    MODULES['win32_setctime'] = 'win32-setctime'

def worker(args):
    def emit(value):
        print(json.dumps(value,ensure_ascii=False),flush=True)
    try:
        from engine import recover, Cancelled
        result = recover(args.input, args.output, args.supplement, emit,
            lambda: bool(args.cancel_file and Path(args.cancel_file).exists()), keys_only=args.keys_only)
        emit(dict(kind='done',report=result))
        return 0
    except Exception as e:
        emit(dict(kind='cancelled' if type(e).__name__=='Cancelled' else 'error',message=str(e) or type(e).__name__))
        return 2 if type(e).__name__=='Cancelled' else 1

class App:
    def __init__(self, root):
        self.root = root
        self.process = None
        self.messages = queue.Queue()
        self.control = None
        self.output_run = None
        self.last_report = None
        self.received_terminal = False
        self.closing = False
        self.source = tk.StringVar()
        self.destination = tk.StringVar(value=str(HERE/'results'))
        self.supplement = tk.StringVar()
        self.status = tk.StringVar(value='选择输入文件和保存路径，然后开始解密。')
        self.summary = tk.StringVar(value='自动分析 ARM64 Native 与引导代码；所有候选参数须通过认证验证。')
        root.title('DexProtector 离线解密工具')
        root.geometry('960x860')
        root.minsize(820,760)
        root.configure(bg='#f3f5f8')
        style = ttk.Style(root)
        style.theme_use('clam')
        style.configure('.',font=('Microsoft YaHei UI',10))
        style.configure('TFrame',background='#f3f5f8')
        style.configure('TLabel',background='#f3f5f8',foreground='#223047')
        style.configure('Title.TLabel',font=('Microsoft YaHei UI',22,'bold'))
        style.configure('Hint.TLabel',foreground='#65748b',font=('Microsoft YaHei UI',9))
        style.configure('TButton',padding=(12,7))
        style.configure('Accent.TButton',background='#2563eb',foreground='white',font=('Microsoft YaHei UI',10,'bold'))
        style.map('Accent.TButton',background=[('active','#1d4ed8'),('disabled','#a0aabc')])
        style.configure('Treeview',rowheight=27,font=('Microsoft YaHei UI',9))
        style.configure('Treeview.Heading',font=('Microsoft YaHei UI',9,'bold'))
        style.configure('Horizontal.TProgressbar',background='#2563eb',troughcolor='#e1e7f0',bordercolor='#e1e7f0')
        page = ttk.Frame(root,padding=24)
        page.pack(fill='both',expand=True)
        page.columnconfigure(0,weight=1)
        page.rowconfigure(8,weight=1)
        ttk.Label(page,text='DexProtector 解密',style='Title.TLabel').grid(row=0,column=0,sticky='w')
        ttk.Label(page,text='导入应用包 · 离线还原 DEX · 完整校验',style='Hint.TLabel').grid(row=1,column=0,sticky='w',pady=(3,18))
        fields = ttk.Frame(page)
        fields.grid(row=2,column=0,sticky='ew')
        fields.columnconfigure(1,weight=1)
        self.inputs = []
        for row,label,var,command in [
            (0,'APK / APKS',self.source,self.choose_input),
            (1,'保存路径',self.destination,self.choose_output),
            (2,'补充 SO / ABI 分包',self.supplement,self.choose_supplement)]:
            ttk.Label(fields,text=label).grid(row=row,column=0,sticky='w',padx=(0,14),pady=6)
            entry = ttk.Entry(fields,textvariable=var)
            entry.grid(row=row,column=1,sticky='ew',pady=6,ipady=4)
            button = ttk.Button(fields,text='浏览…',command=command)
            button.grid(row=row,column=2,padx=(10,0),pady=6)
            self.inputs.extend([entry,button])
        ttk.Label(page,text='补充文件可留空；完整 APKS 会自动提取 SO，单独 APK 会先查找同目录的 SO / ARM64 分包。',
            style='Hint.TLabel',wraplength=870).grid(row=3,column=0,sticky='w',pady=(6,14))
        actions = ttk.Frame(page)
        actions.grid(row=4,column=0,sticky='ew')
        self.start_button = ttk.Button(actions,text='开始解密',style='Accent.TButton',command=self.start)
        self.start_button.pack(side='left')
        self.keys_button = ttk.Button(actions,text='仅提取密钥',command=lambda: self.start(keys_only=True))
        self.keys_button.pack(side='left',padx=(8,0))
        self.cancel_button = ttk.Button(actions,text='取消',state='disabled',command=self.cancel)
        self.cancel_button.pack(side='left',padx=8)
        self.open_button = ttk.Button(actions,text='打开结果目录',state='disabled',command=self.open_output)
        self.open_button.pack(side='right')
        progress_area = ttk.Frame(page)
        progress_area.grid(row=5,column=0,sticky='ew',pady=(16,12))
        self.progress = ttk.Progressbar(progress_area,maximum=100,mode='determinate')
        self.progress.pack(fill='x')
        ttk.Label(progress_area,textvariable=self.status,wraplength=870).pack(anchor='w',pady=(7,0))
        ttk.Label(page,textvariable=self.summary,style='Hint.TLabel',wraplength=870).grid(row=6,column=0,sticky='w',pady=(0,7))
        self.table = ttk.Treeview(page,columns=('file','kind','size','classes','methods'),show='headings',height=6)
        for col,text,width in [('file','文件',220),('kind','类型',90),('size','大小',100),('classes','类',100),('methods','方法',100)]:
            self.table.heading(col,text=text)
            self.table.column(col,width=width,anchor='w' if col in ('file','kind') else 'e')
        self.table.grid(row=7,column=0,sticky='ew',pady=(0,12))
        self.log = ScrolledText(page,height=7,wrap='word',font=('Consolas',10),bg='white',fg='#273449',
            relief='flat',borderwidth=8,state='disabled')
        self.log.grid(row=8,column=0,sticky='nsew')
        self.append('就绪。每次任务创建独立结果目录，不覆盖已有文件。')
        missing = [name for module,name in MODULES.items() if importlib.util.find_spec(module) is None]
        if missing:
            self.status.set('依赖未安装：请先双击 install.bat，然后通过 start.bat 启动。')
            self.append('缺少依赖：'+', '.join(missing))
            self.start_button.configure(state='disabled')
            self.keys_button.configure(state='disabled')
        root.protocol('WM_DELETE_WINDOW',self.close)
        root.after(100,self.poll)

    def append(self, text):
        self.log.configure(state='normal')
        self.log.insert('end',text+'\n')
        self.log.see('end')
        self.log.configure(state='disabled')

    def choose_input(self):
        value = filedialog.askopenfilename(title='选择 APK 或 APKS',filetypes=[('Android 应用包','*.apk *.apks'),('所有文件','*.*')])
        if value:
            self.source.set(value)

    def choose_output(self):
        value = filedialog.askdirectory(title='选择结果保存目录')
        if value:
            self.destination.set(value)

    def choose_supplement(self):
        value = filedialog.askopenfilename(title='选择匹配的 ARM64 SO 或 ABI 分包',filetypes=[('Native 库或 ABI 分包','*.so *.apk'),('所有文件','*.*')])
        if value:
            self.supplement.set(value)

    def start(self, keys_only=False):
        if self.process:
            return
        source, destination = self.source.get().strip(), self.destination.get().strip()
        supplement = self.supplement.get().strip()
        if not Path(source).is_file() or Path(source).suffix.lower() not in ('.apk','.apks'):
            messagebox.showerror('检查输入','请选择存在的 APK / APKS 文件。'); return
        if not destination:
            messagebox.showerror('检查保存路径','请选择结果保存路径。'); return
        if supplement and not Path(supplement).is_file():
            messagebox.showerror('检查补充文件','指定的 SO / ABI 分包不存在。'); return
        self.control = tempfile.TemporaryDirectory(prefix='dex_gui_')
        self.cancel_file = Path(self.control.name)/'cancel'
        command = [sys.executable,'-u',str(HERE/'app.py'),'--worker','--input',source,'--output',destination,
            '--cancel-file',str(self.cancel_file)]
        if supplement:
            command.extend(['--supplement',supplement])
        if keys_only:
            command.append('--keys-only')
        try:
            self.process = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                encoding='utf-8',errors='replace',env={**os.environ,'PYTHONIOENCODING':'utf-8'},
                creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        except OSError as e:
            self.control.cleanup(); self.control=None
            messagebox.showerror('启动失败',str(e)); return
        self.received_terminal=False; self.last_report=None; self.output_run=None
        self.progress['value']=0
        self.table.delete(*self.table.get_children())
        self.summary.set('处理中，输入文件不会被修改。')
        self.status.set('正在启动解密引擎…')
        self.open_button.configure(state='disabled')
        for widget in self.inputs+[self.start_button,self.keys_button]:
            widget.configure(state='disabled')
        self.cancel_button.configure(state='normal')
        self.append('\n开始任务：'+source)
        process = self.process
        def read_output():
            for line in process.stdout:
                try:
                    item=json.loads(line)
                except json.JSONDecodeError:
                    item=dict(kind='diagnostic',message=line.rstrip())
                self.messages.put(item)
            process.stdout.close()
            self.messages.put(dict(kind='exit',code=process.wait()))
        threading.Thread(target=read_output,daemon=True).start()

    def cancel(self):
        if self.process:
            self.cancel_file.touch()
            self.cancel_button.configure(state='disabled')
            self.status.set('正在取消，等待当前步骤退出…')
            self.append('已请求取消。')

    def handle(self, item):
        kind=item.get('kind')
        if kind=='progress':
            self.progress['value']=item['percent']
            self.status.set(f'{item["percent"]}%  {item["message"]}')
            self.output_run=item['output']
            self.append(item['message'])
        elif kind=='done':
            self.received_terminal=True
            report=item['report']; self.last_report=report; self.output_run=report['output']
            files=report['files']; business=[f for f in files if f['kind']=='business']
            self.status.set('解密完成，全部校验通过。')
            self.summary.set(f'{len(business)} 个业务 DEX · {sum(f["classes"] for f in business):,} 个类 · '
                f'{sum(f["methods"] for f in business):,} 个方法 · 用时 {report["elapsed_seconds"]:.1f} 秒')
            for f in files:
                self.table.insert('','end',values=(f['name'],{'business':'业务','fallback':'备用类','bootstrap':'引导'}[f['kind']],
                    f'{f["size"]/1024**2:.2f} MiB',f'{f["classes"]:,}',f'{f["methods"]:,}'))
            if report['status']=='keys_verified':
                self.status.set('密钥推导完成，认证与业务容器检查通过。')
                self.summary.set('已保存 keys.json、analysis.json 和 Native 镜像；本模式未逐方法验证或导出业务 DEX。')
            self.append('保存位置：'+self.output_run)
        elif kind in ('error','cancelled'):
            self.received_terminal=True
            self.status.set('已取消。' if kind=='cancelled' else '解密失败：'+item['message'])
            self.summary.set('未完成的任务不作为成功结果。可查看结果目录中的日志。')
            self.append(item['message'])
        elif kind=='diagnostic':
            self.append(item['message'])
        elif kind=='exit':
            if not self.received_terminal:
                self.status.set(f'解密进程异常退出（{item["code"]}），请查看日志。')
            self.process=None
            if self.control:
                self.control.cleanup(); self.control=None
            for widget in self.inputs+[self.start_button,self.keys_button]:
                widget.configure(state='normal')
            self.cancel_button.configure(state='disabled')
            if self.output_run:
                self.open_button.configure(state='normal')
            if self.closing:
                self.root.destroy()

    def poll(self):
        try:
            while True:
                self.handle(self.messages.get_nowait())
                if self.closing and self.process is None:
                    return
        except queue.Empty:
            self.root.after(100,self.poll)

    def open_output(self):
        if self.output_run and Path(self.output_run).is_dir():
            try:
                os.startfile(self.output_run)
            except OSError as e:
                messagebox.showerror('打开失败',str(e))

    def close(self):
        if self.process:
            if messagebox.askyesno('退出','解密仍在进行。取消任务并退出？'):
                self.closing=True; self.cancel()
        else:
            self.root.destroy()

def main():
    parser=argparse.ArgumentParser(description='DexProtector 离线解密工具')
    parser.add_argument('--worker',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--cli',action='store_true',help='使用命令行执行同一解密流程')
    parser.add_argument('--input')
    parser.add_argument('--output')
    parser.add_argument('--supplement')
    parser.add_argument('--keys-only',action='store_true',help='仅推导并导出密钥，仍认证和解压业务容器')
    parser.add_argument('--cancel-file',help=argparse.SUPPRESS)
    args=parser.parse_args()
    if args.worker or args.cli:
        if not args.input or not args.output:
            parser.error('--input 和 --output 必填')
        return worker(args)
    if os.name=='nt':
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError,OSError):
            print('DPI setup unavailable; continuing with default scaling.',file=sys.stderr)
    root=tk.Tk()
    def callback_error(exc_type, value, tb):
        import traceback
        traceback.print_exception(exc_type,value,tb)
        messagebox.showerror('操作失败',f'{value}\n\n详细信息已记录在 startup.log。')
    root.report_callback_exception=callback_error
    App(root)
    print('GUI initialized successfully.',flush=True)
    root.mainloop()
    return 0

if __name__=='__main__':
    raise SystemExit(main())
