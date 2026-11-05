# -*- coding: utf-8 -*-
"""作业提交系统 v3（局域网单文件版）——已修复 Review 中全部问题"""
import os                                                     # 路径与文件系统操作
import re                                                     # 正则清洗与格式校验
import sys                                                    # 打包检测、标准输出编码
import json                                                   # 配置与公告的 JSON 读写
import time                                                   # 登录限流用的时间戳
import shutil                                                 # 磁盘剩余空间检测
import socket                                                 # 探测本机局域网地址
import secrets                                                # 生成不可预测的文件名后缀
import sqlite3                                                # 提交记录数据库
import tempfile                                               # JSON 原子写用的临时文件
import threading                                              # 锁：线程安全
import zipfile                                                # 批量导出 ZIP
from datetime import datetime                                 # 截止时间与提交时间
from flask import Flask, request, jsonify, send_file          # Web 框架核心
from werkzeug.security import generate_password_hash, check_password_hash  # 密码哈希与校验

try:                                                          # 兼容不同环境的控制台编码
    sys.stdout.reconfigure(encoding="utf-8")                  # Windows 控制台中文正常显示
except Exception:                                             # 某些环境不支持 reconfigure
    pass                                                      # 忽略即可，不影响运行

# ============================ 一、路径准备 ============================
def default_base_dir():                                       # 计算程序所在目录
    if getattr(sys, "frozen", False):                         # 是否被打包成 exe
        return os.path.dirname(os.path.abspath(sys.executable))  # 打包后：exe 所在目录
    return os.path.dirname(os.path.abspath(__file__))         # 源码运行：当前 py 文件目录

def prepare_dirs():                                           # 准备 uploads / data 目录
    base = default_base_dir()                                 # 首选：程序目录（绿色版最直观）
    upload_dir = os.path.join(base, "uploads")                # 上传文件存放目录
    data_dir = os.path.join(base, "data")                     # 配置与数据库目录
    try:                                                      # 先试程序目录（可写就最好）
        os.makedirs(upload_dir, exist_ok=True)                # 创建上传目录
        os.makedirs(data_dir, exist_ok=True)                  # 创建数据目录
        probe = os.path.join(data_dir, ".write_probe")        # 写权限探针文件
        with open(probe, "w", encoding="utf-8") as fp:        # 真实写一次，确认权限
            fp.write("ok")                                    # 写入内容
        os.unlink(probe)                                      # 立刻删除探针
        return upload_dir, data_dir, base                     # 程序目录可用，返回三路径
    except OSError:                                           # 只读目录（如 C:\Program Files）
        root = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "HomeworkServer")  # 用户可写目录
        upload_dir = os.path.join(root, "uploads")            # 兜底上传目录
        data_dir = os.path.join(root, "data")                 # 兜底数据目录
        os.makedirs(upload_dir, exist_ok=True)                # 创建兜底上传目录
        os.makedirs(data_dir, exist_ok=True)                  # 创建兜底数据目录
        return upload_dir, data_dir, root                     # 返回兜底路径

UPLOAD_DIR, DATA_DIR, BASE_DIR = prepare_dirs()               # 初始化目录（含权限兜底）
EXPORT_DIR = os.path.join(DATA_DIR, "exports")                # 批量导出的临时 ZIP 目录
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")           # 管理密码 / 截止时间
NOTICES_FILE = os.path.join(DATA_DIR, "notices.json")         # 公告列表
SUBMISSIONS_DB = os.path.join(DATA_DIR, "submissions.db")     # 提交记录数据库
os.makedirs(EXPORT_DIR, exist_ok=True)                        # 确保导出目录存在

# ============================ 二、常量配置 ============================
DEFAULT_PASSWORD = "admin888"                                 # 首次运行的默认管理密码
MAX_SIZE = 20 * 1024 * 1024                                   # 单文件上限 20 MB
REQUEST_MAX = MAX_SIZE + 2 * 1024 * 1024                      # 请求体上限再留 2 MB 给 multipart 开销
MIN_FREE_BYTES = 200 * 1024 * 1024                            # 磁盘剩余低于 200 MB 就拒收
MAX_PER_STUDENT = 3                                           # 每个学号最多保留 3 次提交
MIN_PASSWORD_LEN = 4                                          # 管理密码最短长度
MAX_PASSWORD_LEN = 64                                         # 管理密码最长长度
PASSWORD_RE = re.compile(r"^[\x21-\x7E]+$")                   # 只允许可见 ASCII，避免 header 非法字符
SID_RE = re.compile(r"^[A-Za-z0-9_-]{2,20}$")                  # 学号：字母数字下划线短横线
MAX_LOGIN_FAILS = 5                                           # 连续失败 5 次触发锁定
LOGIN_LOCK_SECONDS = 60                                       # 锁定时长 60 秒
MAX_STEM_LEN = 40                                             # 原文件主名保留长度
MAX_FILE_NAME_LEN = 120                                       # 拼接后文件名上限，规避 Windows 260 限制
ENFORCE_ORIGIN = True                                         # 是否校验 Origin（反代环境可设 False）
PORT = 8080                                                   # 监听端口

ALLOWED_EXT = {".txt", ".md", ".py", ".c", ".cpp", ".java", ".html", ".css", ".js",  # 文本类
               ".zip", ".rar", ".7z",                                                 # 压缩包
               ".doc", ".docx", ".pdf", ".ppt", ".pptx", ".xls", ".xlsx",              # 文档
               ".jpg", ".jpeg", ".png"}                                               # 图片

BINARY_MAGIC = {                                              # 二进制格式的文件头特征
    ".pdf": [b"%PDF"],                                        # PDF
    ".png": [b"\x89PNG\r\n\x1a\n"],                           # PNG
    ".jpg": [b"\xff\xd8\xff"],                                # JPEG
    ".jpeg": [b"\xff\xd8\xff"],                               # JPEG 另一后缀
    ".zip": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],    # ZIP（含空包与分卷）
    ".docx": [b"PK\x03\x04"],                                  # DOCX 本质是 ZIP
    ".xlsx": [b"PK\x03\x04"],                                  # XLSX 本质是 ZIP
    ".pptx": [b"PK\x03\x04"],                                  # PPTX 本质是 ZIP
    ".rar": [b"Rar!\x1a\x07"],                                 # RAR
    ".7z": [b"7z\xbc\xaf\x27\x1c"],                            # 7Z
    ".doc": [b"\xd0\xcf\x11\xe0"],                             # OLE 复合文档（Word 97-2003）
    ".xls": [b"\xd0\xcf\x11\xe0"],                             # OLE 复合文档（Excel 97-2003）
    ".ppt": [b"\xd0\xcf\x11\xe0"],                             # OLE 复合文档（PPT 97-2003）
}

EXEC_MAGIC = [b"MZ", b"\x7fELF", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce",  # PE / ELF / Mach-O
              b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"]  # Mach-O 变体

TEXT_EXTS = {".txt", ".md", ".py", ".c", ".cpp", ".java", ".html", ".css", ".js"}  # 纯文本，跳过魔数校验

COMPRESSED_EXTS = {".zip", ".rar", ".7z", ".jpg", ".jpeg", ".png",  # 已压缩格式，打包时不再 DEFLATE
                   ".docx", ".xlsx", ".pptx"}                        # Office 2007+ 也是压缩包

# ============================ 三、应用与存储 ============================
app = Flask(__name__)                                         # 创建 Flask 应用
app.config["MAX_CONTENT_LENGTH"] = REQUEST_MAX                # 请求体上限（已含 multipart 余量）
app.config["JSON_AS_ASCII"] = False                           # 兼容 Flask 2.2 的 JSON 中文输出
try:                                                          # Flask 2.3+ 的新写法
    app.json.ensure_ascii = False                             # 让 JSON 直接输出中文
except AttributeError:                                        # 低版本没有 app.json provider
    pass                                                      # 忽略，上面的配置已生效

class JsonStore:                                              # 线程安全的小型 JSON 存储
    def __init__(self, path, default_factory):                # 初始化
        self.path = path                                      # 文件路径
        self.default_factory = default_factory                # 缺省值工厂函数
        self._lock = threading.RLock()                        # 可重入锁，避免嵌套死锁
        if not os.path.exists(path):                          # 首次运行
            try:                                              # 尝试写入默认内容
                self._atomic_write(default_factory())         # 原子写入
            except OSError as exc:                            # 写失败
                print(f"[WARN] 初始化 {path} 失败：{exc}")     # 打印真实原因

    def _read_unlocked(self):                                 # 调用方必须已持有锁
        try:                                                  # 只捕获「文件损坏 / 读不动」两类错误
            with open(self.path, "r", encoding="utf-8") as fp:  # 以只读方式打开
                data = json.load(fp)                          # 解析 JSON
            if isinstance(data, (dict, list)):                # 类型必须正确
                return data                                   # 返回解析结果
            print(f"[WARN] {self.path} 内容类型异常，按默认值处理")  # 类型不对
            return self.default_factory()                     # 退回默认值
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:  # 只捕获预期内错误
            print(f"[WARN] {self.path} 读取失败：{exc}")      # 打印真实原因，不做静默吞掉
            return self.default_factory()                     # 退回默认值

    def _atomic_write(self, data):                            # 原子写：临时文件 + os.replace
        directory = os.path.dirname(self.path) or "."         # 目标目录
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp_", suffix=".json")  # 建临时文件
        try:                                                  # 保证异常时清理临时文件
            with os.fdopen(fd, "w", encoding="utf-8") as fp:   # 打开临时文件
                json.dump(data, fp, ensure_ascii=False, indent=2)  # 写入格式化 JSON
                fp.flush()                                     # 刷缓冲
                os.fsync(fp.fileno())                          # 落盘，断电不丢
            os.replace(tmp_path, self.path)                    # 原子替换目标文件
        except Exception:                                      # 任何失败
            try:                                               # 尝试删除临时文件
                os.unlink(tmp_path)                            # 清理残渣
            except OSError:                                    # 删除失败也无所谓
                pass                                           # 忽略
            raise                                              # 继续抛给调用方

    def read(self):                                           # 加锁读
        with self._lock:                                       # 进入临界区
            return self._read_unlocked()                       # 委托内部实现

    def write(self, data):                                    # 加锁写
        with self._lock:                                       # 进入临界区
            self._atomic_write(data)                           # 原子写入

    def update(self, mutator):                                # 读-改-写 的原子操作
        with self._lock:                                       # 一次性持锁，避免并发丢失更新
            new_data = mutator(self._read_unlocked())          # 交给业务函数变换
            self._atomic_write(new_data)                       # 写回磁盘
            return new_data                                    # 返回新数据

def default_config():                                          # config.json 的出厂内容
    return {"password_hash": generate_password_hash(DEFAULT_PASSWORD), "deadline": ""}  # 默认密码 + 无截止

FIRST_RUN = not os.path.exists(CONFIG_FILE)                   # 必须在创建 store 之前判断，否则永远 False
CONFIG_STORE = JsonStore(CONFIG_FILE, default_config)          # 配置存储
NOTICES_STORE = JsonStore(NOTICES_FILE, list)                 # 公告存储

class SubmissionStore:                                         # 提交记录仓库
    def __init__(self, path):                                 # 初始化
        self.path = path                                       # 数据库文件路径
        self._lock = threading.RLock()                         # 串行化写操作
        self._init_db()                                        # 建表

    def _init_db(self):                                        # 创建表与索引
        with self._lock:                                       # 建表期间加锁
            conn = sqlite3.connect(self.path)                  # 新连接（连接不跨线程）
            try:                                               # 保证连接被关闭
                with conn:                                     # 自动提交事务
                    conn.execute("CREATE TABLE IF NOT EXISTS submissions ("  # 提交记录表
                                 "id INTEGER PRIMARY KEY AUTOINCREMENT,"     # 自增主键
                                 "student_id TEXT,"                            # 学号
                                 "student_name TEXT,"                          # 姓名
                                 "filename TEXT,"                              # 磁盘文件名
                                 "original_name TEXT,"                         # 学生上传的原始文件名
                                 "size INTEGER,"                               # 字节数
                                 "submitted_at TEXT)")                         # 提交时间
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_student ON submissions(student_id)")  # 学号索引
            except sqlite3.Error as exc:                        # 建表失败
                print(f"[WARN] 初始化数据库失败：{exc}")          # 打印原因
            finally:                                            # 无论成败
                conn.close()                                    # 关闭连接

    def add(self, sid, name, filename, original_name, size):    # 新增一条提交记录
        with self._lock:                                        # 写操作加锁
            conn = sqlite3.connect(self.path)                   # 新连接
            try:                                                # 保证关闭
                with conn:                                      # 自动提交
                    cursor = conn.execute(                      # 执行插入
                        "INSERT INTO submissions (student_id, student_name, filename, original_name, size, submitted_at) "
                        "VALUES (?, ?, ?, ?, ?, ?)",            # 六个占位符
                        (sid, name, filename, original_name, size,
                         datetime.now().strftime("%Y-%m-%d %H:%M:%S")))  # 当前时间
                    return cursor.lastrowid                     # 返回新记录 id
            finally:                                            # 无论成败
                conn.close()                                    # 关闭连接

    def list_all(self):                                         # 取出全部记录（按时间倒序）
        with self._lock:                                        # 读也加锁，避免与写冲突
            conn = sqlite3.connect(self.path)                   # 新连接
            conn.row_factory = sqlite3.Row                      # 让结果可按列名访问
            try:                                                # 保证关闭
                rows = conn.execute("SELECT * FROM submissions ORDER BY submitted_at DESC, id DESC").fetchall()  # 倒序查询
                return [dict(row) for row in rows]              # 转成普通字典列表
            finally:                                            # 无论成败
                conn.close()                                    # 关闭连接

    def stats(self):                                            # 统计：总次数 + 去重人数
        with self._lock:                                        # 加锁
            conn = sqlite3.connect(self.path)                   # 新连接
            try:                                                # 保证关闭
                total = conn.execute("SELECT COUNT(*) FROM submissions").fetchone()[0]                       # 提交总次数
                students = conn.execute("SELECT COUNT(DISTINCT student_id) FROM submissions").fetchone()[0]  # 去重学号数
                return {"total": total, "students": students}   # 返回统计字典
            finally:                                            # 无论成败
                conn.close()                                    # 关闭连接

    def count_by_student(self, sid):                            # 某学号已提交次数
        with self._lock:                                        # 加锁
            conn = sqlite3.connect(self.path)                   # 新连接
            try:                                                # 保证关闭
                return conn.execute("SELECT COUNT(*) FROM submissions WHERE student_id = ?", (sid,)).fetchone()[0]  # 计数
            finally:                                            # 无论成败
                conn.close()                                    # 关闭连接

SUBMISSIONS = SubmissionStore(SUBMISSIONS_DB)                 # 实例化仓库

class LoginGuard:                                              # 登录失败限流
    def __init__(self, max_fails, lock_seconds):               # 初始化
        self.max_fails = max_fails                             # 允许的连续失败次数
        self.lock_seconds = lock_seconds                       # 锁定时长
        self._lock = threading.Lock()                          # 内部锁
        self._state = {}                                       # {ip: {"fails": 次数, "first": 起始时间, "until": 解封时间}}

    def blocked_seconds(self, ip):                             # 剩余锁定秒数，0 表示未锁
        with self._lock:                                       # 进入临界区
            record = self._state.get(ip)                       # 取该 IP 记录
            if not record:                                     # 没有记录
                return 0                                       # 视为未锁
            remain = record["until"] - time.time()             # 剩余时间
            return int(remain) + 1 if remain > 0 else 0        # 返回正整数秒数

    def record_failure(self, ip):                              # 记录一次失败
        with self._lock:                                       # 进入临界区
            now = time.time()                                  # 当前时间
            record = self._state.setdefault(ip, {"fails": 0, "first": now, "until": 0})  # 取或建记录
            if now - record["first"] > self.lock_seconds:      # 距首次失败超过窗口期
                record["fails"] = 0                            # 重新计数
                record["first"] = now                          # 重置窗口起点
            record["fails"] += 1                               # 累加失败次数
            if record["fails"] >= self.max_fails:              # 达到阈值
                record["until"] = now + self.lock_seconds      # 设置解封时间
                record["fails"] = 0                            # 计数清零
                record["first"] = now                          # 重置窗口

    def reset(self, ip):                                       # 登录成功后清空记录
        with self._lock:                                       # 进入临界区
            self._state.pop(ip, None)                          # 删除该 IP 记录

LOGIN_GUARD = LoginGuard(MAX_LOGIN_FAILS, LOGIN_LOCK_SECONDS)   # 实例化限流器

# ============================ 四、通用工具函数 ============================
def safe_unlink(path):                                          # 安全删除文件
    try:                                                        # 任何异常都不外抛
        if path and os.path.isfile(path):                       # 必须是存在的普通文件
            os.unlink(path)                                     # 删除
    except OSError:                                             # 被占用 / 权限不足
        pass                                                    # 忽略，不影响主流程

def clean_sid(raw):                                             # 清洗学号
    return re.sub(r"[^A-Za-z0-9_-]", "", raw or "")[:20]        # 只留字母数字下划线短横线，截 20 位

def clean_name(raw):                                            # 清洗姓名
    return re.sub(r"[^\u4e00-\u9fa5A-Za-z0-9·]", "", raw or "")[:20]  # 中文、字母、数字、中点，截 20 位

def clean_stem(raw):                                            # 清洗原文件主名
    return re.sub(r"[^\w.\-]", "_", raw or "")[:MAX_STEM_LEN] or "file"  # 非法字符换下划线，截 40 位

def verify_password(password):                                  # 校验管理密码
    if not password:                                            # 空密码直接失败
        return False                                            # 返回否
    return check_password_hash(CONFIG_STORE.read()["password_hash"], password)  # 哈希比对

def is_default_password():                                      # 当前是否仍是默认密码
    return check_password_hash(CONFIG_STORE.read()["password_hash"], DEFAULT_PASSWORD)  # 用默认密码试一次

def set_password(password):                                     # 修改管理密码
    CONFIG_STORE.update(lambda cfg: {**cfg, "password_hash": generate_password_hash(password)})  # 原子更新哈希

def get_notices():                                              # 读公告列表
    return NOTICES_STORE.read()                                 # 直接返回

def add_notice(title, content):                                 # 新增公告
    notice = {"id": secrets.token_hex(4),                       # 随机 id，避免猜测
              "title": title,                                   # 标题
              "content": content,                               # 正文
              "time": datetime.now().strftime("%Y-%m-%d %H:%M")}  # 发布时间
    NOTICES_STORE.update(lambda items: [notice] + items[:49])   # 只保留最新 50 条
    return notice                                              # 返回新公告

def delete_notice(notice_id):                                   # 删除指定公告
    NOTICES_STORE.update(lambda items: [n for n in items if n.get("id") != notice_id])  # 过滤掉目标

def parse_deadline(text):                                       # 解析截止时间字符串
    try:                                                        # 格式必须是 YYYY-MM-DD HH:MM
        return datetime.strptime(text, "%Y-%m-%d %H:%M")        # 返回 datetime 对象
    except (ValueError, TypeError):                             # 格式不对或类型不对
        return None                                             # 返回空表示失败

def deadline_status():                                          # 判断当前是否可以提交
    raw = (CONFIG_STORE.read().get("deadline") or "").strip()   # 读配置中的截止时间
    if not raw:                                                 # 未设置
        return True, ""                                         # 允许提交
    parsed = parse_deadline(raw)                                # 解析
    if parsed is None:                                          # 手工改坏的格式
        print(f"[WARN] 截止时间格式非法，已忽略：{raw}")          # 打印警告
        return True, ""                                         # 视为未设置，避免误锁
    if datetime.now() > parsed:                                 # 已经过了截止时间
        return False, f"提交已截止（截止时间：{raw}）"            # 拒绝
    return True, ""                                             # 仍在时间内

def check_file_type(ext, header):                               # 校验后缀与文件头是否匹配
    for magic in EXEC_MAGIC:                                    # 先排查可执行文件特征
        if header.startswith(magic):                            # 命中 PE / ELF / Mach-O
            return False, "检测到可执行文件特征，已拒绝"          # 直接拒绝
    if ext in TEXT_EXTS:                                        # 纯文本类不再校验魔数
        return True, ""                                         # 放行
    expected = BINARY_MAGIC.get(ext)                            # 取该后缀应有的文件头
    if expected is None:                                        # 没有登记的后缀
        return True, ""                                         # 放行（已被白名单限制过）
    for magic in expected:                                      # 逐个比对
        if header.startswith(magic):                            # 命中
            return True, ""                                     # 放行
    return False, f"文件内容与后缀 {ext} 不匹配，可能是伪装文件"   # 不匹配则拒绝

def origin_ok():                                                # 同源校验，防 CSRF
    if not ENFORCE_ORIGIN:                                      # 允许关闭校验
        return True                                             # 直接放行
    origin = request.headers.get("Origin", "")                   # 取请求头
    if not origin:                                              # curl / 老客户端不带 Origin
        return True                                             # 放行（这类客户端发不起 CSRF）
    current = request.host_url.rstrip("/").lower()              # 当前站点根地址
    return origin.rstrip("/").lower() == current                # 必须完全一致

def cleanup_exports():                                          # 清理过期的导出临时文件
    try:                                                        # 目录不存在等异常都忽略
        now = time.time()                                       # 当前时间戳
        for name in os.listdir(EXPORT_DIR):                     # 遍历导出目录
            full = os.path.join(EXPORT_DIR, name)               # 完整路径
            if os.path.isfile(full) and now - os.path.getmtime(full) > 3600:  # 超过 1 小时
                safe_unlink(full)                               # 删除
    except OSError:                                             # 目录不可读
        pass                                                    # 忽略

def build_export_zip():                                         # 生成批量导出 ZIP
    cleanup_exports()                                           # 先清理旧文件
    items = SUBMISSIONS.list_all()                              # 取数据库记录作为白名单
    names = []                                                  # 实际要打包的文件名
    for item in items:                                          # 遍历记录
        filename = item.get("filename")                         # 磁盘文件名
        if filename and os.path.isfile(os.path.join(UPLOAD_DIR, filename)):  # 文件确实存在
            names.append(filename)                              # 加入白名单
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")            # 时间戳
    zip_path = os.path.join(EXPORT_DIR, f"submissions_{stamp}_{secrets.token_hex(3)}.zip")  # 临时 ZIP 路径
    with zipfile.ZipFile(zip_path, "w") as zf:                  # 创建 ZIP
        for filename in names:                                  # 逐个写入
            full = os.path.join(UPLOAD_DIR, filename)           # 源文件路径
            ext = os.path.splitext(filename)[1].lower()         # 后缀
            method = zipfile.ZIP_STORED if ext in COMPRESSED_EXTS else zipfile.ZIP_DEFLATED  # 已压缩的不再压缩
            zf.write(full, arcname=filename, compress_type=method)  # 写入并指定压缩方式
    return zip_path, len(names)                                 # 返回路径与文件数

def get_lan_ips():                                              # 收集本机所有候选 IPv4
    results = []                                                # 结果列表
    try:                                                        # 主机名解析可能失败
        for info in socket.getaddrinfo(socket.gethostname(), None):  # 枚举本机地址
            if info[0] != socket.AF_INET:                       # 只看 IPv4
                continue                                        # 跳过 IPv6
            address = info[4][0]                                # 取 IP
            if address and not address.startswith("127.") and address not in results:  # 排除回环并去重
                results.append(address)                         # 收集
    except OSError:                                             # 解析失败
        pass                                                    # 继续走下面的兜底
    if not results:                                             # 一个都没拿到
        try:                                                    # 用 UDP 探一次出口地址
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建 UDP 套接字
            probe.connect(("8.8.8.8", 80))                      # 不会真的发包，只查路由
            results.append(probe.getsockname()[0])              # 取本机出口 IP
            probe.close()                                       # 关闭套接字
        except OSError:                                         # 完全离线
            results.append("127.0.0.1")                         # 退回回环地址
    def rank(addr):                                             # 排序权重：常见内网段优先
        if addr.startswith("192.168."):                          # 家用 / 校园最常见
            return 0                                            # 最高优先
        if addr.startswith("10."):                               # 大型内网
            return 1                                            # 次优先
        if addr.startswith("172."):                              # Docker / 虚拟网卡常见
            return 2                                            # 再次
        return 3                                                # 其余排最后
    results.sort(key=rank)                                      # 排序
    return results                                              # 返回候选列表

# ============================ 五、路由 ============================
@app.route("/")                                                 # 首页
def index():                                                    # 返回内嵌页面
    return PAGE                                                 # Flask 自动设置 text/html

@app.route("/api/upload", methods=["POST"])                     # 学生上传
def api_upload():                                               # 处理上传
    if not origin_ok():                                         # 同源校验
        return jsonify({"ok": False, "message": "来源校验失败，请通过本机页面提交"}), 403  # 拒绝
    allowed, message = deadline_status()                        # 检查截止时间
    if not allowed:                                             # 已截止
        return jsonify({"ok": False, "message": message})       # 拒绝
    sid = clean_sid(request.form.get("student_id", ""))         # 清洗学号
    if not SID_RE.match(sid):                                   # 格式校验
        return jsonify({"ok": False, "message": "学号需为 2-20 位字母、数字、下划线或短横线"})  # 拒绝
    name = clean_name(request.form.get("student_name", ""))     # 清洗姓名
    if not name:                                                # 姓名不能为空
        return jsonify({"ok": False, "message": "请输入姓名"})   # 拒绝
    uploaded = request.files.get("file")                        # 取文件字段
    if not uploaded or not uploaded.filename:                   # 没选文件
        return jsonify({"ok": False, "message": "请选择文件"})   # 拒绝
    raw_name = os.path.basename(uploaded.filename.replace("\\", "/"))  # 去掉路径，防穿越
    stem, ext = os.path.splitext(raw_name)                      # 拆主名与后缀
    ext = ext.lower()                                           # 后缀统一小写
    if ext not in ALLOWED_EXT:                                  # 白名单校验
        return jsonify({"ok": False, "message": f"不支持的文件类型：{ext or '（无后缀）'}"})  # 拒绝
    header = uploaded.stream.read(16)                           # 读前 16 字节判魔数
    uploaded.stream.seek(0)                                     # 指针归位，便于后续保存
    ok, err = check_file_type(ext, header)                      # 内容校验
    if not ok:                                                  # 不通过
        return jsonify({"ok": False, "message": err})           # 拒绝
    try:                                                        # 磁盘容量检查
        free = shutil.disk_usage(UPLOAD_DIR).free               # 剩余空间
    except OSError:                                             # 查询失败
        free = MIN_FREE_BYTES                                   # 视为刚好够，交由大小限制兜底
    if free < MIN_FREE_BYTES:                                   # 空间不足
        return jsonify({"ok": False, "message": "服务器磁盘空间不足，请联系老师清理"})  # 拒绝
    count = SUBMISSIONS.count_by_student(sid)                   # 该学号已提交次数
    if count >= MAX_PER_STUDENT:                                # 达到上限
        return jsonify({"ok": False, "message": f"该学号已提交 {count} 次，达到上限（{MAX_PER_STUDENT} 次）"})  # 拒绝
    safe_stem = clean_stem(stem)                                # 清洗主名
    filename = f"{sid}_{name}_{safe_stem}{ext}"                 # 拼接存盘文件名
    if len(filename) > MAX_FILE_NAME_LEN:                       # 超长则再截
        filename = f"{sid}_{name}_{safe_stem[:20]}{ext}"        # 缩短主名
    if os.path.exists(os.path.join(UPLOAD_DIR, filename)):      # 同名冲突
        filename = f"{sid}_{name}_{safe_stem}_{secrets.token_hex(4)}{ext}"  # 追加随机后缀
    save_path = os.path.join(UPLOAD_DIR, filename)              # 最终路径
    try:                                                        # 保存 + 记录，失败要回滚文件
        uploaded.save(save_path)                                # 落盘
        size = os.path.getsize(save_path)                       # 实际大小
        if size == 0:                                           # 空文件
            raise ValueError("文件内容为空")                     # 触发回滚
        if size > MAX_SIZE:                                     # 超过单文件上限
            raise ValueError("文件超过 20 MB")                   # 触发回滚
        SUBMISSIONS.add(sid, name, filename, raw_name, size)    # 写数据库
    except Exception as exc:                                    # 任何失败
        safe_unlink(save_path)                                  # 删掉残留文件
        app.logger.warning("上传失败：%s", exc)                   # 记日志便于排查
        return jsonify({"ok": False, "message": f"保存失败：{exc}"})  # 返回错误
    remaining = MAX_PER_STUDENT - count - 1                     # 剩余可提交次数
    return jsonify({"ok": True,                                 # 成功标志
                    "message": f"上传成功（{size / 1024 / 1024:.2f} MB，还可提交 {remaining} 次）",  # 提示
                    "filename": filename})                      # 返回存盘名

@app.route("/api/auth", methods=["POST"])                       # 老师解锁
def api_auth():                                                 # 校验密码
    ip = request.remote_addr or "unknown"                       # 客户端地址（反代下会变成代理地址）
    wait = LOGIN_GUARD.blocked_seconds(ip)                      # 是否处于锁定期
    if wait > 0:                                                # 还在锁定期
        return jsonify({"ok": False, "message": f"尝试过于频繁，请 {wait} 秒后再试"}), 429  # 限流
    payload = request.get_json(silent=True) or {}               # 安静解析，避免 415/400
    if verify_password(str(payload.get("password", ""))):       # 密码正确
        LOGIN_GUARD.reset(ip)                                   # 清空失败计数
        return jsonify({"ok": True, "is_default": is_default_password()})  # 返回是否默认密码
    LOGIN_GUARD.record_failure(ip)                              # 记录一次失败
    return jsonify({"ok": False, "message": "密码错误"}), 403    # 拒绝

@app.route("/api/password", methods=["POST"])                   # 修改管理密码
def api_password():                                             # 处理改密
    if not origin_ok():                                         # 同源校验
        return jsonify({"ok": False, "message": "来源校验失败"}), 403  # 拒绝
    payload = request.get_json(silent=True) or {}               # 解析请求体
    if not verify_password(str(payload.get("old_password", ""))):  # 旧密码必须正确
        return jsonify({"ok": False, "message": "旧密码错误"}), 403  # 拒绝
    new_password = str(payload.get("new_password", ""))         # 新密码
    if not (MIN_PASSWORD_LEN <= len(new_password) <= MAX_PASSWORD_LEN):  # 长度校验
        return jsonify({"ok": False, "message": f"新密码长度需为 {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} 位"})  # 拒绝
    if not PASSWORD_RE.match(new_password):                     # 必须是可见 ASCII
        return jsonify({"ok": False, "message": "新密码只能使用英文、数字和英文符号（不支持中文）"})  # 拒绝
    if new_password == DEFAULT_PASSWORD:                        # 不允许继续用默认密码
        return jsonify({"ok": False, "message": "新密码不能继续使用默认密码"})  # 拒绝
    set_password(new_password)                                  # 写入新哈希
    return jsonify({"ok": True})                                # 成功

@app.route("/api/notices", methods=["GET"])                     # 读取公告（公开）
def api_notices_get():                                          # 返回列表
    return jsonify(get_notices())                               # 直接输出

@app.route("/api/notices", methods=["POST"])                    # 发布公告
def api_notices_post():                                         # 处理发布
    if not origin_ok():                                         # 同源校验
        return jsonify({"ok": False, "message": "来源校验失败"}), 403  # 拒绝
    payload = request.get_json(silent=True) or {}               # 解析请求体
    if not verify_password(str(payload.get("password", ""))):   # 校验密码
        return jsonify({"ok": False, "message": "密码错误"}), 403  # 拒绝
    title = str(payload.get("title", "")).strip()[:60]          # 标题截断
    content = str(payload.get("content", "")).strip()[:1000]    # 正文截断
    if not title or not content:                                # 不能为空
        return jsonify({"ok": False, "message": "标题和内容不能为空"})  # 拒绝
    add_notice(title, content)                                  # 写入存储
    return jsonify({"ok": True})                                # 成功

@app.route("/api/notices/delete", methods=["POST"])             # 删除公告（改用 POST）
def api_notices_delete():                                       # 处理删除
    if not origin_ok():                                         # 同源校验
        return jsonify({"ok": False, "message": "来源校验失败"}), 403  # 拒绝
    payload = request.get_json(silent=True) or {}               # 解析请求体
    if not verify_password(str(payload.get("password", ""))):   # 校验密码
        return jsonify({"ok": False, "message": "密码错误"}), 403  # 拒绝
    delete_notice(str(payload.get("id", "")))                   # 删除
    return jsonify({"ok": True})                                # 成功

@app.route("/api/list", methods=["GET"])                        # 作业列表
def api_list():                                                 # 需要密码
    if not verify_password(request.headers.get("X-Admin-Password", "")):  # header 校验
        return jsonify({"ok": False, "message": "密码错误"}), 403  # 拒绝
    return jsonify({"ok": True,                                # 成功
                    "items": SUBMISSIONS.list_all(),            # 全部记录
                    "stats": SUBMISSIONS.stats()})              # 统计

@app.route("/api/download_all", methods=["GET"])                # 一键下载
def api_download_all():                                         # 打包导出
    if not verify_password(request.headers.get("X-Admin-Password", "")):  # 校验密码
        return jsonify({"ok": False, "message": "密码错误"}), 403  # 拒绝
    try:                                                        # 打包可能失败
        zip_path, count = build_export_zip()                    # 生成 ZIP
    except OSError as exc:                                      # 磁盘/权限问题
        app.logger.exception("打包失败")                         # 记录堆栈
        return jsonify({"ok": False, "message": f"打包失败：{exc}"}), 500  # 返回错误
    response = send_file(zip_path,                              # 发送文件
                         mimetype="application/zip",            # MIME
                         as_attachment=True,                    # 作为附件下载
                         download_name=os.path.basename(zip_path))  # 下载文件名
    response.call_on_close(lambda path=zip_path: safe_unlink(path))  # 响应结束即删除临时文件
    return response                                             # 返回响应

@app.route("/api/deadline", methods=["GET"])                    # 读取截止时间（公开）
def api_deadline_get():                                         # 返回配置
    return jsonify({"deadline": CONFIG_STORE.read().get("deadline", "")})  # 输出

@app.route("/api/deadline", methods=["POST"])                   # 设置截止时间
def api_deadline_post():                                        # 处理设置
    if not origin_ok():                                         # 同源校验
        return jsonify({"ok": False, "message": "来源校验失败"}), 403  # 拒绝
    payload = request.get_json(silent=True) or {}               # 解析请求体
    if not verify_password(str(payload.get("password", ""))):   # 校验密码
        return jsonify({"ok": False, "message": "密码错误"}), 403  # 拒绝
    deadline = str(payload.get("deadline", "")).strip()         # 取值
    if deadline:                                                # 非空才校验
        parsed = parse_deadline(deadline)                       # 解析
        if parsed is None:                                      # 格式错误
            return jsonify({"ok": False, "message": "格式错误，应为 YYYY-MM-DD HH:MM"})  # 拒绝
        if parsed <= datetime.now():                            # 不允许设为过去
            return jsonify({"ok": False, "message": "截止时间必须晚于当前时间"})  # 拒绝
    CONFIG_STORE.update(lambda cfg: {**cfg, "deadline": deadline})  # 原子保存
    return jsonify({"ok": True})                                # 成功

@app.errorhandler(404)                                          # 404 统一处理
def on_404(error):                                              # 接口返回 JSON，页面返回文本
    if request.path.startswith("/api/"):                        # 接口路径
        return jsonify({"ok": False, "message": "接口不存在"}), 404  # JSON
    return "Not Found", 404                                     # 普通文本

@app.errorhandler(413)                                          # 请求体过大
def on_413(error):                                              # 返回明确提示
    return jsonify({"ok": False, "message": "文件或请求超过大小限制（单文件 20 MB）"}), 413  # JSON

@app.errorhandler(500)                                          # 服务器内部错误
def on_500(error):                                              # 记录堆栈后再返回
    app.logger.exception("服务器内部错误")                       # 写日志，便于排查
    return jsonify({"ok": False, "message": "服务器内部错误，请查看控制台日志"}), 500  # JSON

# ============================ 六、前端页面 ============================
PAGE = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>作业提交</title>
<style>
/* 主题变量：浅色与深色两套色板，切换靠 [data-theme] */
:root,[data-theme="light"]{--bg:#eef4fb;--text:#1a2436;--text-sub:#5b6b82;--glass-bg:rgba(255,255,255,.55);--glass-border:rgba(255,255,255,.75);--glass-shadow:0 8px 32px rgba(31,38,135,.12);--glass-inset:inset 0 1px 1px rgba(255,255,255,.85);--input-bg:rgba(255,255,255,.6);--input-border:rgba(0,0,0,.08);--accent:#3b82f6;--accent-hover:#2563eb;--danger:#ef4444;--blob-1:#a5d8ff;--blob-2:#d0bfff;--blob-3:#ffd8a8;--blob-opacity:.75}
[data-theme="dark"]{--bg:#0a0f1a;--text:#e6eef8;--text-sub:#8b9bb4;--glass-bg:rgba(20,30,48,.55);--glass-border:rgba(255,255,255,.08);--glass-shadow:0 8px 32px rgba(0,0,0,.4);--glass-inset:inset 0 1px 1px rgba(255,255,255,.06);--input-bg:rgba(255,255,255,.06);--input-border:rgba(255,255,255,.1);--accent:#60a5fa;--accent-hover:#3b82f6;--danger:#f87171;--blob-1:#1e3a8a;--blob-2:#4c1d95;--blob-3:#7c2d12;--blob-opacity:.5}
/* 基础重置与页面底色 */
*{box-sizing:border-box}html,body{margin:0;padding:0;min-height:100vh}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;color:var(--text);background:var(--bg);overflow-x:hidden;transition:background .3s,color .3s}
/* 背景光斑动画 */
.blob{position:fixed;border-radius:50%;filter:blur(90px);z-index:-1;pointer-events:none;opacity:var(--blob-opacity);transition:background .5s,opacity .5s}
.blob-1{width:50vmax;height:50vmax;background:var(--blob-1);top:-15vmax;left:-15vmax;animation:f1 22s ease-in-out infinite}
.blob-2{width:45vmax;height:45vmax;background:var(--blob-2);bottom:-15vmax;right:-15vmax;animation:f2 26s ease-in-out infinite}
.blob-3{width:35vmax;height:35vmax;background:var(--blob-3);top:30%;left:40%;animation:f3 30s ease-in-out infinite}
@keyframes f1{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(8vw,6vh) scale(1.1)}}
@keyframes f2{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-8vw,-6vh) scale(1.15)}}
@keyframes f3{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-5vw,8vh) scale(.9)}}
/* 毛玻璃卡片 */
.glass{background:var(--glass-bg);backdrop-filter:blur(24px) saturate(180%);-webkit-backdrop-filter:blur(24px) saturate(180%);border:1px solid var(--glass-border);box-shadow:var(--glass-shadow),var(--glass-inset);border-radius:22px}
.app{max-width:720px;margin:0 auto;padding:24px 16px 64px}
/* 顶部栏与标签 */
.topbar{padding:16px 20px;display:flex;align-items:center;justify-content:space-between;gap:16px;position:sticky;top:16px;z-index:10;margin-bottom:20px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:12px}.logo{font-size:28px}.brand h1{margin:0;font-size:18px;font-weight:700}.brand p{margin:2px 0 0;font-size:12px;color:var(--text-sub)}
.tabs{display:flex;gap:4px;padding:4px;background:rgba(0,0,0,.05);border-radius:12px;flex-wrap:wrap}[data-theme="dark"] .tabs{background:rgba(255,255,255,.05)}
.tab{border:none;background:transparent;padding:8px 14px;border-radius:8px;cursor:pointer;font-size:14px;color:var(--text-sub);transition:all .2s;font-family:inherit}
.tab:hover{color:var(--text)}.tab.active{background:var(--glass-bg);color:var(--text);box-shadow:0 2px 8px rgba(0,0,0,.08)}[data-theme="dark"] .tab.active{background:rgba(255,255,255,.1)}
/* 视图切换动画 */
.view{display:none}.view.active{display:block;animation:fadeIn .25s ease}@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.card{padding:24px;margin-bottom:20px}.card h2{margin:0 0 6px;font-size:18px;font-weight:700}.hint{color:var(--text-sub);font-size:13px;margin:0 0 16px;line-height:1.6}
/* 表单 */
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}@media (max-width:480px){.form-row{grid-template-columns:1fr}}
.field{display:flex;flex-direction:column;gap:6px;margin-bottom:12px}.field label{font-size:13px;color:var(--text-sub)}
.field input,.field textarea{width:100%;padding:12px 14px;border-radius:12px;border:1px solid var(--input-border);background:var(--input-bg);color:var(--text);font-size:15px;font-family:inherit;transition:border .2s,box-shadow .2s;outline:none}
.field input:focus,.field textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
/* 拖拽上传区 */
.dropzone{border:2px dashed var(--input-border);border-radius:16px;padding:32px 20px;text-align:center;cursor:pointer;transition:all .2s;background:var(--input-bg);margin:8px 0 16px}
.dropzone:hover,.dropzone.over{border-color:var(--accent);background:rgba(59,130,246,.06)}
.dz-icon{font-size:32px;margin-bottom:8px;opacity:.6}.dz-text{color:var(--text-sub);font-size:14px}.dz-file{margin-top:8px;font-size:13px;color:var(--accent);font-weight:600;word-break:break-all}
/* 按钮与结果提示 */
.btn{padding:12px 20px;border-radius:12px;border:1px solid var(--input-border);background:var(--input-bg);color:var(--text);font-size:15px;font-weight:600;cursor:pointer;font-family:inherit;transition:all .2s}
.btn:hover{transform:translateY(-1px)}
.btn.primary{background:linear-gradient(135deg,var(--accent),var(--accent-hover));color:#fff;border:none;width:100%;padding:14px;font-size:16px;box-shadow:0 4px 16px rgba(59,130,246,.35)}
.btn.primary:hover{box-shadow:0 6px 20px rgba(59,130,246,.45)}
.btn.ghost{background:transparent}.btn.small{padding:8px 14px;font-size:13px}
.result{margin-top:14px;font-size:14px;padding:12px 14px;border-radius:10px;display:none;word-break:break-all;white-space:pre-wrap}
.result.ok{display:block;background:rgba(34,197,94,.12);color:#15803d}.result.err{display:block;background:rgba(239,68,68,.12);color:var(--danger)}[data-theme="dark"] .result.ok{color:#4ade80}
/* 公告列表 */
.card-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;gap:12px}.card-head h2{margin:0}
.notice-list{display:flex;flex-direction:column;gap:12px}.notice-item{padding:16px;border-radius:14px;background:var(--input-bg);border:1px solid var(--input-border)}
.notice-head{display:flex;justify-content:space-between;align-items:baseline;gap:12px;margin-bottom:8px}.notice-head strong{font-size:15px;word-break:break-all}.notice-time{font-size:12px;color:var(--text-sub);white-space:nowrap}
.notice-content{font-size:14px;line-height:1.6;word-break:break-word}.empty{text-align:center;color:var(--text-sub);padding:32px;font-size:14px}
.btn-text{background:none;border:none;color:var(--text-sub);cursor:pointer;font-size:12px;padding:4px 8px;font-family:inherit;margin-top:8px}.btn-text.danger:hover{color:var(--danger)}
/* 主题选择卡片 */
.theme-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.theme-opt{background:var(--input-bg);border:2px solid var(--input-border);border-radius:14px;padding:12px;cursor:pointer;font-family:inherit;color:var(--text);transition:all .2s;display:flex;flex-direction:column;align-items:center;gap:8px}
.theme-opt:hover{border-color:var(--accent)}.theme-opt.active{border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
.theme-preview{width:100%;height:48px;border-radius:8px}.theme-preview.light{background:linear-gradient(135deg,#eef4fb,#d0e3ff)}.theme-preview.dark{background:linear-gradient(135deg,#0a0f1a,#1e3a8a)}.theme-preview.auto{background:linear-gradient(135deg,#eef4fb 50%,#0a0f1a 50%)}
.theme-opt span{font-size:13px}
/* 弹窗 */
.modal-mask{position:fixed;inset:0;background:rgba(0,0,0,.4);backdrop-filter:blur(4px);display:none;align-items:center;justify-content:center;z-index:100;padding:20px}
.modal-mask.show{display:flex;animation:fadeIn .2s ease}.modal{padding:24px;width:100%;max-width:480px}.modal h2{margin:0 0 16px;font-size:18px}
.modal-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:16px}.modal-actions .btn{width:auto}
/* 提交列表与统计 */
.sub-item{padding:12px 14px;border-radius:12px;background:var(--input-bg);border:1px solid var(--input-border);display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:8px}
.sub-main{flex:1;min-width:0}.sub-main strong{font-size:14px;display:block;margin-bottom:2px}.sub-file{font-size:12px;color:var(--text-sub);word-break:break-all}.sub-time{font-size:12px;color:var(--text-sub);white-space:nowrap}
.stats{display:flex;gap:20px;padding:14px 18px;border-radius:14px;background:var(--input-bg);border:1px solid var(--input-border);margin-bottom:16px}
.stats div{display:flex;flex-direction:column}.stats b{font-size:20px;color:var(--accent)}.stats span{font-size:12px;color:var(--text-sub)}
</style>
</head>
<body>
<div class="blob blob-1"></div><div class="blob blob-2"></div><div class="blob blob-3"></div>
<div class="app">
  <header class="glass topbar">
    <div class="brand"><div class="logo">📚</div><div><h1>作业提交</h1><p>局域网 · 单文件上传</p></div></div>
    <nav class="tabs">
      <button class="tab active" data-view="upload">上传</button>
      <button class="tab" data-view="notice">公告</button>
      <button class="tab" data-view="submissions" id="tab-submissions" style="display:none">作业</button>
      <button class="tab" data-view="settings">设置</button>
    </nav>
  </header>
  <main>
    <section class="view active" id="view-upload">
      <div class="glass card">
        <h2>提交作业</h2>
        <p class="hint" id="upload-hint">支持文档、压缩包、图片，单个文件 ≤ 20 MB · 每人最多 3 次</p>
        <div class="form-row">
          <div class="field"><label>学号</label><input type="text" id="sid" placeholder="例如 1001" maxlength="20"></div>
          <div class="field"><label>姓名</label><input type="text" id="sname" placeholder="例如 张三" maxlength="20"></div>
        </div>
        <div class="dropzone" id="dropzone">
          <input type="file" id="file" hidden>
          <div class="dz-icon">⬆</div>
          <div class="dz-text">点击选择文件，或拖拽到此处</div>
          <div class="dz-file" id="dz-file"></div>
        </div>
        <button class="btn primary" id="btn-upload">提交作业</button>
        <div class="result" id="upload-result"></div>
      </div>
    </section>
    <section class="view" id="view-notice">
      <div class="glass card">
        <div class="card-head"><h2>公告区</h2><button class="btn ghost small" id="btn-notice-teacher" style="display:none">老师发布</button></div>
        <div id="notice-list" class="notice-list"><div class="empty">暂无公告</div></div>
      </div>
    </section>
    <section class="view" id="view-submissions">
      <div class="glass card">
        <div class="card-head"><h2>作业列表</h2><button class="btn ghost small" id="btn-download-all" style="display:none">一键下载</button></div>
        <div class="stats" id="sub-stats" style="display:none"><div><b id="stat-total">0</b><span>提交次数</span></div><div><b id="stat-students">0</b><span>学生人数</span></div></div>
        <div id="submissions-list"><div class="empty">加载中...</div></div>
      </div>
    </section>
    <section class="view" id="view-settings">
      <div class="glass card">
        <h2>外观</h2><p class="hint">选择你喜欢的显示模式</p>
        <div class="theme-grid">
          <button class="theme-opt" data-theme-opt="light"><div class="theme-preview light"></div><span>浅色</span></button>
          <button class="theme-opt" data-theme-opt="dark"><div class="theme-preview dark"></div><span>深色</span></button>
          <button class="theme-opt" data-theme-opt="auto"><div class="theme-preview auto"></div><span>跟随系统</span></button>
        </div>
      </div>
      <div class="glass card">
        <h2>老师模式</h2>
        <div id="teacher-off">
          <p class="hint">输入管理密码解锁发公告、查看作业列表、修改密码等功能</p>
          <div class="field"><label>管理密码</label><input type="password" id="teacher-pwd" placeholder="默认 admin888"></div>
          <button class="btn primary" id="btn-login">解锁</button>
        </div>
        <div id="teacher-on" style="display:none">
          <p class="hint">已解锁。前往公告页发布通知，作业页查看列表，下方修改密码和截止时间。</p>
          <div class="field"><label>修改密码（4-64 位英文、数字或英文符号）</label><input type="password" id="new-pwd" placeholder="新密码（不支持中文）"></div>
          <button class="btn" id="btn-change-pwd">修改密码</button>
          <div class="field" style="margin-top:20px"><label>截止时间（YYYY-MM-DD HH:MM）</label><input type="text" id="deadline-input" placeholder="留空表示不限制，例如 2025-12-31 23:59"></div>
          <button class="btn" id="btn-save-deadline">保存截止时间</button>
          <button class="btn ghost" id="btn-logout" style="margin-top:12px">退出老师模式</button>
        </div>
        <div class="result" id="settings-result"></div>
      </div>
    </section>
  </main>
</div>
<div class="modal-mask" id="notice-modal">
  <div class="glass modal">
    <h2>发布公告</h2>
    <div class="field"><label>标题</label><input type="text" id="notice-title" placeholder="例如 本周作业截止时间" maxlength="60"></div>
    <div class="field"><label>内容</label><textarea id="notice-content" placeholder="公告内容..." maxlength="1000" rows="5"></textarea></div>
    <div class="modal-actions"><button class="btn ghost" id="modal-cancel">取消</button><button class="btn primary" id="modal-confirm">发布</button></div>
  </div>
</div>
<script>
/* ========== 常量与安全存储封装 ========== */
var THEME_KEY = 'homework-theme';                      // localStorage 中保存主题偏好的键名
var TEACHER_KEY = 'homework-teacher-pwd';              // sessionStorage 中保存管理密码的键名

function safeLocalGet(key) {                           // 读 localStorage（隐私模式可能抛错）
  try { return localStorage.getItem(key); } catch (e) { return null; }   // 失败返回 null
}
function safeLocalSet(key, value) {                    // 写 localStorage
  try { localStorage.setItem(key, value); } catch (e) {}                 // 失败静默忽略
}
function safeSessionGet(key) {                         // 读 sessionStorage
  try { return sessionStorage.getItem(key); } catch (e) { return null; } // 失败返回 null
}
function safeSessionSet(key, value) {                  // 写 sessionStorage
  try { sessionStorage.setItem(key, value); } catch (e) {}               // 失败静默忽略
}
function safeSessionDel(key) {                         // 删 sessionStorage
  try { sessionStorage.removeItem(key); } catch (e) {}                   // 失败静默忽略
}

/* ========== 主题：解析 / 应用 / 监听系统变化 ========== */
function resolveTheme(pref) {                          // 把偏好解析成具体主题
  if (pref === 'light' || pref === 'dark') return pref;                  // 显式指定直接用
  var mq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;  // 读系统偏好
  return mq && mq.matches ? 'dark' : 'light';                          // 系统深色则用深色
}
function applyTheme(pref) {                            // 应用主题
  document.documentElement.dataset.theme = resolveTheme(pref);         // 写入 data-theme 属性
}
function setThemePreference(pref) {                    // 用户点击主题卡片
  safeLocalSet(THEME_KEY, pref);                       // 持久化偏好
  applyTheme(pref);                                    // 立即生效
  document.querySelectorAll('.theme-opt').forEach(function (el) {      // 遍历三张卡片
    el.classList.toggle('active', el.dataset.themeOpt === pref);       // 只高亮当前项
  });
}
function onSchemeChange() {                            // 系统主题变化回调
  if ((safeLocalGet(THEME_KEY) || 'auto') === 'auto') applyTheme('auto');  // 仅自动模式跟随
}
(function bindSchemeWatcher() {                        // 绑定系统主题监听（兼容旧浏览器）
  if (!window.matchMedia) return;                      // 不支持就直接跳过，防止抛错中断脚本
  var mq = window.matchMedia('(prefers-color-scheme: dark)');  // 媒体查询对象
  if (typeof mq.addEventListener === 'function') {     // 现代浏览器
    mq.addEventListener('change', onSchemeChange);     // 标准写法
  } else if (typeof mq.addListener === 'function') {   // Safari 13 及以下
    mq.addListener(onSchemeChange);                    // 兼容写法
  }
})();

/* ========== 视图切换 ========== */
function switchView(name) {                            // 切换标签页
  document.querySelectorAll('.view').forEach(function (v) {            // 遍历所有视图
    v.classList.toggle('active', v.id === 'view-' + name);             // 只显示目标
  });
  document.querySelectorAll('.tab').forEach(function (t) {             // 遍历所有标签按钮
    t.classList.toggle('active', t.dataset.view === name);             // 只高亮目标
  });
  if (name === 'notice') loadNotices();                                // 进入公告页就刷新
  if (name === 'submissions') loadSubmissions();                       // 进入作业页就刷新
}

/* ========== 通用工具 ========== */
function escapeHtml(value) {                           // 转义 HTML 特殊字符，防 XSS
  return String(value).replace(/[&<>"']/g, function (ch) {             // 逐个字符替换
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch];  // 映射表
  });
}
function fmtSize(bytes) {                              // 字节数转可读大小
  if (bytes < 1024) return bytes + ' B';                               // 不足 1KB
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';       // 不足 1MB
  return (bytes / 1048576).toFixed(2) + ' MB';                         // 超过 1MB
}
function passwordAsciiOk(pwd) {                        // 检查密码能否放进 HTTP header
  return /^[\x21-\x7E]*$/.test(pwd);                   // 只允许可见 ASCII
}
async function apiFetch(url, options) {                // 统一封装请求
  var response = await fetch(url, options);            // 发送请求
  if (response.status === 403 && url.indexOf('/api/auth') !== 0) {     // 密码失效（登录接口除外）
    clearTeacherPwd();                                 // 清掉过期密码
    updateTeacherUI();                                 // UI 退回学生模式
  }
  return response;                                     // 原样返回给调用方
}

/* ========== 老师登录态 ========== */
function isTeacher() { return !!safeSessionGet(TEACHER_KEY); }          // 是否已解锁
function getTeacherPwd() { return safeSessionGet(TEACHER_KEY) || ''; }  // 取密码
function setTeacherPwd(pwd) { safeSessionSet(TEACHER_KEY, pwd); }       // 存密码
function clearTeacherPwd() { safeSessionDel(TEACHER_KEY); }             // 清密码
function updateTeacherUI() {                            // 根据登录态刷新界面
  var on = isTeacher();                                 // 是否已解锁
  document.getElementById('teacher-off').style.display = on ? 'none' : '';   // 未解锁面板
  document.getElementById('teacher-on').style.display = on ? '' : 'none';    // 已解锁面板
  document.getElementById('btn-notice-teacher').style.display = on ? '' : 'none';  // 发布公告按钮
  document.getElementById('tab-submissions').style.display = on ? '' : 'none';      // 作业标签
  document.getElementById('btn-download-all').style.display = on ? '' : 'none';     // 一键下载按钮
  if (!on && document.getElementById('view-submissions').classList.contains('active')) {  // 退出时停在作业页
    switchView('upload');                              // 退回上传页
  }
}

/* ========== 文件选择与拖拽 ========== */
var dropzone = document.getElementById('dropzone');     // 拖拽区
var fileInput = document.getElementById('file');       // 隐藏的文件输入
var dzFile = document.getElementById('dz-file');        // 已选文件显示区

dropzone.addEventListener('click', function () { fileInput.click(); });  // 点区域等于点输入框
dropzone.addEventListener('dragover', function (event) {                 // 拖入时高亮
  event.preventDefault();                              // 阻止浏览器默认打开文件
  dropzone.classList.add('over');                      // 加高亮样式
});
dropzone.addEventListener('dragleave', function () { dropzone.classList.remove('over'); });  // 拖出取消高亮
dropzone.addEventListener('drop', function (event) {   // 松手放下文件
  event.preventDefault();                              // 阻止默认行为
  dropzone.classList.remove('over');                   // 取消高亮
  var files = event.dataTransfer && event.dataTransfer.files;  // 取拖入的文件列表
  if (!files || !files.length) return;                 // 没有文件就退出
  try {                                                // 旧浏览器可能不支持 DataTransfer
    var bucket = new DataTransfer();                   // 构造可写文件列表
    bucket.items.add(files[0]);                        // 只取第一个文件
    fileInput.files = bucket.files;                    // 赋给 input（现代浏览器支持）
  } catch (err) {                                      // 构造失败
    dzFile.textContent = '当前浏览器不支持拖拽，请点击选择文件';  // 降级提示
    return;                                            // 不再继续
  }
  showFile();                                          // 刷新文件名显示
});
fileInput.addEventListener('change', showFile);         // 选择文件后刷新显示
function showFile() {                                  // 显示已选文件名和大小
  if (fileInput.files.length) {                        // 有文件
    var f = fileInput.files[0];                        // 取第一个
    dzFile.textContent = f.name + '（' + fmtSize(f.size) + '）';  // 显示名称与大小
  } else {                                             // 没文件
    dzFile.textContent = '';                           // 清空显示
  }
}

/* ========== 上传 ========== */
document.getElementById('btn-upload').addEventListener('click', async function () {
  var sid = document.getElementById('sid').value.trim();     // 学号
  var sname = document.getElementById('sname').value.trim(); // 姓名
  var result = document.getElementById('upload-result');     // 结果框
  result.className = 'result';                               // 重置样式
  result.textContent = '';                                   // 清空文字
  if (!sid || !sname) {                                      // 缺字段
    result.classList.add('err');                             // 错误样式
    result.textContent = '请填写学号和姓名';                  // 提示
    return;                                                  // 中断
  }
  if (!fileInput.files.length) {                             // 没选文件
    result.classList.add('err');                             // 错误样式
    result.textContent = '请选择文件';                        // 提示
    return;                                                  // 中断
  }
  var form = new FormData();                                 // 组装表单
  form.append('student_id', sid);                            // 学号字段
  form.append('student_name', sname);                        // 姓名字段
  form.append('file', fileInput.files[0]);                   // 文件字段
  try {                                                      // 网络异常兜底
    var response = await apiFetch('/api/upload', { method: 'POST', body: form });  // 发送
    var data = await response.json();                        // 解析 JSON
    result.classList.add(data.ok ? 'ok' : 'err');            // 按结果上色
    result.textContent = data.message || (data.ok ? '上传成功' : '上传失败');  // 显示消息
    if (data.ok) {                                           // 成功后清空选择
      fileInput.value = '';                                  // 清空 input
      dzFile.textContent = '';                               // 清空文件名
    }
  } catch (err) {                                            // 网络或解析失败
    result.classList.add('err');                             // 错误样式
    result.textContent = '网络错误：' + err.message;          // 提示
  }
});

/* ========== 公告 ========== */
async function loadNotices() {                               // 加载公告列表
  var list = document.getElementById('notice-list');         // 容器
  try {                                                      // 网络异常兜底
    var response = await fetch('/api/notices');              // 公告是公开接口
    var data = await response.json();                        // 解析
    if (!Array.isArray(data) || !data.length) {              // 空列表
      list.innerHTML = '<div class="empty">暂无公告</div>';   // 占位
      return;                                                // 结束
    }
    list.innerHTML = data.map(function (notice) {            // 逐条渲染
      var body = escapeHtml(notice.content).replace(/\n/g, '<br>');  // 转义并保留换行
      var del = isTeacher() ? '<button class="btn-text danger" data-del="' + escapeHtml(notice.id) + '">删除</button>' : '';  // 老师才有删除按钮
      return '<div class="notice-item">'                     // 卡片开始
        + '<div class="notice-head"><strong>' + escapeHtml(notice.title) + '</strong>'  // 标题
        + '<span class="notice-time">' + escapeHtml(notice.time) + '</span></div>'       // 时间
        + '<div class="notice-content">' + body + '</div>'   // 正文
        + del + '</div>';                                    // 删除按钮 + 卡片结束
    }).join('');                                             // 拼接成 HTML
    list.querySelectorAll('[data-del]').forEach(function (btn) {  // 绑定删除事件，避免内联 onclick
      btn.addEventListener('click', function () { deleteNotice(btn.dataset.del); });  // 传公告 id
    });
  } catch (err) {                                            // 请求失败
    list.innerHTML = '<div class="empty">加载失败</div>';     // 占位
  }
}
async function deleteNotice(id) {                            // 删除公告
  if (!confirm('确定删除这条公告？')) return;                 // 二次确认
  try {                                                      // 网络异常兜底
    var response = await apiFetch('/api/notices/delete', {   // 改用 POST，避免 DELETE 带 body 的兼容问题
      method: 'POST',                                        // 方法
      headers: { 'Content-Type': 'application/json' },        // JSON 请求体
      body: JSON.stringify({ password: getTeacherPwd(), id: id })  // 密码 + 公告 id
    });
    var data = await response.json();                        // 解析
    if (data.ok) loadNotices();                              // 成功则刷新
    else alert(data.message || '删除失败');                   // 失败提示
  } catch (err) {                                            // 网络异常
    alert('网络错误：' + err.message);                        // 提示
  }
}

/* ========== 老师模式：解锁 / 改密 / 退出 ========== */
document.getElementById('btn-login').addEventListener('click', async function () {
  var pwd = document.getElementById('teacher-pwd').value;     // 输入框密码
  var result = document.getElementById('settings-result');    // 结果框
  result.className = 'result';                                // 重置样式
  result.textContent = '';                                    // 清空文字
  if (!pwd) {                                                 // 空密码
    result.classList.add('err');                              // 错误样式
    result.textContent = '请输入管理密码';                     // 提示
    return;                                                   // 中断
  }
  try {                                                       // 网络异常兜底
    var response = await apiFetch('/api/auth', {              // 校验密码
      method: 'POST',                                         // 方法
      headers: { 'Content-Type': 'application/json' },         // JSON
      body: JSON.stringify({ password: pwd })                 // 密码
    });
    var data = await response.json();                        
