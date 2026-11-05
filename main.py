# -*- coding: utf-8 -*-
"""
局域网作业收集系统 —— 液态玻璃 UI 单文件版
运行：python main.py
打包：pyinstaller --onefile --name 作业收集 main.py
"""
import os
import re
import sys
import json
import socket
import secrets
import tempfile
import threading
from datetime import datetime

from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- 路径 ----------
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DATA_DIR   = os.path.join(BASE_DIR, "data")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

CONFIG_FILE  = os.path.join(DATA_DIR, "config.json")
NOTICES_FILE = os.path.join(DATA_DIR, "notices.json")

# ---------- 配置 ----------
DEFAULT_PASSWORD = "admin888"
MAX_SIZE = 20 * 1024 * 1024
ALLOWED_EXT = {
    ".txt", ".md", ".py", ".c", ".cpp", ".java", ".html", ".css", ".js",
    ".zip", ".rar", ".7z",
    ".doc", ".docx", ".pdf", ".ppt", ".pptx", ".xls", ".xlsx",
    ".jpg", ".jpeg", ".png",
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_SIZE


# ---------- 线程安全 JSON 存储 ----------
class JsonStore:
    """RLock 保护 + 临时文件原子替换，解决并发读-改-写和半截文件问题。"""

    def __init__(self, path: str, default_factory):
        self.path = path
        self.default_factory = default_factory
        self._lock = threading.RLock()
        if not os.path.exists(path):
            self._atomic_write(default_factory())

    def _read_unlocked(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return self.default_factory()

    def _atomic_write(self, data):
        d = os.path.dirname(self.path) or "."
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp_", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def read(self):
        with self._lock:
            return self._read_unlocked()

    def write(self, data):
        with self._lock:
            self._atomic_write(data)

    def update(self, mutator):
        with self._lock:
            data = self._read_unlocked()
            new_data = mutator(data)
            self._atomic_write(new_data)
            return new_data


CONFIG_STORE = JsonStore(
    CONFIG_FILE,
    lambda: {"password_hash": generate_password_hash(DEFAULT_PASSWORD)},
)
NOTICES_STORE = JsonStore(NOTICES_FILE, list)


# ---------- 密码 & 公告 ----------
def get_password_hash() -> str:
    return CONFIG_STORE.read()["password_hash"]


def set_password(new_pwd: str):
    CONFIG_STORE.write({"password_hash": generate_password_hash(new_pwd)})


def verify_password(pwd: str) -> bool:
    return bool(pwd) and check_password_hash(get_password_hash(), pwd)


def get_notices() -> list:
    return NOTICES_STORE.read()


def add_notice(title: str, content: str) -> dict:
    notice = {
        "id": secrets.token_hex(4),
        "title": title,
        "content": content,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }

    def mutator(notices):
        notices.insert(0, notice)
        return notices[:50]

    NOTICES_STORE.update(mutator)
    return notice


def delete_notice(nid: str):
    NOTICES_STORE.update(lambda notices: [n for n in notices if n.get("id") != nid])


# ---------- 工具 ----------
def clean_field(s, max_len=32) -> str:
    s = re.sub(r"[^\w\u4e00-\u9fa5]", "", s or "")
    return s[:max_len]


# ---------- API ----------
@app.route("/")
def index():
    return PAGE


@app.route("/api/upload", methods=["POST"])
def api_upload():
    sid  = clean_field(request.form.get("student_id", ""))
    name = clean_field(request.form.get("student_name", ""))

    if not sid or not name:
        return jsonify({"ok": False, "message": "学号和姓名不能为空，且只能包含中英文、数字、下划线"})

    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"ok": False, "message": "请选择要上传的文件"})

    raw = os.path.basename(f.filename.replace("\\", "/"))
    stem, ext = os.path.splitext(raw)
    ext = ext.lower()

    if ext not in ALLOWED_EXT:
        return jsonify({"ok": False, "message": f"不支持的文件类型：{ext or '(无后缀)'}"})

    safe_stem = re.sub(r"[^\w\u4e00-\u9fa5.\-]", "_", stem)[:64] or "file"
    final_name = f"{sid}_{name}_{safe_stem}{ext}"
    save_path = os.path.join(UPLOAD_DIR, final_name)

    if os.path.exists(save_path):
        stamp = datetime.now().strftime("%Y%m%d%H%M%S")
        final_name = f"{sid}_{name}_{safe_stem}_{stamp}{ext}"
        save_path = os.path.join(UPLOAD_DIR, final_name)

    try:
        f.save(save_path)
    except Exception as e:
        return jsonify({"ok": False, "message": f"保存失败：{e}"})

    size_mb = os.path.getsize(save_path) / 1024 / 1024
    return jsonify({
        "ok": True,
        "message": f"上传成功（{size_mb:.2f} MB）",
        "filename": final_name,
    })


@app.route("/api/auth", methods=["POST"])
def api_auth():
    data = request.get_json() or {}
    if verify_password(data.get("password", "")):
        return jsonify({"ok": True})
    return jsonify({"ok": False, "message": "密码错误"}), 403


@app.route("/api/password", methods=["POST"])
def api_password():
    data = request.get_json() or {}
    if not verify_password(data.get("old_password", "")):
        return jsonify({"ok": False, "message": "旧密码错误"}), 403
    new_pwd = data.get("new_password", "")
    if len(new_pwd) < 4:
        return jsonify({"ok": False, "message": "新密码至少 4 位"})
    set_password(new_pwd)
    return jsonify({"ok": True})


@app.route("/api/notices", methods=["GET"])
def api_notices_get():
    return jsonify(get_notices())


@app.route("/api/notices", methods=["POST"])
def api_notices_post():
    data = request.get_json() or {}
    if not verify_password(data.get("password", "")):
        return jsonify({"ok": False, "message": "密码错误"}), 403
    title = (data.get("title") or "").strip()[:60]
    content = (data.get("content") or "").strip()[:1000]
    if not title or not content:
        return jsonify({"ok": False, "message": "标题和内容不能为空"})
    add_notice(title, content)
    return jsonify({"ok": True})


@app.route("/api/notices/<nid>", methods=["DELETE"])
def api_notices_delete(nid):
    data = request.get_json() or {}
    if not verify_password(data.get("password", "")):
        return jsonify({"ok": False, "message": "密码错误"}), 403
    delete_notice(nid)
    return jsonify({"ok": True})


@app.errorhandler(413)
def on_413(e):
    return jsonify({"ok": False, "message": "文件超过 20 MB 限制，请压缩后再传"}), 413


@app.errorhandler(500)
def on_500(e):
    return jsonify({"ok": False, "message": "服务器内部错误"}), 500


# ---------- 前端 ----------
PAGE = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>作业提交</title>
<style>
*{box-sizing:border-box}
html,body{margin:0;padding:0;min-height:100vh}
body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
  color:var(--text);background:var(--bg);overflow-x:hidden;
  transition:background .3s,color .3s;
}
:root,[data-theme="light"]{
  --bg:#eef4fb;--text:#1a2436;--text-sub:#5b6b82;
  --glass-bg:rgba(255,255,255,.55);--glass-border:rgba(255,255,255,.75);
  --glass-shadow:0 8px 32px rgba(31,38,135,.12);
  --glass-inset:inset 0 1px 1px rgba(255,255,255,.85);
  --input-bg:rgba(255,255,255,.6);--input-border:rgba(0,0,0,.08);
  --accent:#3b82f6;--accent-hover:#2563eb;--danger:#ef4444;
  --blob-1:#a5d8ff;--blob-2:#d0bfff;--blob-3:#ffd8a8;--blob-opacity:.75;
}
[data-theme="dark"]{
  --bg:#0a0f1a;--text:#e6eef8;--text-sub:#8b9bb4;
  --glass-bg:rgba(20,30,48,.55);--glass-border:rgba(255,255,255,.08);
  --glass-shadow:0 8px 32px rgba(0,0,0,.4);
  --glass-inset:inset 0 1px 1px rgba(255,255,255,.06);
  --input-bg:rgba(255,255,255,.06);--input-border:rgba(255,255,255,.1);
  --accent:#60a5fa;--accent-hover:#3b82f6;--danger:#f87171;
  --blob-1:#1e3a8a;--blob-2:#4c1d95;--blob-3:#7c2d12;--blob-opacity:.5;
}
.blob{position:fixed;border-radius:50%;filter:blur(90px);z-index:-1;pointer-events:none;
  opacity:var(--blob-opacity);transition:background .5s,opacity .5s}
.blob-1{width:50vmax;height:50vmax;background:var(--blob-1);top:-15vmax;left:-15vmax;animation:f1 22s ease-in-out infinite}
.blob-2{width:45vmax;height:45vmax;background:var(--blob-2);bottom:-15vmax;right:-15vmax;animation:f2 26s ease-in-out infinite}
.blob-3{width:35vmax;height:35vmax;background:var(--blob-3);top:30%;left:40%;animation:f3 30s ease-in-out infinite}
@keyframes f1{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(8vw,6vh) scale(1.1)}}
@keyframes f2{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-8vw,-6vh) scale(1.15)}}
@keyframes f3{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-5vw,8vh) scale(.9)}}
.glass{
  background:var(--glass-bg);
  backdrop-filter:blur(24px) saturate(180%);
  -webkit-backdrop-filter:blur(24px) saturate(180%);
  border:1px solid var(--glass-border);
  box-shadow:var(--glass-shadow),var(--glass-inset);
  border-radius:22px;
}
.app{max-width:720px;margin:0 auto;padding:24px 16px 64px}
.topbar{padding:16px 20px;display:flex;align-items:center;justify-content:space-between;
  gap:16px;position:sticky;top:16px;z-index:10;margin-bottom:20px}
.brand{display:flex;align-items:center;gap:12px}
.logo{font-size:28px}
.brand h1{margin:0;font-size:18px;font-weight:700}
.brand p{margin:2px 0 0;font-size:12px;color:var(--text-sub)}
.tabs{display:flex;gap:4px;padding:4px;background:rgba(0,0,0,.05);border-radius:12px}
[data-theme="dark"] .tabs{background:rgba(255,255,255,.05)}
.tab{border:none;background:transparent;padding:8px 14px;border-radius:8px;cursor:pointer;
  font-size:14px;color:var(--text-sub);transition:all .2s;font-family:inherit}
.tab:hover{color:var(--text)}
.tab.active{background:var(--glass-bg);color:var(--text);box-shadow:0 2px 8px rgba(0,0,0,.08)}
[data-theme="dark"] .tab.active{background:rgba(255,255,255,.1)}
.view{display:none}
.view.active{display:block;animation:fadeIn .25s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.card{padding:24px;margin-bottom:20px}
.card h2{margin:0 0 6px;font-size:18px;font-weight:700}
.hint{color:var(--text-sub);font-size:13px;margin:0 0 16px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
@media (max-width:480px){.form-row{grid-template-columns:1fr}}
.field{display:flex;flex-direction:column;gap:6px;margin-bottom:12px}
.field label{font-size:13px;color:var(--text-sub)}
.field input,.field textarea{
  width:100%;padding:12px 14px;border-radius:12px;
  border:1px solid var(--input-border);background:var(--input-bg);
  color:var(--text);font-size:15px;font-family:inherit;
  transition:border .2s,box-shadow .2s;outline:none
}
.field input:focus,.field textarea:focus{
  border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.15)
}
.dropzone{
  border:2px dashed var(--input-border);border-radius:16px;padding:32px 20px;
  text-align:center;cursor:pointer;transition:all .2s;background:var(--input-bg);margin:8px 0 16px
}
.dropzone:hover,.dropzone.over{border-color:var(--accent);background:rgba(59,130,246,.06)}
.dz-icon{font-size:32px;margin-bottom:8px;opacity:.6}
.dz-text{color:var(--text-sub);font-size:14px}
.dz-file{margin-top:8px;font-size:13px;color:var(--accent);font-weight:600;word-break:break-all}
.btn{
  padding:12px 20px;border-radius:12px;border:1px solid var(--input-border);
  background:var(--input-bg);color:var(--text);font-size:15px;font-weight:600;
  cursor:pointer;font-family:inherit;transition:all .2s
}
.btn:hover{transform:translateY(-1px)}
.btn.primary{
  background:linear-gradient(135deg,var(--accent),var(--accent-hover));
  color:#fff;border:none;width:100%;padding:14px;font-size:16px;
  box-shadow:0 4px 16px rgba(59,130,246,.35)
}
.btn.primary:hover{box-shadow:0 6px 20px rgba(59,130,246,.45)}
.btn.ghost{background:transparent}
.btn.small{padding:8px 14px;font-size:13px}
.result{margin-top:14px;font-size:14px;padding:12px 14px;border-radius:10px;display:none;word-break:break-all}
.result.ok{display:block;background:rgba(34,197,94,.12);color:#15803d}
.result.err{display:block;background:rgba(239,68,68,.12);color:var(--danger)}
[data-theme="dark"] .result.ok{color:#4ade80}
.card-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
.card-head h2{margin:0}
.notice-list{display:flex;flex-direction:column;gap:12px}
.notice-item{padding:16px;border-radius:14px;background:var(--input-bg);
  border:1px solid var(--input-border)}
.notice-head{display:flex;justify-content:space-between;align-items:baseline;gap:12px;margin-bottom:8px}
.notice-head strong{font-size:15px;word-break:break-all}
.notice-time{font-size:12px;color:var(--text-sub);white-space:nowrap}
.notice-content{font-size:14px;line-height:1.6;word-break:break-word}
.empty{text-align:center;color:var(--text-sub);padding:32px;font-size:14px}
.btn-text{background:none;border:none;color:var(--text-sub);cursor:pointer;
  font-size:12px;padding:4px 8px;font-family:inherit;margin-top:8px}
.btn-text.danger:hover{color:var(--danger)}
.theme-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.theme-opt{background:var(--input-bg);border:2px solid var(--input-border);border-radius:14px;
  padding:12px;cursor:pointer;font-family:inherit;color:var(--text);transition:all .2s;
  display:flex;flex-direction:column;align-items:center;gap:8px}
.theme-opt:hover{border-color:var(--accent)}
.theme-opt.active{border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
.theme-preview{width:100%;height:48px;border-radius:8px}
.theme-preview.light{background:linear-gradient(135deg,#eef4fb,#d0e3ff)}
.theme-preview.dark{background:linear-gradient(135deg,#0a0f1a,#1e3a8a)}
.theme-preview.auto{background:linear-gradient(135deg,#eef4fb 50%,#0a0f1a 50%)}
.theme-opt span{font-size:13px}
.modal-mask{position:fixed;inset:0;background:rgba(0,0,0,.4);backdrop-filter:blur(4px);
  display:none;align-items:center;justify-content:center;z-index:100;padding:20px}
.modal-mask.show{display:flex;animation:fadeIn .2s ease}
.modal{padding:24px;width:100%;max-width:480px}
.modal h2{margin:0 0 16px;font-size:18px}
.modal-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:16px}
.modal-actions .btn{width:auto}
</style>
</head>
<body>
<div class="blob blob-1"></div>
<div class="blob blob-2"></div>
<div class="blob blob-3"></div>

<div class="app">
  <header class="glass topbar">
    <div class="brand">
      <div class="logo">📚</div>
      <div>
        <h1>作业提交</h1>
        <p>局域网 · 单文件上传</p>
      </div>
    </div>
    <nav class="tabs">
      <button class="tab active" data-view="upload">上传</button>
      <button class="tab" data-view="notice">公告</button>
      <button class="tab" data-view="settings">设置</button>
    </nav>
  </header>

  <main>
    <section class="view active" id="view-upload">
      <div class="glass card">
        <h2>提交作业</h2>
        <p class="hint">支持文档、压缩包、图片，单个文件 ≤ 20 MB</p>
        <div class="form-row">
          <div class="field">
            <label>学号</label>
            <input type="text" id="sid" placeholder="例如 1001" maxlength="32">
          </div>
          <div class="field">
            <label>姓名</label>
            <input type="text" id="sname" placeholder="例如 张三" maxlength="32">
          </div>
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
        <div class="card-head">
          <h2>公告区</h2>
          <button class="btn ghost small" id="btn-notice-teacher" style="display:none">老师发布</button>
        </div>
        <div id="notice-list" class="notice-list">
          <div class="empty">暂无公告</div>
        </div>
      </div>
    </section>

    <section class="view" id="view-settings">
      <div class="glass card">
        <h2>外观</h2>
        <p class="hint">选择你喜欢的显示模式</p>
        <div class="theme-grid">
          <button class="theme-opt" data-theme-opt="light">
            <div class="theme-preview light"></div><span>浅色</span>
          </button>
          <button class="theme-opt" data-theme-opt="dark">
            <div class="theme-preview dark"></div><span>深色</span>
          </button>
          <button class="theme-opt" data-theme-opt="auto">
            <div class="theme-preview auto"></div><span>跟随系统</span>
          </button>
        </div>
      </div>

      <div class="glass card">
        <h2>老师模式</h2>
        <div id="teacher-off">
          <p class="hint">输入管理密码解锁发公告、修改密码等功能</p>
          <div class="field">
            <label>管理密码</label>
            <input type="password" id="teacher-pwd" placeholder="默认 admin888">
          </div>
          <button class="btn primary" id="btn-login">解锁</button>
        </div>
        <div id="teacher-on" style="display:none">
          <p class="hint">已解锁，可前往公告页发布公告</p>
          <div class="field">
            <label>修改密码</label>
            <input type="password" id="new-pwd" placeholder="新密码（至少 4 位）">
          </div>
          <button class="btn" id="btn-change-pwd">修改密码</button>
          <button class="btn ghost" id="btn-logout">退出老师模式</button>
        </div>
        <div class="result" id="settings-result"></div>
      </div>
    </section>
  </main>
</div>

<div class="modal-mask" id="notice-modal">
  <div class="glass modal">
    <h2>发布公告</h2>
    <div class="field">
      <label>标题</label>
      <input type="text" id="notice-title" placeholder="例如 本周作业截止时间" maxlength="60">
    </div>
    <div class="field">
      <label>内容</label>
      <textarea id="notice-content" placeholder="公告内容..." maxlength="1000" rows="5"></textarea>
    </div>
    <div class="modal-actions">
      <button class="btn ghost" id="modal-cancel">取消</button>
      <button class="btn primary" id="modal-confirm">发布</button>
    </div>
  </div>
</div>

<script>
const THEME_KEY='homework-theme';
const TEACHER_KEY='homework-teacher-pwd';

/* ---------- 主题 ---------- */
function resolveTheme(pref){
  if(pref==='light'||pref==='dark') return pref;
  return matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';
}
function applyTheme(pref){
  document.documentElement.dataset.theme=resolveTheme(pref);
}
function setThemePreference(pref){
  localStorage.setItem(THEME_KEY,pref);
  applyTheme(pref);
  document.querySelectorAll('.theme-opt').forEach(el=>{
    el.classList.toggle('active',el.dataset.themeOpt===pref);
  });
}
matchMedia('(prefers-color-scheme: dark)').addEventListener('change',()=>{
  if((localStorage.getItem(THEME_KEY)||'auto')==='auto') applyTheme('auto');
});

/* ---------- Tab 切换 ---------- */
function switchView(name){
  document.querySelectorAll('.view').forEach(v=>v.classList.toggle('active',v.id==='view-'+name));
  document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active',t.dataset.view===name));
  if(name==='notice') loadNotices();
}

/* ---------- 上传 ---------- */
const dropzone=document.getElementById('dropzone');
const fileInput=document.getElementById('file');
const dzFile=document.getElementById('dz-file');

dropzone.addEventListener('click',()=>fileInput.click());
dropzone.addEventListener('dragover',e=>{e.preventDefault();dropzone.classList.add('over')});
dropzone.addEventListener('dragleave',()=>dropzone.classList.remove('over'));
dropzone.addEventListener('drop',e=>{
  e.preventDefault();dropzone.classList.remove('over');
  if(e.dataTransfer.files.length){fileInput.files=e.dataTransfer.files;showFile()}
});
fileInput.addEventListener('change',showFile);
function showFile(){
  if(fileInput.files.length){
    const f=fileInput.files[0];
    dzFile.textContent=f.name+' ('+(f.size/1024).toFixed(1)+' KB)';
  }else dzFile.textContent='';
}

document.getElementById('btn-upload').addEventListener('click',async()=>{
  const sid=document.getElementById('sid').value.trim();
  const sname=document.getElementById('sname').value.trim();
  const result=document.getElementById('upload-result');
  result.className='result';result.textContent='';

  if(!sid||!sname){result.classList.add('err');result.textContent='请填写学号和姓名';return}
  if(!fileInput.files.length){result.classList.add('err');result.textContent='请选择文件';return}

  const fd=new FormData();
  fd.append('student_id',sid);
  fd.append('student_name',sname);
  fd.append('file',fileInput.files[0]);

  try{
    const resp=await fetch('/api/upload',{method:'POST',body:fd});
    const data=await resp.json();
    result.classList.add(data.ok?'ok':'err');
    result.textContent=data.message+(data.filename?' → '+data.filename:'');
    if(data.ok){fileInput.value='';dzFile.textContent=''}
  }catch(e){
    result.classList.add('err');result.textContent='网络错误：'+e.message;
  }
});

/* ---------- 公告 ---------- */
function escapeHtml(s){
  return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function loadNotices(){
  const list=document.getElementById('notice-list');
  try{
    const resp=await fetch('/api/notices');
    const data=await resp.json();
    if(!data.length){list.innerHTML='<div class="empty">暂无公告</div>';return}
    list.innerHTML=data.map(n=>`
      <div class="notice-item">
        <div class="notice-head">
          <strong>${escapeHtml(n.title)}</strong>
          <span class="notice-time">${escapeHtml(n.time)}</span>
        </div>
        <div class="notice-content">${escapeHtml(n.content).replace(/\n/g,'<br>')}</div>
        ${isTeacher()?`<button class="btn-text danger" onclick="deleteNotice('${n.id}')">删除</button>`:''}
      </div>
    `).join('');
  }catch(e){list.innerHTML='<div class="empty">加载失败</div>'}
}

async function deleteNotice(id){
  if(!confirm('确定删除这条公告？')) return;
  try{
    const resp=await fetch('/api/notices/'+id,{
      method:'DELETE',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:getTeacherPwd()})
    });
    const data=await resp.json();
    if(data.ok) loadNotices();
    else alert(data.message||'删除失败');
  }catch(e){alert('网络错误')}
}

/* ---------- 老师模式 ---------- */
function isTeacher(){return !!sessionStorage.getItem(TEACHER_KEY)}
function getTeacherPwd(){return sessionStorage.getItem(TEACHER_KEY)||''}
function setTeacherPwd(p){sessionStorage.setItem(TEACHER_KEY,p)}

function updateTeacherUI(){
  const on=isTeacher();
  document.getElementById('teacher-off').style.display=on?'none':'';
  document.getElementById('teacher-on').style.display=on?'':'none';
  document.getElementById('btn-notice-teacher').style.display=on?'':'none';
}

document.getElementById('btn-login').addEventListener('click',async()=>{
  const pwd=document.getElementById('teacher-pwd').value;
  const result=document.getElementById('settings-result');
  result.className='result';result.textContent='';
  try{
    const resp=await fetch('/api/auth',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:pwd})
    });
    const data=await resp.json();
    if(data.ok){
      setTeacherPwd(pwd);updateTeacherUI();
      result.classList.add('ok');result.textContent='已解锁老师模式';
      document.getElementById('teacher-pwd').value='';
      loadNotices();
    }else{
      result.classList.add('err');result.textContent=data.message||'密码错误';
    }
  }catch(e){result.classList.add('err');result.textContent='网络错误'}
});

document.getElementById('btn-logout').addEventListener('click',()=>{
  sessionStorage.removeItem(TEACHER_KEY);
  updateTeacherUI();loadNotices();
});

document.getElementById('btn-change-pwd').addEventListener('click',async()=>{
  const newPwd=document.getElementById('new-pwd').value;
  const result=document.getElementById('settings-result');
  result.className='result';result.textContent='';
  if(!newPwd||newPwd.length<4){
    result.classList.add('err');result.textContent='新密码至少 4 位';return;
  }
  try{
    const resp=await fetch('/api/password',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({old_password:getTeacherPwd(),new_password:newPwd})
    });
    const data=await resp.json();
    if(data.ok){
      setTeacherPwd(newPwd);
      result.classList.add('ok');result.textContent='密码已修改';
      document.getElementById('new-pwd').value='';
    }else{
      result.classList.add('err');result.textContent=data.message||'修改失败';
    }
  }catch(e){result.classList.add('err');result.textContent='网络错误'}
});

/* ---------- 发公告 ---------- */
document.getElementById('btn-notice-teacher').addEventListener('click',()=>{
  document.getElementById('notice-modal').classList.add('show');
});
document.getElementById('modal-cancel').addEventListener('click',()=>{
  document.getElementById('notice-modal').classList.remove('show');
});
document.getElementById('modal-confirm').addEventListener('click',async()=>{
  const title=document.getElementById('notice-title').value.trim();
  const content=document.getElementById('notice-content').value.trim();
  if(!title||!content){alert('标题和内容不能为空');return}
  try{
    const resp=await fetch('/api/notices',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:getTeacherPwd(),title,content})
    });
    const data=await resp.json();
    if(data.ok){
      document.getElementById('notice-modal').classList.remove('show');
      document.getElementById('notice-title').value='';
      document.getElementById('notice-content').value='';
      loadNotices();
    }else alert(data.message||'发布失败');
  }catch(e){alert('网络错误')}
});

/* ---------- 绑定 ---------- */
document.querySelectorAll('.tab').forEach(t=>{
  t.addEventListener('click',()=>switchView(t.dataset.view));
});
document.querySelectorAll('.theme-opt').forEach(el=>{
  el.addEventListener('click',()=>setThemePreference(el.dataset.themeOpt));
});

/* ---------- 初始化 ---------- */
(function init(){
  const pref=localStorage.getItem(THEME_KEY)||'auto';
  applyTheme(pref);
  document.querySelectorAll('.theme-opt').forEach(el=>{
    el.classList.toggle('active',el.dataset.themeOpt===pref);
  });
  updateTeacherUI();
  loadNotices();
})();
</script>
</body>
</html>
"""


# ---------- 启动 ----------
def get_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


if __name__ == "__main__":
    first_run = not os.path.exists(CONFIG_FILE)
    get_password_hash()
    ip = get_lan_ip()
    print("=" * 56)
    print("  作业提交系统 已启动")
    print(f"  本机访问   : http://127.0.0.1:8080")
    print(f"  局域网访问 : http://{ip}:8080")
    print(f"  上传目录   : {UPLOAD_DIR}")
    if first_run:
        print(f"  ⚠ 首次启动，默认管理密码：{DEFAULT_PASSWORD}")
        print(f"    请打开网页 → 设置 → 老师模式，及时修改")
    print("=" * 56)
    print("  按 Ctrl-C 停止服务")
    app.run(host="0.0.0.0", port=8080, debug=False)