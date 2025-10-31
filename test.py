#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pentest All in One
- Dashboard (rectangular buttons)
- GraphQL suite:
  • Monitor (High-Speed, COMBINED EXTRACTORS, JS+maps+TS, scans downloaded JS bundles)
  • Fuzzer (Root & Per-Op; RPS control; tells if suggestions are disabled)
  • Introspection (Normal + Custom deep walk; no fuzz/wordlist; output like user's script)
  • Wordlist extractor (scan .txt files in a folder, extract words, de-dup, save to .txt)
  • Alias/Batch Gen
  • Query Fixer (Quick Fix fixed, Batch Multi-threaded & Detailed Logging)
  • Schema Search (Supports Query/Mutation folders and multi-field search & Stop button)
  • Operation Monitor (Remembers host/path)
Authorized testing only.
"""

import sys, os, re, json, time, threading, traceback, glob, concurrent.futures as cf
from typing import Dict, List, Tuple, Optional, Set, Any
from datetime import datetime
from urllib.parse import urljoin
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QWidget, QStackedWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QSpinBox, QComboBox, QPlainTextEdit, QMessageBox,
    QGroupBox, QFormLayout, QProgressBar, QDialog, QTextEdit, QGridLayout, QTabWidget,
    QSplitter, QCheckBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QSettings, QThread
from PyQt6.QtGui import QGuiApplication

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- Global Constants for Introspection Caching ---
CACHE_FILENAME = ".type_cache.json"

# ======================== Shared logging / signals ========================

class LogSignal(QObject):
    text = pyqtSignal(str)
    progress = pyqtSignal(int, int, float)   # done, total, rps
    output_ready = pyqtSignal(str) # For fast fixer output

class BaseTab(QWidget):
    _LAST_DIR = "" # Class variable to store the last opened directory for QFileDialog

    def __init__(self):
        super().__init__()
        self.log_signal = LogSignal()
        self.log_signal.text.connect(self._append_log)
        self.log_signal.progress.connect(self._update_progress)
        self.settings = QSettings("PentestAIO", self.__class__.__name__)
        # Load last directory from settings
        BaseTab._LAST_DIR = self.settings.value("LastDirectory", os.getcwd())
        
        # Thread management for cancellable tasks
        self._stop_event = threading.Event()
        self._worker_thread = None

    def _load_setting(self, key, default=""):
        return self.settings.value(key, default)
    
    def _save_setting(self, key, value):
        self.settings.setValue(key, value)
    
    def _create_persistent_input(self, widget_class, setting_key, default_value="", placeholder=""):
        widget = widget_class()
        widget._setting_key = setting_key
        if issubclass(widget_class, QLineEdit):
            widget.setText(self._load_setting(setting_key, default_value))
            widget.setPlaceholderText(placeholder)
            widget.textChanged.connect(lambda t: self._save_setting(setting_key, t))
        elif issubclass(widget_class, QPlainTextEdit):
            widget.setPlainText(self._load_setting(setting_key, default_value))
            widget.setPlaceholderText(placeholder)
            widget.textChanged.connect(lambda t: self._save_setting(setting_key, t))
        elif issubclass(widget_class, QSpinBox):
            widget.setValue(int(self._load_setting(setting_key, str(default_value))))
            widget.valueChanged.connect(lambda v: self._save_setting(setting_key, str(v)))
        return widget

    def _clear_inputs(self, widgets):
        for w in widgets:
            if isinstance(w, QLineEdit): w.clear()
            elif isinstance(w, QPlainTextEdit): w.clear()
            elif isinstance(w, QSpinBox): w.setValue(0)
            elif isinstance(w, QComboBox): w.setCurrentIndex(0)
            
            # Clear saved settings
            if hasattr(w, '_setting_key'):
                self.settings.remove(w._setting_key)
        self.log("Inputs cleared.")


    def _pick_dir(self, dialog_title: str):
        d = QFileDialog.getExistingDirectory(self, dialog_title, BaseTab._LAST_DIR)
        if d:
            BaseTab._LAST_DIR = d
            self.settings.setValue("LastDirectory", d)
            return d
        return ""
    
    def _pick_file(self, dialog_title: str, filter_str: str):
        f, _ = QFileDialog.getOpenFileName(self, dialog_title, BaseTab._LAST_DIR, filter_str)
        if f:
            BaseTab._LAST_DIR = os.path.dirname(f)
            self.settings.setValue("LastDirectory", BaseTab._LAST_DIR)
            return f
        return ""
    
    def _save_file(self, dialog_title: str, default_filename: str, filter_str: str):
        f, _ = QFileDialog.getSaveFileName(self, dialog_title, os.path.join(BaseTab._LAST_DIR, default_filename), filter_str)
        if f:
            BaseTab._LAST_DIR = os.path.dirname(f)
            self.settings.setValue("LastDirectory", BaseTab._LAST_DIR)
            return f
        return ""

    def _append_log(self, msg: str):
        if hasattr(self, "log_box"):
            self.log_box.appendPlainText(msg)
        try: print(msg)
        except: pass
    def _update_progress(self, done: int, total: int, rps: float):
        if hasattr(self, "pbar"):
            self.pbar.setMaximum(max(1,total))
            self.pbar.setValue(done)
        if hasattr(self, "rps_lbl"):
            self.rps_lbl.setText(f"RPS: {rps:.1f}")
    def log(self, msg: str): self.log_signal.text.emit(msg)
    def prog(self, d: int, t: int, r: float): self.log_signal.progress.emit(d,t,r)
    def _help_popup(self, title: str, text: str):
        dlg = QDialog(self); dlg.setWindowTitle(title); dlg.resize(600, 420)
        te = QTextEdit(dlg); te.setReadOnly(True); te.setPlainText(text)
        vl = QVBoxLayout(dlg); vl.addWidget(te)
        ok = QPushButton("Close"); ok.clicked.connect(dlg.accept); vl.addWidget(ok, alignment=Qt.AlignmentFlag.AlignRight)
        dlg.exec()
    def _copy_to_clipboard(self, text_widget: QPlainTextEdit):
        try:
            QGuiApplication.clipboard().setText(text_widget.toPlainText())
            self.log("Copied to clipboard.")
        except Exception as e:
            self.log(f"Error copying to clipboard: {e}")

# ======================== HTTP helpers (Unchanged) ========================

def _session():
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.1, status_forcelist=[500,502,503,504], raise_on_status=False)
    adapter = HTTPAdapter(max_retries=retry, pool_connections=256, pool_maxsize=256, pool_block=False)
    s.mount('http://', adapter); s.mount('https://', adapter); s.trust_env = False
    return s

def _download_bytes(url: str, headers: Dict[str,str], timeout=(5,15)):
    try:
        r = _session().get(url, headers=headers, timeout=timeout, allow_redirects=True)
        r.raise_for_status(); return r.content
    except Exception: return None

def _download_text(url: str, headers: Dict[str,str], timeout=(5,15)):
    try:
        r = _session().get(url, headers=headers, timeout=timeout, allow_redirects=True)
        r.raise_for_status(); return r.text
    except Exception: return None

def build_headers(jwt_text: str, cookie_text: str, extra_headers_text: str) -> Dict[str, str]:
    headers = {"Content-Type": "application/json", "User-Agent": "Pentest-AIO/GraphQL"}
    if jwt_text.strip(): headers["Authorization"] = f"Bearer {jwt_text.strip()}"
    if cookie_text.strip(): headers["Cookie"] = cookie_text.strip()
    for line in extra_headers_text.splitlines():
        if line.strip() and ":" in line:
            k, v = line.split(":", 1); headers[k.strip()] = v.strip()
    return headers

def safe_post(url: str, headers: Dict[str, str], payload: Dict, timeout: int = 20) -> requests.Response:
    return requests.post(url, headers=headers, json=payload, timeout=timeout)

# ======================== Small utils (Unchanged) ========================

def _sanitize(path: str) -> str:
    path = re.sub(r'^\.\.?[/\\]webpack:[/\\_]+', '', path)
    path = re.sub(r'^\.\.?[/\\]', '', path)
    path = re.sub(r'[<>:"|?*]', '_', path)
    return path.replace('/', '_').replace('\\', '_')

# ======================== Extractor Functions (Unchanged) ========================

GQL_BLOCK_PATTERN = re.compile(r'gql\s*`([\s\S]+?)`')
OPERATION_PATTERN  = re.compile(r'^\s*(mutation|query|subscription)\s+([_A-Za-z]\w*)', re.DOTALL|re.MULTILINE)
ARG_PATTERN        = re.compile(r'\$([_A-Za-z]\w*)\s*:\s*([\[\]\w!]+)')
TYPE_ARGS_PATTERN_V2 = re.compile(r"export\s+type\s+(Mutation|Query)(\w+)Args\s*=\s*\{(.*?)\};", re.DOTALL|re.MULTILINE)
ROOT_TYPE_BLOCK = re.compile(r"export\s+type\s+(Query|Mutation)\s*=\s*\{([\s\S]*?)\n\}", re.MULTILINE)

def clean_description(desc):
    if not desc: return "No description available.", []
    lines = desc.strip().split('\n'); cleaned=[]; tags=[]
    for line in lines:
        m = re.search(r'@(\w+)(?:\s+(.+?))?$', line)
        if m: tags.append((m.group(1), m.group(2) or '')); continue
        cleaned_line = re.sub(r'^\s*\*\s?', '', line).strip()
        if cleaned_line and not cleaned_line.startswith('@'): cleaned.append(cleaned_line)
    full_desc = ' '.join(cleaned)
    return full_desc or "No description available.", tags

def extract_from_gql_blocks(content):
    ops=[]
    for block in GQL_BLOCK_PATTERN.findall(content):
        m = OPERATION_PATTERN.search(block.strip())
        if not m: continue
        op_type = m.group(1).capitalize(); op_name = m.group(2)
        args=[]
        am = re.search(r'\(([\s\S]*?)\)', block)
        if am:
            for nm, typ in ARG_PATTERN.findall(am.group(1)):
                args.append({"name": nm, "type": re.sub(r'[!\[\]]','',typ), "optional": not typ.endswith('!')})
        rfields=[]
        sm = re.search(r'{([\s\S]*)}', block)
        if sm:
            body = sm.group(1)
            for fld in re.findall(r'\b([a-zA-Z_]\w*)\s*(?:\{|$|\n)', body):
                if fld not in ['query','mutation','subscription','fragment'] and not fld.startswith('...'):
                    rfields.append({'name': fld, 'type': 'Unknown', 'optional': False, 'nested': [], 'depth': 0})
        ops.append((op_type, {
            "name": op_name, "description": "Extracted from gql template literal.",
            "tags": [], "return_type": "See return fields", "return_fields": rfields,
            "arguments": args, "fragments": re.findall(r'\.\.\.\s*(\w+)', block)
        }))
    return ops

def extract_from_inline_queries(content):
    ops=[]
    pats = [
        r'`\s*(query|mutation|subscription)\s+([_A-Za-z]\w*)\s*(\([^)]*\))?\s*\{',
        r'"\s*(query|mutation|subscription)\s+([_A-Za-z]\w*)\s*(\([^)]*\))?\s*\{',
        r"'\s*(query|mutation|subscription)\s+([_A-Za-z]\w*)\s*(\([^)]*\))?\s*\{"
    ]
    for pat in pats:
        for m in re.finditer(pat, content):
            kind = m.group(1).capitalize(); name = m.group(2); args_str = m.group(3) or ""
            args=[]
            for nm, typ in ARG_PATTERN.findall(args_str):
                args.append({"name": nm, "type": re.sub(r'[!\[\]]','',typ), "optional": not typ.endswith('!')})
            ops.append((kind, {
                "name": name, "description": f"Extracted from inline {kind.lower()} string.",
                "tags": [], "return_type":"See return fields", "return_fields":[],
                "arguments": args, "fragments":[]
            }))
    return ops

def extract_from_graphql_schema(content):
    ops=[]
    tpat = re.compile(r'type\s+(Query|Mutation|Subscription)\s*\{([\s\S]*?)\n\}', re.MULTILINE)
    for tm in tpat.finditer(content):
        kind = tm.group(1); body = tm.group(2)
        op_pat = re.compile(r'(?:"""([\s\S]*?)"""\s*)?(\w+)\s*(?:\(([\s\S]*?)\))?\s*:\s*([\w\[\]!]+)', re.MULTILINE)
        for om in op_pat.finditer(body):
            desc_raw, name, args_str, rtype = om.groups()
            desc, tags = clean_description(desc_raw)
            args=[]
            if args_str:
                for nm, typ in re.findall(r'(\w+)\s*:\s*([\w\[\]!]+)', args_str):
                    args.append({"name": nm, "type": re.sub(r'[!\[\]]','',typ), "optional": not typ.endswith('!')})
            ops.append((kind, {
                "name": name, "description": desc, "tags": tags,
                "return_type": rtype, "return_fields": [], "arguments": args, "fragments":[]
            }))
    return ops

def extract_from_type_definitions_v2(content):
    ops=[]
    for root_m in ROOT_TYPE_BLOCK.finditer(content):
        root = root_m.group(1); inner = root_m.group(2)
        for mm in re.finditer(r"(?:/\*\*[\s\S]*?\*/\s*)?(\w+)\s*:\s*([^\n]+)", inner):
            nm = mm.group(1)
            if nm=="__typename": continue
            ops.append((root, {"name": nm, "description": "From TypeScript root type",
                               "tags": [], "return_type": mm.group(2).strip(),
                               "return_fields": [], "arguments": [], "fragments":[]}))
    for m in TYPE_ARGS_PATTERN_V2.finditer(content):
        root = m.group(1); suf = m.group(2)
        if not suf: continue
        nm = suf[0].lower()+suf[1:]
        args_content = m.group(3)
        args=[]
        for line in [x.strip() for x in re.split(r'[;,]', args_content) if x.strip()]:
            mt = re.match(r'(\w+)(\??):\s*(.+)', line)
            if not mt: continue
            name, opt, t = mt.group(1), mt.group(2)=='?', re.sub(r"Scalars\['(\w+)'\]\['input'\]", r"\1", mt.group(3))
            args.append({"name":name,"type":t,"optional":opt})
        ops.append((root, {"name": nm, "description": "Extracted from TS Args type",
                           "tags": [], "return_type": "Unknown", "return_fields": [],
                           "arguments": args, "fragments":[]}))
    return ops

def extract_combined(content: str) -> Dict[Tuple[str,str], Dict[str,Any]]:
    out={}
    if re.search(r'\btype\s+(Query|Mutation|Subscription)\b', content):
        for k,op in extract_from_graphql_schema(content): out[(k,op['name'])]=op
    for k,op in extract_from_gql_blocks(content): out[(k,op['name'])]=op
    for k,op in extract_from_inline_queries(content): out[(k,op['name'])]=op
    for k,op in extract_from_type_definitions_v2(content): out[(k,op['name'])]=op
    return out

# ======================== Rate limiter (Fuzzer) (Unchanged) ========================

class RateLimiter:
    def __init__(self, target_rps: float):
        self.lock = threading.Lock()
        self.target_rps = max(0.1, float(target_rps))
        self.min_gap = 1.0 / self.target_rps
        self.next_time = time.monotonic()
        self.start = time.monotonic()
        self.sent = 0
    def acquire(self):
        with self.lock:
            now = time.monotonic()
            if now < self.next_time:
                time.sleep(self.next_time - now); now = time.monotonic()
            self.next_time = now + self.min_gap
            self.sent += 1
            elapsed = now - self.start
            if elapsed >= 2.0:
                obs_rps = self.sent / max(0.001, elapsed)
                if obs_rps > self.target_rps * 1.1: self.min_gap *= 1.1
                elif obs_rps < self.target_rps * 0.9: self.min_gap /= 1.1
                self.start = now; self.sent = 0
                self.min_gap = max(0.001, min(self.min_gap, 5.0))

# ======================== Monitor Tab (Minor update to browse) ========================

class MonitorTab(BaseTab):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)

        # Set up persistent fields
        self.config_path = self._create_persistent_input(QLineEdit, "config_path", placeholder="config.json (hosts[], cookies)")
        self.js_txt = self._create_persistent_input(QLineEdit, "js_txt", placeholder="JS.txt (list of bundle URLs)")
        self.out_dir = self._create_persistent_input(QLineEdit, "out_dir", placeholder="Output base dir (e.g., graphql_monitor)")
        self.js_threads = self._create_persistent_input(QSpinBox, "js_threads", default_value=50)
        self.ts_threads = self._create_persistent_input(QSpinBox, "ts_threads", default_value=50)
        self.js_threads.setRange(1, 256)
        self.ts_threads.setRange(1, 256)

        top = QHBoxLayout()
        help_btn = QPushButton("Help"); help_btn.clicked.connect(self._show_help)
        top.addStretch(1); top.addWidget(help_btn)
        lay.addLayout(top)

        cfg = QGroupBox("Monitor (High-Speed)")
        f = QFormLayout()
        
        b1 = QPushButton("Browse…"); b1.clicked.connect(lambda: self._pick_config(self.config_path))
        hb1 = QHBoxLayout(); hb1.addWidget(self.config_path); hb1.addWidget(b1)

        b2 = QPushButton("Browse…"); b2.clicked.connect(lambda: self._pick_js(self.js_txt))
        hb2 = QHBoxLayout(); hb2.addWidget(self.js_txt); hb2.addWidget(b2)

        b3 = QPushButton("Choose…"); b3.clicked.connect(lambda: self._pick_out(self.out_dir))
        hb3 = QHBoxLayout(); hb3.addWidget(self.out_dir); hb3.addWidget(b3)

        ex_btn = QPushButton("Show config.json example"); ex_btn.clicked.connect(self._show_config_example)
        clear_btn = QPushButton("Clear All Inputs"); 
        clear_btn.clicked.connect(lambda: self._clear_inputs([self.config_path, self.js_txt, self.out_dir, self.js_threads, self.ts_threads]))


        f.addRow("config.json:", hb1)
        f.addRow("JS.txt:", hb2)
        f.addRow("Output dir:", hb3)
        f.addRow("JS/Map threads:", self.js_threads)
        f.addRow("TS threads:", self.ts_threads)
        f.addWidget(ex_btn)
        f.addWidget(clear_btn)
        cfg.setLayout(f)
        lay.addWidget(cfg)

        run = QPushButton("Run (download → maps → TS → extract → history)")
        run.clicked.connect(self.run_monitor)
        lay.addWidget(run)

        self.pbar = QProgressBar(); self.pbar.setMaximum(1); self.pbar.setValue(0)
        self.rps_lbl = QLabel("RPS: 0.0")
        hb = QHBoxLayout(); hb.addWidget(self.pbar, 1); hb.addWidget(self.rps_lbl)
        lay.addLayout(hb)

        self.log_box = QPlainTextEdit(); self.log_box.setReadOnly(True)
        lay.addWidget(self.log_box)

    def _show_help(self):
        self._help_popup("Monitor Help",
"""Monitor tab
• Downloads JS bundles from a provided JS.txt (one URL per line)
• Resolves sourcemaps and fetches TypeScript either from embedded sourcesContent or by HTTP
• Extracts GraphQL operations using combined extractors (inline strings, gql blocks, TS root types, Args typedefs, .graphql/.gql)
• Scans downloaded JS bundles too
• Writes GraphQL_API/ (all ops) and GraphQL_NEW/ (only new this run)
• Writes a FORMATTED MUTATION JSON block into each file (as requested)
• Shows a final summary with exact counts matching files on disk""")

    def _pick_config(self, le: QLineEdit):
        f = self._pick_file("config.json", "JSON (*.json);;All Files (*)")
        if f: le.setText(f)
    def _pick_js(self, le: QLineEdit):
        f = self._pick_file("JS.txt", "Text (*.txt);;All Files (*)")
        if f: le.setText(f)
    def _pick_out(self, le: QLineEdit):
        d = self._pick_dir("Choose output directory")
        if d: le.setText(d)
    def _show_config_example(self):
        dlg = QDialog(self); dlg.setWindowTitle("config.json example"); dlg.resize(600, 380)
        te = QTextEdit(dlg); te.setReadOnly(True)
        te.setPlainText(json.dumps({"hosts": ["cdn.example.com","app.example.com"],"cookies":"session=abc; csrftoken=xyz"}, indent=2))
        vl = QVBoxLayout(dlg); vl.addWidget(te)
        ok = QPushButton("Close"); ok.clicked.connect(dlg.accept); vl.addWidget(ok, alignment=Qt.AlignmentFlag.AlignRight)
        dlg.exec()
    
    def _extract_ops_dir(self, base_dir: str, extra_js_folder: Optional[str]=None) -> Dict[Tuple[str,str], Dict[str,Any]]:
        files = (
            glob.glob(os.path.join(base_dir, '**/*.ts'), recursive=True) +
            glob.glob(os.path.join(base_dir, '**/*.tsx'), recursive=True) +
            glob.glob(os.path.join(base_dir, '**/*.js'), recursive=True) +
            glob.glob(os.path.join(base_dir, '**/*.jsx'), recursive=True) +
            glob.glob(os.path.join(base_dir, '**/*.graphql'), recursive=True) +
            glob.glob(os.path.join(base_dir, '**/*.gql'), recursive=True)
        )
        if extra_js_folder and os.path.exists(extra_js_folder):
            files += (
                glob.glob(os.path.join(extra_js_folder, '**/*.js'), recursive=True) +
                glob.glob(os.path.join(extra_js_folder, '**/*.jsx'), recursive=True)
            )
        out={}
        for p in files:
            try:
                content = open(p,'r',encoding='utf-8',errors='ignore').read()
                combined = extract_combined(content)
                for k,v in combined.items(): out[k]=v
            except Exception as e:
                self.log(f"[extract] {p}: {e}")
        return out

    def _get_placeholder_value(self, arg_type: str, nested_fields: Optional[List[Dict]] = None) -> Any:
        """Generate placeholder values for different argument types."""
        base_type = arg_type.replace('!', '').strip()
        
        if base_type.startswith('['):
            return []
        elif 'String' in base_type or 'ID' in base_type:
            return "test_value"
        elif 'Int' in base_type:
            return 1
        elif 'Float' in base_type:
            return 1.0
        elif 'Boolean' in base_type:
            return True
        else:
            # For complex types, build object from nested fields
            if nested_fields:
                obj = {}
                for field in nested_fields:
                    obj[field['name']] = self._get_placeholder_value(field['type'])
                return obj
            return {}

    def _format_mutation_as_json(self, mutation_name: str, root_type: str, arguments: List[Dict], is_scalar: bool = False) -> str:
        """Format the mutation as a JSON payload with variables."""
        
        # Ensure root_type is lowercase for the query string
        root_op = root_type.lower()
        if root_op not in ['query', 'mutation', 'subscription']:
            root_op = 'mutation' # Default
            
        if arguments:
            # Build the GraphQL mutation string with proper formatting
            arg_definitions = ", ".join([f"${arg['name']}: {arg['type']}" for arg in arguments])
            arg_usage = ", ".join([f"{arg['name']}: ${arg['name']}" for arg in arguments])
            
            if is_scalar:
                mutation_str = f"{root_op} {mutation_name}({arg_definitions}) {{\n    {mutation_name}({arg_usage})\n}}"
            else:
                # Try to find a real name, default to operation name
                op_name = mutation_name[0].upper() + mutation_name[1:]
                mutation_str = f"{root_op} {op_name}({arg_definitions}) {{\n    {mutation_name}({arg_usage}) {{\n        __typename\n    }}\n}}"
            
            # Build variables object with nested fields
            variables = {}
            for arg in arguments:
                if 'nested_fields' in arg and arg['nested_fields']:
                    # Build nested object
                    nested_obj = {}
                    for field in arg['nested_fields']:
                        field_value = self._get_placeholder_value(field['type'])
                        nested_obj[field['name']] = field_value
                    variables[arg['name']] = nested_obj
                else:
                    variables[arg['name']] = self._get_placeholder_value(arg['type'])
        else:
            # No arguments
            op_name = mutation_name[0].upper() + mutation_name[1:]
            if is_scalar:
                mutation_str = f"{root_op} {op_name} {{\n    {mutation_name}\n}}"
            else:
                mutation_str = f"{root_op} {op_name} {{\n    {mutation_name} {{\n        __typename\n    }}\n}}"
            variables = {}
        
        payload = {
            "query": mutation_str,
            "variables": variables
        }
        
        return json.dumps(payload, separators=(',', ':'))

    def _write_op_to_file(self, op: Dict[str,Any], root: str, base_dir: str):
        folder = os.path.join(base_dir, "GraphQL_API", root); os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, f"{op['name']}.txt"), 'w', encoding='utf-8') as f:
            f.write("="*80+"\n")
            f.write(f"{root.upper()}: {op['name']}\n")
            f.write("="*80+"\n")
            f.write(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"Description: {op.get('description','')}\n\n")
            f.write("ARGUMENTS:\n----------------------------------------\n")
            args = op.get("arguments") or []
            if not args: f.write("No arguments required.\n")
            else:
                for a in sorted(args, key=lambda x: x.get("optional", False)):
                    status = "optional" if a.get("optional") else "required"
                    f.write(f"• {a['name']} ({a['type']}) - {status}\n")
            f.write("\nRETURN TYPE:\n----------------------------------------\n")
            f.write(op.get("return_type","Unknown")+"\n\n")

            try:
                # Re-map arguments to the format expected by the fixer script
                mapped_args = []
                for a in args:
                    mapped_args.append({
                        'name': a['name'],
                        'type': a['type'] if not a.get('optional') else a['type'].replace('!', ''),
                        'required': not a.get('optional', False),
                        'nested_fields': a.get('nested_fields', []) # Pass this along if it exists
                    })
                
                # is_scalar is not easily known here, assume False
                formatted_json = self._format_mutation_as_json(
                    op['name'], 
                    root, 
                    mapped_args,
                    is_scalar=False # We can't easily tell from monitor output if it's scalar
                )
                f.write("FORMATTED MUTATION:\n----------------------------------------\n")
                f.write(formatted_json + "\n\n")
            except Exception as e:
                # Don't fail the whole write op, just skip this part
                f.write("FORMATTED MUTATION:\n----------------------------------------\n")
                f.write(f"Error generating formatted JSON: {e}\n\n")


    def run_monitor(self):
        cfg = self.config_path.text().strip()
        jsfile = self.js_txt.text().strip()
        base = self.out_dir.text().strip() or os.path.join(os.getcwd(), "graphql_monitor")
        if not os.path.exists(cfg) or not os.path.exists(jsfile):
            QMessageBox.warning(self, "Missing", "Provide config.json and JS.txt"); return

        def work():
            # ... Monitor implementation ...
            try:
                self.log("=" * 60); self.log("GraphQL Monitor v3.1 - JS URL Edition"); self.log("=" * 60)
                config = json.load(open(cfg,'r',encoding='utf-8'))
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0",
                    "Cookie": config.get('cookies',"")
                }
                hosts = config.get('hosts', [])
                if not hosts:
                    self.log("Error: No hosts defined in config.json"); return

                OUTPUT_DIR = base
                TS_DIR = os.path.join(OUTPUT_DIR,"ts_files")
                MAP_CACHE_DIR = os.path.join(OUTPUT_DIR,".maps_cache")
                JS_FOLDER = os.path.join(OUTPUT_DIR,"JS")
                os.makedirs(OUTPUT_DIR, exist_ok=True); os.makedirs(TS_DIR, exist_ok=True)
                os.makedirs(MAP_CACHE_DIR, exist_ok=True); os.makedirs(JS_FOLDER, exist_ok=True)

                # Step 0: Download JS files
                js_urls = [l.strip() for l in open(jsfile,'r',encoding='utf-8') if l.strip() and not l.strip().startswith('#')]
                js_total_count = len(js_urls); js_downloaded_count = 0
                t0 = time.time(); done = 0
                def dl_js(url: str):
                    nonlocal js_downloaded_count, done
                    content = _download_bytes(url, headers)
                    if content:
                        name = url.split('/')[-1].split('?')[0] or "bundle.js"
                        if not name.endswith('.js'): name += '.js'
                        open(os.path.join(JS_FOLDER, name),'wb').write(content)
                        self.log(f"  ✓ JS: {name}"); js_downloaded_count += 1
                    else:
                        self.log(f"  ✗ JS: {url}")
                    done += 1; self.prog(done, js_total_count, done/max(0.001, time.time()-t0))
                with cf.ThreadPoolExecutor(max_workers=self.js_threads.value()) as ex:
                    list(ex.map(dl_js, js_urls))
                self.log(f"\nJS Download Summary: {js_downloaded_count}/{js_total_count} downloaded")

                # Step 1: Download TS from source maps
                local_js_files = [f for f in glob.glob(os.path.join(JS_FOLDER, '*.js*')) if not f.endswith('.map')]
                ts_extracted_count = 0; ts_downloaded_count = 0
                def process_js_file(js_path: str):
                    nonlocal ts_extracted_count, ts_downloaded_count
                    try:
                        txt = open(js_path,'rb').read().decode('utf-8', errors='ignore')
                        m = re.search(r'//# sourceMappingURL=(.+\.map)', txt)
                        if not m: return
                        map_name = m.group(1).strip()
                        cache_path = os.path.join(MAP_CACHE_DIR, _sanitize(map_name))
                        if os.path.exists(cache_path):
                            data = json.load(open(cache_path,'r',encoding='utf-8'))
                        else:
                            data = None
                            for h in hosts:
                                url = urljoin(f"https://{h}/", map_name)
                                resp = _download_text(url, headers)
                                if resp:
                                    try:
                                        data = json.loads(resp)
                                        open(cache_path,'w',encoding='utf-8').write(json.dumps(data)); break
                                    except: pass
                        if not data: return
                        sources = data.get("sources") or []
                        sc = data.get("sourcesContent") or []
                        if sc and len(sc)==len(sources):
                            for src, src_content in zip(sources, sc):
                                if src.endswith(('.ts','.tsx')) and src_content:
                                    ts_extracted_count +=1
                                    dst = os.path.join(TS_DIR, _sanitize(src))
                                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                                    open(dst,'w',encoding='utf-8').write(src_content)
                        else:
                            ts_urls = []
                            for src in sources:
                                if src.endswith(('.ts','.tsx')):
                                    for h in hosts: ts_urls.append(urljoin(f"https://{h}/", src))
                            def dl_ts(url: str):
                                nonlocal ts_downloaded_count
                                txt2 = _download_text(url, headers)
                                if txt2:
                                    dst = os.path.join(TS_DIR, _sanitize(url))
                                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                                    open(dst,'w',encoding='utf-8').write(txt2); ts_downloaded_count += 1
                            if ts_urls:
                                with cf.ThreadPoolExecutor(max_workers=self.ts_threads.value()) as ex2:
                                    list(ex2.map(dl_ts, list(set(ts_urls))))
                    except Exception as e:
                        self.log(f"[map] {os.path.basename(js_path)}: {e}")
                
                t1 = time.time(); done = 0; total = len(local_js_files)
                with cf.ThreadPoolExecutor(max_workers=self.js_threads.value()) as ex:
                    for _ in ex.map(process_js_file, local_js_files):
                        done += 1; self.prog(done, total, done/max(0.001, time.time()-t1))
                self.log(f"\nTS Download Summary: Extracted {ts_extracted_count}, Downloaded {ts_downloaded_count}")

                # Step 2: Extract GQL ops
                all_ops = self._extract_ops_dir(TS_DIR, extra_js_folder=JS_FOLDER)
                self.log(f"\nExtracted {len(all_ops)} total operations")

                # Step 3+4: history & NEW with exact counts
                hist_file = os.path.join(base, "operations_history.json")
                old = json.load(open(hist_file,'r')) if os.path.exists(hist_file) else {}  # keys: "Root:Name"
                cur: Dict[str, Dict[str, Any]] = {}
                for (root,name), data in all_ops.items():
                    root_cap = root if root in ("Query","Mutation","Subscription") else root.capitalize()
                    cur[f"{root_cap}:{name}"] = {
                        "name": name, "type": root_cap,
                        "description": data.get('description',''),
                        "arguments": data.get('arguments', []),
                        "return_type": data.get('return_type','')
                    }

                # Write full GraphQL_API
                for (root,name), data in all_ops.items():
                    self._write_op_to_file(data, root if root in ("Query","Mutation","Subscription") else root.capitalize(), base)

                # Compute NEW
                new_map = {k:v for k,v in cur.items() if k not in old}
                json.dump(cur, open(hist_file,'w'), indent=2)

                GRAPHQL_NEW_DIR = os.path.join(base,"GraphQL_NEW")
                if os.path.exists(GRAPHQL_NEW_DIR): import shutil; shutil.rmtree(GRAPHQL_NEW_DIR)
                os.makedirs(GRAPHQL_NEW_DIR, exist_ok=True)

                # Write NEW files and count by category
                new_mut, new_qry, new_sub = {}, {}, {}
                def find_op(root, name): return all_ops.get((root, name)) or all_ops.get((root.capitalize(), name))
                for key, meta in new_map.items():
                    root, name = key.split(':',1)
                    op = find_op(root, name)
                    if not op: continue
                    self._write_op_to_file(op, root, GRAPHQL_NEW_DIR.replace("GraphQL_API", ""))
                    if root=="Mutation": new_mut[name]=1
                    elif root=="Query": new_qry[name]=1
                    elif root=="Subscription": new_sub[name]=1

                # FINAL block
                total_new = len(new_map)
                self.log(f"\n🎯 FOUND {total_new} NEW OPERATIONS THIS RUN!"); self.log("="*60)
                self.log(f"  🔴 NEW Mutations: {len(new_mut)}"); self.log(f"  🔵 NEW Queries: {len(new_qry)}")
                self.log(f"  🟢 NEW Subscriptions: {len(new_sub)}")
                self.prog(1,1,0.0)
            except Exception as e:
                self.log(f"[Monitor] ERROR: {e}\n{traceback.format_exc()}")

        threading.Thread(target=work, daemon=True).start()

# ======================== Fuzzer Tab (Minor update to browse and persistence) ========================

def check_suggestion_support(endpoint: str, headers: Dict[str,str]) -> bool:
    probe = {"query": "query Test{ __doesNotExist__ }"}
    try:
        r = safe_post(endpoint, headers, probe, timeout=15)
        data = r.json() if r is not None else {}
        errs = data.get("errors", [])
        for e in errs:
            if "Did you mean" in e.get("message",""):
                return True
    except Exception:
        pass
    return False

def fuzz_root_fields(endpoint: str, headers: Dict[str, str], words: List[str],
                     operation_type: str, nested_field: str, threads: int,
                     rate: RateLimiter, log_fn, prog_fn, suggestions_enabled: bool):
    lock = threading.Lock()
    hits: Set[str] = set(); suggs: Set[str] = set()
    total = len(words); done = 0; t0 = time.time()
    def one(field: str):
        nonlocal done
        rate.acquire()
        query = f"""\n{operation_type} Test {{\n  {field} {{\n    {nested_field}\n  }}\n}}\n"""
        payload = {"query": query}
        try:
            r = safe_post(endpoint, headers, payload, timeout=20)
            data = r.json() if r is not None else {}
            errors = data.get("errors", [])
            for error in errors:
                msg = error.get("message", "")
                patterns = [
                    f'Cannot query field "{nested_field}" on type',
                    r'Field "' + re.escape(field) + r'" must not have a selection since type "[^"]*!?" has no subfields',
                    r'Field "' + re.escape(field) + r'" argument "[^"]*" of type "[^"]*!?" is required, but it was not provided',
                    r'Cannot query field "' + re.escape(nested_field) + r'" on type "(?!Query|Mutation)[^"]*"'
                ]
                if any(re.search(p, msg) for p in patterns):
                    with lock:
                        if field not in hits:
                            hits.add(field); log_fn(f"[HIT] {field}")
                elif suggestions_enabled and "Did you mean" in msg:
                    for s in re.findall(r'\"([A-Za-z0-9_]+)\"', msg.split("Did you mean",1)[1]):
                        with lock:
                            if s not in suggs:
                                suggs.add(s); log_fn(f"[SUGG] {field} -> {s}")
        except Exception as e:
            log_fn(f"[ERR] {field}: {e}")
        finally:
            with lock:
                done += 1; prog_fn(done, total, done/max(0.001, time.time()-t0))
    with cf.ThreadPoolExecutor(max_workers=max(1, int(threads))) as ex:
        list(ex.map(one, words))
    return hits, suggs

def brute_force_fields(endpoint: str, headers: Dict[str, str],
                       op_root: str, op_names: List[str], field_words: List[str],
                       threads: int, rate: RateLimiter, log_fn, prog_fn, suggestions_enabled: bool):
    lock = threading.Lock()
    out: Dict[str, Dict[str, List[str]]] = {q: {"required_args": [], "fields": []} for q in op_names}
    req_re = re.compile(r'argument \"([A-Za-z0-9_]+)\" of type \"([^\"]+)\" is required')
    sugg_re = re.compile(r'Did you mean \"([A-Za-z0-9_]+)\"')
    jobs = [(q, f) for q in op_names for f in field_words]
    total = len(jobs); done = 0; t0 = time.time()
    def one(job):
        nonlocal done
        rate.acquire()
        q, field = job
        payload = {"query": f"{op_root} Test {{ {q} {{ {field} }} }}"}
        try:
            r = safe_post(endpoint, headers, payload, timeout=20)
            data = r.json() if r is not None else {}
            errors = data.get("errors", [])
            required_args = []; valid_field = True; suggested_field = None
            for error in errors:
                msg = error.get("message", "")
                m = req_re.search(msg)
                if m: required_args.append(f"${m.group(1)}:{m.group(2)}")
                if "Cannot query field" in msg:
                    valid_field = False
                    if suggestions_enabled:
                        sm = sugg_re.search(msg)
                        if sm: suggested_field = sm.group(1); valid_field = True
                if "must not have a selection" in msg: # Handle scalar return types
                    valid_field = True
                    break
            field_to_save = suggested_field if suggested_field else field
            with lock:
                for a in sorted(set(required_args)):
                    if a not in out[q]["required_args"]: out[q]["required_args"].append(a)
                if valid_field and field_to_save and field_to_save not in out[q]["fields"]:
                    out[q]["fields"].append(field_to_save)
        except Exception as e:
            log_fn(f"[ERR] {q}.{field}: {e}")
        finally:
            with lock:
                done += 1; prog_fn(done, total, done/max(0.001, time.time()-t0))
    with cf.ThreadPoolExecutor(max_workers=max(1, int(threads))) as ex:
        list(ex.map(one, jobs))
    for q in out:
        out[q]["fields"].sort(); out[q]["required_args"].sort()
    return out

class FuzzerTab(BaseTab):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        # Set up persistent fields
        self.url_edit = self._create_persistent_input(QLineEdit, "fuzzer_url", placeholder="https://example.com/graphql")
        self.jwt_edit = self._create_persistent_input(QLineEdit, "fuzzer_jwt", placeholder="JWT")
        self.cookie_edit = self._create_persistent_input(QLineEdit, "fuzzer_cookie", placeholder="cookie1=a; cookie2=b")
        self.extra_hdrs = self._create_persistent_input(QPlainTextEdit, "fuzzer_extra_hdrs", placeholder="X-Forwarded-For: 127.0.0.1")
        self.threads_spin = self._create_persistent_input(QSpinBox, "fuzzer_threads", default_value=12)
        self.target_rps  = self._create_persistent_input(QSpinBox, "fuzzer_rps", default_value=30)
        self.nested_edit = self._create_persistent_input(QLineEdit, "fuzzer_nested", default_value="fsdfsdfsd")
        self.root_wordlist = self._create_persistent_input(QLineEdit, "fuzzer_root_list")
        self.op_names_path = self._create_persistent_input(QLineEdit, "fuzzer_op_names")
        self.field_words_path = self._create_persistent_input(QLineEdit, "fuzzer_field_words")

        self.threads_spin.setRange(1,256); self.target_rps.setRange(1,500)


        top = QHBoxLayout()
        help_btn = QPushButton("Help"); help_btn.clicked.connect(self._show_help)
        top.addStretch(1); top.addWidget(help_btn)
        layout.addLayout(top)

        auth_box = QGroupBox("Endpoint & Auth"); af = QFormLayout()
        af.addRow("GraphQL URL:", self.url_edit); af.addRow("JWT:", self.jwt_edit)
        af.addRow("Cookies:", self.cookie_edit); af.addRow("Extra headers:", self.extra_hdrs)
        
        clear_btn = QPushButton("Clear Auth/Headers"); 
        clear_btn.clicked.connect(lambda: self._clear_inputs([self.url_edit, self.jwt_edit, self.cookie_edit, self.extra_hdrs]))
        af.addWidget(clear_btn)

        auth_box.setLayout(af); layout.addWidget(auth_box)

        rate_box = QGroupBox("Rate Control"); rf = QFormLayout()
        rf.addRow("Threads:", self.threads_spin); rf.addRow("Target RPS:", self.target_rps)
        rate_box.setLayout(rf); layout.addWidget(rate_box)

        root_box = QGroupBox("Root Field Fuzzer"); rff = QFormLayout()
        self.op_combo = QComboBox(); self.op_combo.addItems(["query","mutation"])
        br = QPushButton("Browse…"); br.clicked.connect(lambda: self._pick_root_words(self.root_wordlist))
        hb = QHBoxLayout(); hb.addWidget(self.root_wordlist); hb.addWidget(br)
        self.btn_run_root = QPushButton("Run Root Fuzzer"); self.btn_run_root.clicked.connect(self.run_root_fuzzer)
        rff.addRow("Operation type:", self.op_combo)
        rff.addRow("Nested field:", self.nested_edit)
        rff.addRow("Wordlist:", hb)
        rff.addRow(self.btn_run_root)
        root_box.setLayout(rff); layout.addWidget(root_box)

        qf_box = QGroupBox("Per-Operation Field Brute-Forcer"); qff = QFormLayout()
        self.root_toggle = QComboBox(); self.root_toggle.addItems(["Query","Mutation"])
        bq = QPushButton("Browse ops…"); bq.clicked.connect(lambda: self._pick_opnames(self.op_names_path))
        hb2 = QHBoxLayout(); hb2.addWidget(self.op_names_path); hb2.addWidget(bq)
        bf = QPushButton("Browse fields…"); bf.clicked.connect(lambda: self._pick_fields(self.field_words_path))
        hb3 = QHBoxLayout(); hb3.addWidget(self.field_words_path); hb3.addWidget(bf)
        self.btn_run_brute = QPushButton("Run Brute-Forcer"); self.btn_run_brute.clicked.connect(self.run_bruteforcer)
        qff.addRow("Root type:", self.root_toggle)
        qff.addRow("operations.txt:", hb2)
        qff.addRow("fields wordlist:", hb3)
        qff.addRow(self.btn_run_brute)
        qf_box.setLayout(qff); layout.addWidget(qf_box)

        self.pbar = QProgressBar(); self.pbar.setMaximum(1); self.pbar.setValue(0)
        self.rps_lbl = QLabel("RPS: 0.0"); hb4 = QHBoxLayout(); hb4.addWidget(self.pbar,1); hb4.addWidget(self.rps_lbl)
        layout.addLayout(hb4)
        self.log_box = QPlainTextEdit(); self.log_box.setReadOnly(True); layout.addWidget(self.log_box)

    def _show_help(self):
        self._help_popup("Fuzzer Help",
"""Fuzzer tab
• Root Field Fuzzer: brute queries or mutations using a wordlist; detects valid roots via error heuristics
• Per-Operation Field Brute-Forcer: for a list of operations, tries field names and captures required args
• Target RPS control with auto-adjust; Threads control
• Tells you if the server disables 'Did you mean …' suggestions""")

    def _headers(self):
        return build_headers(self.jwt_edit.text(), self.cookie_edit.text(), self.extra_hdrs.toPlainText())
    def _pick_root_words(self, le: QLineEdit):
        f = self._pick_file("Wordlist", "Text (*.txt);;All Files (*)")
        if f: le.setText(f)
    def _pick_opnames(self, le: QLineEdit):
        f = self._pick_file("operations.txt", "Text (*.txt);;All Files (*)")
        if f: le.setText(f)
    def _pick_fields(self, le: QLineEdit):
        f = self._pick_file("fields wordlist", "Text (*.txt);;All Files (*)")
        if f: le.setText(f)
    
    def run_root_fuzzer(self):
        url = self.url_edit.text().strip(); path = self.root_wordlist.text().strip()
        if not url or not os.path.exists(path):
            QMessageBox.warning(self, "Missing", "Provide URL and wordlist."); return
        words = [w.strip() for w in open(path,'r',encoding='utf-8',errors='ignore') if w.strip()]
        op = self.op_combo.currentText(); nested = self.nested_edit.text().strip() or "fsdfsdfsd"
        th = self.threads_spin.value(); headers = self._headers(); limiter = RateLimiter(self.target_rps.value())

        def work():
            try:
                suggestions_enabled = check_suggestion_support(url, headers)
                if not suggestions_enabled:
                    self.log("ℹ️  Suggestions appear to be disabled by the server (no “Did you mean …” in errors).")
                self.log(f"[RootFuzzer] {op} with {len(words)} candidates, target {self.target_rps.value()} rps, {th} threads")
                hits, suggs = fuzz_root_fields(url, headers, words, op, nested, th, limiter, self.log, self.prog, suggestions_enabled)
                open("ValidHits.txt","w").write("\n".join(sorted(hits)))
                open("ValidSuggestions.txt","w").write("\n".join(sorted(suggs)))
                all_set = sorted(set().union(hits, suggs)); open("all.txt","w").write("\n".join(all_set))
                self.log(f"[RootFuzzer] Hits: {len(hits)} | Suggestions: {len(suggs)} | Saved all.txt")
                self.prog(1,1,0.0)
            except Exception as e:
                self.log(f"[RootFuzzer] ERROR: {e}\n{traceback.format_exc()}")

        threading.Thread(target=work, daemon=True).start()

    def run_bruteforcer(self):
        url = self.url_edit.text().strip()
        op_path = self.op_names_path.text().strip()
        fpath   = self.field_words_path.text().strip()
        if not url or not os.path.exists(op_path) or not os.path.exists(fpath):
            QMessageBox.warning(self, "Missing", "Provide URL, operations.txt, and fields list."); return
        op_names = [x.strip() for x in open(op_path,'r',encoding='utf-8',errors='ignore') if x.strip()]
        fields   = [x.strip() for x in open(fpath,'r',encoding='utf-8',errors='ignore') if x.strip()]
        headers  = self._headers(); th = self.threads_spin.value()
        root     = self.root_toggle.currentText().lower()
        limiter  = RateLimiter(self.target_rps.value())

        def work():
            try:
                suggestions_enabled = check_suggestion_support(url, headers)
                if not suggestions_enabled:
                    self.log("ℹ️  Suggestions appear to be disabled by the server (no “Did you mean …” in errors).")
                self.log(f"[Brute] {root} :: {len(op_names)} ops × {len(fields)} fields | target {self.target_rps.value()} rps, {th} threads")
                result = brute_force_fields(url, headers, root, op_names, fields, th, limiter, self.log, self.prog, suggestions_enabled)
                outdir = f"{root}_ops"; os.makedirs(outdir, exist_ok=True)
                for q, data in result.items():
                    with open(os.path.join(outdir, f"{q}.txt"),"w") as f:
                        if data["required_args"]:
                            f.write("#### Required Arguments\n")
                            for a in data["required_args"]: f.write(a+"\n"); f.write("\n")
                        for fld in data["fields"]: f.write(fld+"\n")
                self.log(f"[Brute] Saved per-{root} results to ./{root}_ops/")
                self.prog(1,1,0.0)
            except Exception as e:
                self.log(f"[Brute] ERROR: {e}\n{traceback.format_exc()}")

        threading.Thread(target=work, daemon=True).start()

# ======================== Introspection Tabs (NEW container for Req 3) ========================

# Introspection Queries (for OperationMonitorTab)
QUERY_INTROSPECTION = """
query {
    __schema {
        queryType {
            fields {
                name
            }
        }
    }
}
"""
MUTATION_INTROSPECTION = """
query {
    __schema {
        mutationType {
            fields {
                name
            }
        }
    }
}
"""

class OperationMonitorTab(BaseTab):
    """
    Operation Monitor Tab
    """
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self.settings.beginGroup("OperationMonitor")
        
        # Set up persistent fields
        self.url = self._create_persistent_input(QLineEdit, "LastHost", placeholder="https://example.com/graphql")
        self.jwt = self._create_persistent_input(QLineEdit, "jwt", placeholder="JWT")
        self.cookie = self._create_persistent_input(QLineEdit, "cookie", placeholder="session=…; other=…")
        self.out_dir = self._create_persistent_input(QLineEdit, "LastOutputDir", default_value="op_monitor_output", placeholder="Output base dir (for history files)")
        
        self.url.setText(self.settings.value("LastHost", ""))
        self.out_dir.setText(self.settings.value("LastOutputDir", "op_monitor_output"))
        self.url.textChanged.connect(lambda t: self.settings.setValue("LastHost", t))
        self.out_dir.textChanged.connect(lambda t: self.settings.setValue("LastOutputDir", t))
        
        top = QHBoxLayout()
        help_btn = QPushButton("Help"); help_btn.clicked.connect(self._show_help)
        top.addStretch(1); top.addWidget(help_btn)
        layout.addLayout(top)

        auth_box = QGroupBox("Endpoint & Auth (Saves Host/Path)"); af = QFormLayout()
        
        outbtn = QPushButton("Choose…"); outbtn.clicked.connect(lambda: self._pick_out(self.out_dir))
        hb = QHBoxLayout(); hb.addWidget(self.out_dir); hb.addWidget(outbtn)
        
        clear_btn = QPushButton("Clear Auth/Headers");
        clear_btn.clicked.connect(lambda: self._clear_inputs([self.url, self.jwt, self.cookie]))

        af.addRow("GraphQL URL:", self.url); af.addRow("JWT:", self.jwt)
        af.addRow("Cookies:", self.cookie); 
        af.addRow("Output dir:", hb)
        af.addWidget(clear_btn)
        auth_box.setLayout(af); layout.addWidget(auth_box)

        run_btn = QPushButton("Run Name Monitor (Check for New Operations)"); run_btn.clicked.connect(self.run_monitor)
        layout.addWidget(run_btn)
        
        self.log_box = QPlainTextEdit(); self.log_box.setReadOnly(True); layout.addWidget(self.log_box)
        self.settings.endGroup()


    def _show_help(self):
        self._help_popup("Operation Name Monitor Help",
"""Operation Name Monitor tab
• Performs simple Introspection to get only the top-level Query and Mutation names.
• Compares the newly found names against a history file in the Output Directory.
• Reports any NEW names found since the last run.
• Saves the Host and Output Path for persistence (per Request 3).""")
        
    def _pick_out(self, le: QLineEdit):
        d = self._pick_dir("Choose output directory")
        if d: le.setText(d)
        
    def _headers(self):
        # We don't use extra headers in this simplified monitor, but we should include content-type
        headers = {"Content-Type": "application/json", "User-Agent": "Pentest-AIO/GraphQL"}
        if self.jwt.text().strip(): headers["Authorization"] = f"Bearer {self.jwt.text().strip()}"
        if self.cookie.text().strip(): headers["Cookie"] = self.cookie.text().strip()
        return headers

    def _make_graphql_request(self, url, query):
        """Handles the HTTP request to the GraphQL endpoint."""
        payload = {"query": query}
        try:
            response = requests.post(url, headers=self._headers(), json=payload, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.log(f"  [ERROR] Request failed for {url}. Error: {e}")
            raise

    def _get_fields_from_api(self, url, entity_type):
        """Runs the introspection query for a single entity type."""
        
        if entity_type == 'query':
            graphql_query = QUERY_INTROSPECTION
            path = ['data', '__schema', 'queryType', 'fields']
        elif entity_type == 'mutation':
            graphql_query = MUTATION_INTROSPECTION
            path = ['data', '__schema', 'mutationType', 'fields']
        else:
            return set()

        try:
            data = self._make_graphql_request(url, graphql_query)
        except Exception:
            return set()
            
        current = data
        for key in path:
            current = current.get(key) if isinstance(current, dict) else None
            if current is None: break
        
        if current is not None and isinstance(current, list):
            return set(field['name'] for field in current if isinstance(field, dict) and 'name' in field)
        return set()

    def _process_entity_type(self, url, entity_type, output_dir):
        """Handles the full workflow for a single entity type (Query or Mutation)."""
        
        filename = os.path.join(output_dir, f"{entity_type.capitalize()}.txt")
        
        # 1. Load existing fields
        existing_fields = set()
        if os.path.exists(filename):
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    existing_fields = set(line.strip() for line in f if line.strip())
            except Exception as e:
                self.log(f"[WARNING] Could not read existing fields from {filename}. Error: {e}")

        # 2. Get new fields from the API
        new_fields_set = self._get_fields_from_api(url, entity_type)
        self.log(f"-> Found {len(new_fields_set)} unique {entity_type} fields from API.")

        # 3. Find the difference (New - Existing)
        new_items = sorted(list(new_fields_set - existing_fields))
        
        # 4. Save the full, updated list for the next run
        if new_fields_set:
            try:
                sorted_fields = sorted(list(new_fields_set))
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(sorted_fields) + '\n')
                self.log(f"Updated {filename} with the full list of {len(new_fields_set)} items.")
            except Exception as e:
                self.log(f"[ERROR] Failed to save updated fields to {filename}: {e}")

        # 5. Report new items
        if new_items:
            self.log(f"\n[!!! NEW {entity_type.upper()} ITEMS FOUND ({len(new_items)}) !!!]")
            for item in new_items:
                self.log(f"- {item}")
            self.log("-" * 30)
        else:
            self.log(f"[OK] No new {entity_type} fields found.")
        
        return new_items

    def run_monitor(self):
        url = self.url.text().strip()
        out_dir = self.out_dir.text().strip()
        
        if not url:
            QMessageBox.warning(self, "Missing", "Enter GraphQL URL."); return
        
        self.settings.beginGroup("OperationMonitor")
        self.settings.setValue("LastHost", url)
        self.settings.setValue("LastOutputDir", out_dir)
        self.settings.endGroup()
        
        os.makedirs(out_dir, exist_ok=True)

        def work():
            self.log_box.clear()
            self.log("🚀 Starting Operation Name Monitor…")
            self.log(f"URL: {url}")
            self.log(f"Output: {out_dir}")
            self.log("="*60)
            
            try:
                q_new = self._process_entity_type(url, 'query', out_dir)
                m_new = self._process_entity_type(url, 'mutation', out_dir)

                self.log("\n🎉 Monitoring complete!")
                if not q_new and not m_new:
                    self.log("No new operations found in this run.")
                self.log("="*60)

            except Exception as e:
                self.log(f"[Monitor] ERROR: {e}\n{traceback.format_exc()}")

        threading.Thread(target=work, daemon=True).start()

# --- Deep Introspector and FullIntrospectionTab (Updated for caching and speed) ---

class DeepIntrospector:
    
    # Static helpers for type unwrapping and scalar check
    @staticmethod
    def unwrap_type(type_dict: Dict) -> str:
        if not type_dict: return None
        kind = type_dict.get("kind"); of_type = type_dict.get("ofType")
        if kind in ["NON_NULL", "LIST"] and of_type: return DeepIntrospector.unwrap_type(of_type)
        return type_dict.get("name")
    
    @staticmethod
    def is_scalar_type(type_name: str) -> bool:
        return type_name in ["Int", "Float", "String", "Boolean", "ID", "DateTime", "Date", "Time", "JSON"]
    
    @staticmethod
    def is_required(type_dict: Dict) -> bool:
        return type_dict.get("kind") == "NON_NULL"

    def __init__(self, endpoint: str, headers: Dict[str,str], out_base: str, log_fn, prog_fn, threads=1, stop_event=None):
        self.endpoint = endpoint
        self.headers = headers
        self.out_base = out_base
        self._log_signal = log_fn
        self._prog_signal = prog_fn
        self.thread_count = threads
        self.stop_event = stop_event if stop_event is not None else threading.Event()
        
        # --- Caching ---
        self.type_cache: Dict[str, Any] = self._load_cache()
        self.processed_types: Set[str] = set(self.type_cache.keys())
        # -------------
        
        self.request_count = 0
        self.start_time = time.time()
        for folder in ['Query','Mutation','Subscription']:
            os.makedirs(os.path.join(self.out_base, folder), exist_ok=True)
            
    def _load_cache(self):
        cache_path = os.path.join(self.out_base, CACHE_FILENAME)
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                self._log_signal(f"⚠️  Could not load type cache: {e}. Starting fresh.")
                return {}
        return {}

    def _save_cache(self):
        cache_path = os.path.join(self.out_base, CACHE_FILENAME)
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(self.type_cache, f, indent=2)
            self._log_signal(f"💾 Saved {len(self.type_cache)} types to cache.")
        except Exception as e:
            self._log_signal(f"❌ Error saving type cache: {e}")

    def _post(self, query: str, variables: Dict=None) -> Dict:
        if self.stop_event.is_set(): raise InterruptedError("Operation stopped by user.")
        
        self.request_count += 1
        payload = {"query": query}
        if variables: payload["variables"] = variables
        
        # Calculate RPS for progress bar update (approximation)
        elapsed = time.time() - self.start_time
        rps = self.request_count / max(elapsed, 0.001)

        self._prog_signal(self.request_count, self.request_count + 100, rps) # Total is arbitrary here
        
        r = safe_post(self.endpoint, self.headers, payload, timeout=45)
        if r is None: raise RuntimeError("No response")
        if r.status_code in (401,403): raise PermissionError(f"Forbidden ({r.status_code})")
        r.raise_for_status(); return r.json()

    def schema(self) -> Dict:
        # Using the comprehensive query structure from AutoGQL_Introspection.py
        q = """
        query ComprehensiveIntrospection {
          __schema {
            queryType {
              name
              fields {
                name
                description
                args {
                  name
                  description
                  type {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                        ofType {
                          kind
                          name
                        }
                      }
                    }
                  }
                  defaultValue
                }
                type {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
                isDeprecated
                deprecationReason
              }
            }
            mutationType {
              name
              fields {
                name
                description
                args {
                  name
                  description
                  type {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                        ofType {
                          kind
                          name
                        }
                      }
                    }
                  }
                  defaultValue
                }
                type {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
                isDeprecated
                deprecationReason
              }
            }
            subscriptionType {
              name
              fields {
                name
                description
                args {
                  name
                  description
                  type {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                        ofType {
                          kind
                          name
                        }
                      }
                    }
                  }
                  defaultValue
                }
                type {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
                isDeprecated
                deprecationReason
              }
            }
          }
        }
        """
        return self._post(q)

    def get_type_details(self, type_name: str) -> Optional[Dict]:
        """Fetches type details, checking cache first."""
        if self.stop_event.is_set(): return None
        if not type_name or self.is_scalar_type(type_name): return None
        if type_name in self.type_cache: return self.type_cache[type_name]
        
        # Prevent redundant calls if type was fetched/failed previously
        if type_name in self.processed_types: return None 
        self.processed_types.add(type_name)
        
        # Introspect if not in cache
        q = """
        query GetTypeDetails($typeName: String!) {
          __type(name: $typeName) {
            name
            kind
            description
            fields {
              name
              description
              type {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                    }
                  }
                }
              }
            }
            inputFields {
              name
              description
              type {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                    }
                  }
                }
              }
            }
            enumValues {
              name
              description
              isDeprecated
              deprecationReason
            }
          }
        }
        """
        try:
            data = self._post(q, {"typeName": type_name}); node = data["data"]["__type"]
            self.type_cache[type_name] = node; return node
        except Exception as e:
            self._log_signal(f"⚠️  Could not introspect type {type_name}: {e}")
            return None

    def _fmt_type_details(self, type_info: Dict) -> Dict:
        # Matches AutoGQL_Introspection's output structure
        if not type_info: return {}
        out = {"name": type_info.get("name"), "kind": type_info.get("kind"), "description": type_info.get("description")}
        
        # Fields for OBJECT/INTERFACE types
        if isinstance(type_info.get("fields"), list):
            out["fields"] = {}
            for f in type_info["fields"]:
                if isinstance(f, dict) and "name" in f and "type" in f:
                    out["fields"][f["name"]] = {"type": self.unwrap_type(f["type"]), "description": f.get("description")}
        
        # Input fields for INPUT_OBJECT types
        if isinstance(type_info.get("inputFields"), list):
            out["input_fields"] = {}
            for f in type_info["inputFields"]:
                if isinstance(f, dict) and "name" in f and "type" in f:
                    tname = self.unwrap_type(f["type"])
                    req = self.is_required(f.get("type",{}))
                    out["input_fields"][f["name"]] = {"type": tname, "required": req, "description": f.get("description")}
        
        return out

    def _add_nested_fields(self, content: List[str], type_name: str, indent: str, visited: set):
        if self.stop_event.is_set(): return
        if not type_name or self.is_scalar_type(type_name) or type_name in visited: return
        
        # Create a copy of the visited set for the recursion path to prevent infinite loops in cycles
        current_visited = visited.copy()
        current_visited.add(type_name)

        ti = self.type_cache.get(type_name)
        if ti and isinstance(ti.get("fields"), list):
            for fld in ti["fields"]:
                if self.stop_event.is_set(): return
                if isinstance(fld, dict) and "name" in fld and "type" in fld:
                    t2 = self.unwrap_type(fld["type"])
                    content.append(f"{indent}└─ {fld['name']}: {t2}")
                    if t2 and not self.is_scalar_type(t2) and t2 not in current_visited:
                        # Ensure nested type is in cache before recursing
                        if t2 not in self.type_cache: self.get_type_details(t2)
                        self._add_nested_fields(content, t2, indent+"    ", current_visited)
        
    def _write_op_file(self, op: Dict, root: str):
        if self.stop_event.is_set(): return
        name = op["name"]; folder = os.path.join(self.out_base, root.capitalize())
        os.makedirs(folder, exist_ok=True)
        fp = os.path.join(folder, f"{name}.txt")
        lines=[]; 
        
        # --- File Header ---
        lines.append("="*80); lines.append(f"{root.upper()}: {name}"); lines.append("="*80)
        lines.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"); lines.append("")
        if op.get("description"): lines.append(f"Description: {op['description']}"); lines.append("")
        if op.get("isDeprecated"): lines.append("⚠️  DEPRECATED"); 
        if op.get("deprecationReason"): lines.append(f"Reason: {op['deprecationReason']}"); lines.append("")
        
        # --- Arguments Section ---
        lines.append("ARGUMENTS:"); lines.append("-"*40)
        args = op.get("args") or []
        if not args: lines.append("No arguments"); lines.append("")
        else:
            for a in args:
                if self.stop_event.is_set(): return
                req = "REQUIRED" if a.get("required") else "optional"
                lines.append(f"• {a['name']} ({a['unwrapped_type']}) - {req}")
                if a.get("description"): lines.append(f"  Description: {a['description']}")
                if a.get("defaultValue"): lines.append(f"  Default: {a['defaultValue']}")
                
                td = a.get("type_details",{}).get("input_fields",{})
                if td:
                    lines.append("  Input Fields:")
                    for fname, finfo in td.items():
                        req2 = "required" if finfo.get("required") else "optional"
                        lines.append(f"    └─ {fname}: {finfo.get('type')} ({req2})")
                        if finfo.get("description"): lines.append(f"       {finfo['description']}")
                lines.append("")
                
        # --- Return Type Section ---
        ret = op.get("unwrapped_return_type","Unknown")
        lines.append("RETURN TYPE:"); lines.append("-"*40); lines.append(f"Type: {ret}")
        rtd = op.get("return_type_details",{}).get("fields",{})
        if rtd:
            lines.append("Fields:")
            for fn, fi in rtd.items():
                if self.stop_event.is_set(): return
                lines.append(f"  • {fn}: {fi.get('type')}")
                if fi.get("description"): lines.append(f"    {fi['description']}")
                nested = fi.get("type")
                
                # Recursive nested fields (Matching AutoGQL_Introspection)
                if nested and nested in self.type_cache and not self.is_scalar_type(nested):
                    self._add_nested_fields(lines, nested, "    ", set())
        lines.append("")

        # --- GraphQL Example ---
        lines.append("GRAPHQL EXAMPLE:"); lines.append("-"*40); lines.append(f"{root} {{")
        # Build example arguments
        if args:
            arg_examples=[]
            for a in args:
                td = a.get("type_details",{}).get("input_fields",{})
                if td:
                    inner=[]
                    for fname, finfo in td.items():
                        if finfo.get("required"):
                            t=finfo.get("type")
                            if t=="String": inner.append(f'{fname}: "example_value"')
                            elif t in ("Int","Float"): inner.append(f'{fname}: 123')
                            elif t=="Boolean": inner.append(f'{fname}: true')
                            else: inner.append(f'{fname}: "..."')
                    arg_examples.append(f'{a["name"]}: {{ {", ".join(inner)} }}' if inner else f'{a["name"]}: {{}}')
                else:
                    t=a.get("unwrapped_type")
                    if t=="String": arg_examples.append(f'{a["name"]}: "example"')
                    elif t in ("Int","Float"): arg_examples.append(f'{a["name"]}: 123')
                    elif t=="Boolean": arg_examples.append(f'{a["name"]}: true')
                    else: arg_examples.append(f'{a["name"]}: "..."')
            lines.append(f'  {name}({", ".join(arg_examples)}) {{')
        else:
            lines.append(f'  {name} {{')
        
        # Build example return fields (Matching AutoGQL_Introspection's 5 subfield limit)
        if rtd:
            for fn in list(rtd.keys()):
                lines.append(f"    {fn}")
                nested = rtd[fn].get("type")
                if nested and nested in self.type_cache and not self.is_scalar_type(nested):
                    ti = self.type_cache[nested]
                    if ti and isinstance(ti.get("fields"), list):
                        for sub in ti["fields"][:5]:
                            if isinstance(sub, dict) and "name" in sub:
                                lines.append(f"      {sub['name']}")
                        if len(ti["fields"])>5:
                            lines.append(f"      # ... {len(ti['fields'])-5} more subfields available")
        else:
            lines.append("    # Add fields you want to retrieve")
        lines.append("  }"); lines.append("}"); lines.append("")
        
        # --- Type Definitions Section (Matching AutoGQL_Introspection) ---
        has_type_def_section = (op.get("return_type_details") or any(a.get("type_details") for a in args))
        if has_type_def_section:
            lines.append("TYPE DEFINITIONS:")
            lines.append("-" * 40)
            
            # Show input types
            for arg in args:
                if arg.get("type_details"):
                    type_details = arg["type_details"]
                    lines.append(f"Input Type: {type_details['name']}")
                    if type_details.get("description"):
                        lines.append(f"  {type_details['description']}")
                    
                    if type_details.get("input_fields"):
                        for field_name, field_info in type_details["input_fields"].items():
                            req_text = "!" if field_info["required"] else ""
                            lines.append(f"  {field_name}: {field_info['type']}{req_text}")
                    lines.append("")
            
            # Show return type details
            if op.get("return_type_details"):
                return_details = op["return_type_details"]
                lines.append(f"Return Type: {return_details['name']}")
                if return_details.get("description"):
                    lines.append(f"  {return_details['description']}")
                
                if return_details.get("fields"):
                    for field_name, field_info in return_details["fields"].items():
                        lines.append(f"  {field_name}: {field_info['type']}")
            lines.append("")

        with open(fp,'w',encoding='utf-8') as f: f.write('\n'.join(lines))
        self._log_signal(f"📄 Created: {fp}")


    def _eager_introspect_types(self, ops: List[Dict]):
        """Eagerly collects all non-scalar argument and return types for processing."""
        if self.stop_event.is_set(): return
        types_to_fetch = set()
        for op in ops:
            if self.stop_event.is_set(): return
            # Collect return type
            r = self.unwrap_type(op["type"])
            if r and not self.is_scalar_type(r) and r not in self.type_cache:
                types_to_fetch.add(r)
            # Collect argument types
            for arg in op.get("args") or []:
                a = self.unwrap_type(arg["type"])
                if a and not self.is_scalar_type(a) and a not in self.type_cache:
                    types_to_fetch.add(a)
        
        if self.stop_event.is_set(): return
        self._log_signal(f"🔎 Eagerly collecting {len(types_to_fetch)} types...")
        
        def fetch_one_type(type_name):
            if self.stop_event.is_set(): return
            self.get_type_details(type_name)

        # Use ThreadPoolExecutor for concurrent fetching
        with cf.ThreadPoolExecutor(max_workers=self.thread_count) as executor:
            futures = [executor.submit(fetch_one_type, t) for t in types_to_fetch]
            # Wait for completion or stop event
            for future in cf.as_completed(futures):
                if self.stop_event.is_set():
                    # Cancel remaining futures
                    for f in futures: f.cancel()
                    break

        if self.stop_event.is_set(): return

        # Check for nested types found during eager fetch
        newly_cached_types = list(self.type_cache.keys() - self.processed_types)
        if newly_cached_types:
            self.processed_types.update(newly_cached_types)
            # Recursively check for nested types within the newly fetched ones
            for type_name in newly_cached_types:
                 self._introspect_nested(self.type_cache[type_name])
            
        if not self.stop_event.is_set(): self._save_cache()


    def _enrich_ops(self, ops: List[Dict], root: str) -> List[Dict]:
        out=[]; total=len(ops); idx=0
        for field in ops:
            if self.stop_event.is_set(): return []
            idx+=1; self._log_signal(f"📝 [{idx}/{total}] Processing {field['name']}")
            node = field.copy()
            # args
            a2=[]
            for arg in (field.get("args") or []):
                an = arg.copy()
                tname = self.unwrap_type(arg["type"]); an["unwrapped_type"]=tname
                an["required"] = self.is_required(arg.get("type",{}))
                if tname and not self.is_scalar_type(tname):
                    ti = self.type_cache.get(tname)
                    if ti: an["type_details"]=self._fmt_type_details(ti)
                a2.append(an)
            node["args"]=a2
            
            # return type
            r = self.unwrap_type(field["type"]); node["unwrapped_return_type"]=r
            if r and not self.is_scalar_type(r):
                ti = self.type_cache.get(r)
                if ti: node["return_type_details"]=self._fmt_type_details(ti)
            
            # --- Save file instantly (Fix 4: Speed) ---
            self._write_op_file(node, root)
            # ------------------------------------------
            out.append(node)
            self._prog_signal(idx, total, 0.0)
        return out

    def _introspect_nested(self, type_info: Dict):
        """Introspects nested types from a fetched type definition."""
        if self.stop_event.is_set(): return
        if not type_info: return
        nest=set()
        
        # Fields
        if isinstance(type_info.get("fields"), list):
            for f in type_info["fields"]:
                tn = self.unwrap_type(f.get("type")); 
                if tn and not self.is_scalar_type(tn) and tn not in self.type_cache: nest.add(tn)
        # Input Fields
        if isinstance(type_info.get("inputFields"), list):
            for f in type_info["inputFields"]:
                tn = self.unwrap_type(f.get("type")); 
                if tn and not self.is_scalar_type(tn) and tn not in self.type_cache: nest.add(tn)
        
        def fetch_one_nested_type(type_name):
            if self.stop_event.is_set(): return
            self.get_type_details(type_name)
        
        # Recursively fetch nested types
        if nest:
            with cf.ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                futures = [executor.submit(fetch_one_nested_type, t) for t in nest]
                
                for future in cf.as_completed(futures):
                    if self.stop_event.is_set():
                        for f in futures: f.cancel()
                        break
                    
            # Recursively check newly added types for their nested dependencies
            for tn in nest:
                if tn in self.type_cache:
                    self._introspect_nested(self.type_cache[tn])

    def run(self):
        if self.stop_event.is_set(): return

        self._log_signal("🚀 Starting complete schema introspection (with caching)…")
        self._log_signal(f"⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._log_signal(f"Loaded {len(self.type_cache)} types from cache.")
        self._log_signal("="*80)
        
        try:
            # Step 1: Get root schema and operations
            data = self.schema()
            sch = data["data"]["__schema"]
            
            # Step 2: Eagerly fetch all types (arguments and returns) concurrently
            all_ops = []
            if sch.get("queryType") and sch["queryType"].get("fields"): all_ops.extend(sch["queryType"]["fields"])
            if sch.get("mutationType") and sch["mutationType"].get("fields"): all_ops.extend(sch["mutationType"]["fields"])
            if sch.get("subscriptionType") and sch["subscriptionType"].get("fields"): all_ops.extend(sch["subscriptionType"]["fields"])

            self._eager_introspect_types(all_ops)

            if self.stop_event.is_set(): raise InterruptedError()
            
            # Step 3: Enrich data and write files (fast step, minimal network calls now)
            res={}
            if sch.get("queryType") and sch["queryType"].get("fields"):
                self._log_signal("📋 Processing Queries…")
                res["queries"]=self._enrich_ops(sch["queryType"]["fields"],"query")
                self._log_signal(f"✅ Created {len(res.get('queries',[]))} query files"); self._log_signal("="*40)
            
            if self.stop_event.is_set(): raise InterruptedError()

            if sch.get("mutationType") and sch["mutationType"].get("fields"):
                self._log_signal("🔧 Processing Mutations…")
                res["mutations"]=self._enrich_ops(sch["mutationType"]["fields"],"mutation")
                self._log_signal(f"✅ Created {len(res.get('mutations',[]))} mutation files"); self._log_signal("="*40)
            
            if self.stop_event.is_set(): raise InterruptedError()

            if sch.get("subscriptionType") and sch["subscriptionType"].get("fields"):
                self._log_signal("📡 Processing Subscriptions…")
                res["subscriptions"]=self._enrich_ops(sch["subscriptionType"]["fields"],"subscription")
                self._log_signal(f"✅ Created {len(res.get('subscriptions',[]))} subscription files"); self._log_signal("="*40)
                
            elapsed = time.time()-self.start_time; rps = self.request_count/max(elapsed,0.01)
            self._log_signal("🎉 Schema introspection complete!")
            self._log_signal("="*80)
            self._log_signal("📈 FINAL STATISTICS:")
            self._log_signal(f"   • Total requests: {self.request_count}")
            self._log_signal(f"   • Total time: {elapsed:.1f} seconds")
            self._log_signal(f"   • Average RPS: {rps:.2f} requests/second")
            self._log_signal(f"   • Types processed: {len(self.type_cache)}")
            self._log_signal("="*80)
            
        except InterruptedError:
            self._log_signal("🛑 Introspection manually stopped by user.")
        except PermissionError:
            self._log_signal("Introspection forbidden: server returned 401/403 or equivalent error message.")
            QMessageBox.information(None, "Introspection", "Introspection fully disabled (forbidden).")
        except Exception as e:
            self._log_signal(f"[Introspection] ERROR: {e}\n{traceback.format_exc()}")
        finally:
            self._prog_signal(1,1,0.0)


class IntrospectionWorker(QObject):
    log_text = pyqtSignal(str)
    progress_update = pyqtSignal(int, int, float)
    finished = pyqtSignal()

    def __init__(self, endpoint, headers, out_base, threads, stop_event):
        super().__init__()
        self.endpoint = endpoint
        self.headers = headers
        self.out_base = out_base
        self.threads = threads
        self.stop_event = stop_event

    def run(self):
        try:
            insp = DeepIntrospector(
                self.endpoint, self.headers, self.out_base, 
                log_fn=self.log_text.emit, 
                prog_fn=self.progress_update.emit,
                threads=self.threads,
                stop_event=self.stop_event
            )
            insp.run()
        except Exception as e:
            self.log_text.emit(f"[FATAL WORKER ERROR] {e}\n{traceback.format_exc()}")
        finally:
            self.finished.emit()


class FullIntrospectionTab(BaseTab): # Renamed
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        # Set up persistent fields
        self.url = self._create_persistent_input(QLineEdit, "intro_url", placeholder="https://example.com/graphql")
        self.jwt = self._create_persistent_input(QLineEdit, "intro_jwt", placeholder="JWT")
        self.cookie = self._create_persistent_input(QLineEdit, "intro_cookie", placeholder="session=…; other=…")
        self.extra = self._create_persistent_input(QPlainTextEdit, "intro_extra", placeholder="X-Token: abc\nAccept: */*")
        self.out_dir = self._create_persistent_input(QLineEdit, "intro_out_dir", placeholder="Output base dir (defaults to CWD)")
        self.threads_spin = self._create_persistent_input(QSpinBox, "intro_threads", default_value=8)
        self.threads_spin.setRange(1, 64)
        

        top = QHBoxLayout()
        help_btn = QPushButton("Help"); help_btn.clicked.connect(self._show_help)
        top.addStretch(1); top.addWidget(help_btn)
        layout.addLayout(top)

        auth_box = QGroupBox("Endpoint & Auth"); af = QFormLayout()
        af.addRow("GraphQL URL:", self.url); af.addRow("JWT:", self.jwt)
        af.addRow("Cookies:", self.cookie); af.addRow("Extra headers:", self.extra)
        
        clear_btn = QPushButton("Clear Auth/Headers"); 
        clear_btn.clicked.connect(lambda: self._clear_inputs([self.url, self.jwt, self.cookie, self.extra]))
        af.addWidget(clear_btn)
        
        auth_box.setLayout(af); layout.addWidget(auth_box)

        hb_out = QHBoxLayout()
        outbtn = QPushButton("Choose…"); outbtn.clicked.connect(lambda: self._pick_out(self.out_dir))
        hb_out.addWidget(self.out_dir); hb_out.addWidget(outbtn)
        
        layout.addLayout(hb_out)
        
        # Thread control (Req 6)
        hb_threads = QHBoxLayout()
        hb_threads.addWidget(QLabel("Worker Threads:"))
        hb_threads.addWidget(self.threads_spin)
        hb_threads.addStretch(1)
        layout.addLayout(hb_threads)

        # Run/Stop buttons
        hb_run = QHBoxLayout()
        self.run_btn = QPushButton("Run Full Detailed Introspection")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.run_btn.clicked.connect(self.run_intro)
        self.stop_btn.clicked.connect(self.stop_intro)
        hb_run.addWidget(self.run_btn)
        hb_run.addWidget(self.stop_btn)
        layout.addLayout(hb_run)

        self.pbar = QProgressBar(); self.pbar.setMaximum(1); self.pbar.setValue(0)
        self.rps_lbl = QLabel("RPS: 0.0")
        pb = QHBoxLayout(); pb.addWidget(self.pbar,1); pb.addWidget(self.rps_lbl); layout.addLayout(pb)
        self.log_box = QPlainTextEdit(); self.log_box.setReadOnly(True); layout.addWidget(self.log_box)

    def _show_help(self):
        self._help_popup("Full Detailed Introspection Help",
"""Full Detailed Introspection tab
• Performs normal __schema introspection, then a deep custom walk of types
• Uses local caching to significantly speed up repeated runs to the same schema (Cache: .type_cache.json).
• For each Query/Mutation/Subscription field, writes a detailed .txt (args, input objects, return fields, sample query)
• Files are saved to subfolders: Query/, Mutation/, Subscription/""")

    def _pick_out(self, le: QLineEdit):
        d = self._pick_dir("Choose output directory")
        if d: le.setText(d)
    def _headers(self):
        return build_headers(self.jwt.text(), self.cookie.text(), self.extra.toPlainText())

    def run_intro(self):
        if self._worker_thread and self._worker_thread.isRunning(): return
        
        url = self.url.text().strip()
        if not url:
            QMessageBox.warning(self, "Missing", "Enter GraphQL URL."); return
        
        self.log_box.clear()
        self._stop_event.clear()
        
        # Setup Worker
        self._worker_thread = QThread()
        self._worker = IntrospectionWorker(
            endpoint=url,
            headers=self._headers(),
            out_base=self.out_dir.text().strip() or os.getcwd(),
            threads=self.threads_spin.value(),
            stop_event=self._stop_event
        )
        
        # Connect signals
        self._worker.moveToThread(self._worker_thread)
        self._worker.log_text.connect(self.log)
        self._worker.progress_update.connect(self.prog)
        self._worker.finished.connect(self._worker_thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker_thread.finished.connect(self._worker_thread.deleteLater)
        self._worker_thread.started.connect(self._worker.run)
        self._worker_thread.finished.connect(self._on_finished)
        
        # Start
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._worker_thread.start()

    def stop_intro(self):
        if self._worker_thread and self._worker_thread.isRunning():
            self._stop_event.set()
            self.log("Sending stop signal... waiting for thread to finish current operation.")
            
    def _on_finished(self):
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)


class IntrospectionTab(BaseTab): # New container for Req 3
    def __init__(self):
        super().__init__()
        v = QVBoxLayout(self)
        tabs = QTabWidget()
        tabs.addTab(FullIntrospectionTab(), "Full Detailed Introspection")
        tabs.addTab(OperationMonitorTab(), "Operation Name Monitor")
        v.addWidget(tabs)

# ======================== Wordlist Extractor Tab (Minor update to browse and persistence) ========================

class WordlistExtractorTab(BaseTab):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        
        # Set up persistent fields
        self.folder_edit = self._create_persistent_input(QLineEdit, "wordlist_folder", placeholder="Folder that contains .txt files (recursive)")
        self.output_edit = self._create_persistent_input(QLineEdit, "wordlist_output", placeholder="Output wordlist file (e.g., wordlist.txt)")
        self.minlen = self._create_persistent_input(QSpinBox, "wordlist_minlen", default_value=1)
        self.minlen.setRange(1, 50)
        self.lowercase = QComboBox()
        self.lowercase.addItems(["keep", "lowercase"])
        self.lowercase.setCurrentText(self._load_setting("wordlist_case", "keep"))
        self.lowercase.currentTextChanged.connect(lambda t: self._save_setting("wordlist_case", t))


        top = QHBoxLayout()
        help_btn = QPushButton("Help"); help_btn.clicked.connect(self._show_help)
        top.addStretch(1); top.addWidget(help_btn)
        layout.addLayout(top)

        io = QGroupBox("Wordlist extractor")
        f = QFormLayout()
        
        b1 = QPushButton("Browse…"); b1.clicked.connect(lambda: self._pick_folder(self.folder_edit, self.output_edit))
        hb1 = QHBoxLayout(); hb1.addWidget(self.folder_edit); hb1.addWidget(b1)

        b2 = QPushButton("Save as…"); b2.clicked.connect(lambda: self._pick_output(self.output_edit))
        hb2 = QHBoxLayout(); hb2.addWidget(self.output_edit); hb2.addWidget(b2)
        
        clear_btn = QPushButton("Clear Inputs");
        clear_btn.clicked.connect(lambda: self._clear_inputs([self.folder_edit, self.output_edit, self.minlen, self.lowercase]))


        f.addRow("Source folder:", hb1)
        f.addRow("Output file:", hb2)
        f.addRow("Min word length:", self.minlen)
        f.addRow("Case:", self.lowercase)
        f.addWidget(clear_btn)
        io.setLayout(f)
        layout.addWidget(io)

        self.run_btn = QPushButton("Extract unique words"); self.run_btn.clicked.connect(self.run_extract)
        layout.addWidget(self.run_btn)

        self.pbar = QProgressBar(); self.pbar.setMaximum(1); self.pbar.setValue(0)
        self.rps_lbl = QLabel("Progress"); hb = QHBoxLayout(); hb.addWidget(self.pbar, 1); hb.addWidget(self.rps_lbl)
        layout.addLayout(hb)

        self.log_box = QPlainTextEdit(); self.log_box.setReadOnly(True); layout.addWidget(self.log_box)

    def _show_help(self):
        self._help_popup("Wordlist Extractor Help",
"""Wordlist extractor tab
• Pick a folder; it scans all .txt files recursively
• Extracts words with a broad regex, removes duplicates, applies min length and optional lowercasing
• Saves a single .txt wordlist to the file you choose (default path inside the chosen folder)
• Runs in the background; shows progress and final unique count""")

    def _pick_folder(self, folder_le: QLineEdit, output_le: QLineEdit):
        d = self._pick_dir("Choose folder with .txt files")
        if d:
            folder_le.setText(d)
            default_out = os.path.join(d, "wordlist_extracted.txt")
            output_le.setText(default_out)

    def _pick_output(self, le: QLineEdit):
        f = self._save_file("Save wordlist as", le.text().strip() or "wordlist.txt", "Text (*.txt);;All Files (*)")
        if f: le.setText(f)

    def run_extract(self):
        folder = self.folder_edit.text().strip()
        outpath = self.output_edit.text().strip()
        if not os.path.isdir(folder):
            QMessageBox.warning(self, "Missing", "Pick a valid folder."); return
        if not outpath:
            QMessageBox.warning(self, "Missing", "Pick an output file path."); return

        def work():
            self.run_btn.setEnabled(False)
            try:
                files = glob.glob(os.path.join(folder, "**/*.txt"), recursive=True)
                if not files:
                    self.log("No .txt files found under the chosen folder."); return
                total = len(files); done = 0; t0 = time.time()
                words: Set[str] = set()
                word_pattern = re.compile(r"[A-Za-z0-9_]+")
                minlen = self.minlen.value()
                to_lower = (self.lowercase.currentText() == "lowercase")

                def process_one(p: str):
                    nonlocal done
                    try:
                        text = open(p, 'r', encoding='utf-8', errors='ignore').read()
                        for w in word_pattern.findall(text):
                            if to_lower: w = w.lower()
                            if len(w) >= minlen:
                                words.add(w)
                    except Exception as e:
                        self.log(f"[read] {p}: {e}")
                    finally:
                        done += 1
                        self.prog(done, total, done/max(0.001, time.time()-t0))

                with cf.ThreadPoolExecutor(max_workers=16) as ex:
                    list(ex.map(process_one, files))

                uniq = sorted(words)
                with open(outpath, 'w', encoding='utf-8') as f:
                    f.write("\n".join(uniq))
                self.log(f"✅ Extracted {len(uniq)} unique words → {outpath}")
                self.prog(1,1,0.0)
            except Exception as e:
                self.log(f"[WordlistExtractor] ERROR: {e}\n{traceback.format_exc()}")
            finally:
                self.run_btn.setEnabled(True)

        threading.Thread(target=work, daemon=True).start()

# ======================== Alias/Batch Gen Tab (Unchanged, added persistence) ========================

class AliasBatchTab(BaseTab):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        # Set up persistent fields
        self.count_spin = self._create_persistent_input(QSpinBox, "alias_count", default_value=20)
        self.count_spin.setRange(1, 10000)
        self.base_query_edit = self._create_persistent_input(QPlainTextEdit, "alias_base_query", 
            default_value='{"operationName":"VerifyEmailChangeOtp","variables":{"input":{"otpCode":"111111"}},"query":"mutation VerifyEmailChangeOtp($input: VerifyEmailChangeOtpInput!) {\\n  verifyEmailChangeOtp(input: $input) {\\n    success\\n    error\\n    __typename\\n  }\\n}\\n"}',
            placeholder='Paste base query JSON, e.g.\n{"operationName":"VerifyEmailChangeOtp", ...}'
        )

        top = QHBoxLayout()
        help_btn = QPushButton("Help"); help_btn.clicked.connect(self._show_help)
        top.addStretch(1); top.addWidget(help_btn)
        layout.addLayout(top)

        main_splitter = QGridLayout()
        
        # --- Left Side (Inputs) ---
        input_box = QGroupBox("Inputs")
        input_layout = QVBoxLayout()
        
        form_layout = QFormLayout()
        form_layout.addRow("Number to Generate:", self.count_spin)
        
        self.generate_btn = QPushButton("Generate")
        self.generate_btn.clicked.connect(self.run_generate)
        
        input_layout.addLayout(form_layout)
        input_layout.addWidget(QLabel("Base Query JSON:"))
        input_layout.addWidget(self.base_query_edit, 1) # Give stretch
        
        clear_btn = QPushButton("Clear Inputs");
        clear_btn.clicked.connect(lambda: self._clear_inputs([self.count_spin, self.base_query_edit]))
        
        input_layout.addWidget(self.generate_btn)
        input_layout.addWidget(clear_btn)
        input_box.setLayout(input_layout)
        main_splitter.addWidget(input_box, 0, 0)
        
        # --- Right Side (Outputs) ---
        output_tabs = QTabWidget()
        
        # Alias Tab
        alias_widget = QWidget()
        alias_layout = QVBoxLayout()
        self.alias_output = QPlainTextEdit()
        self.alias_output.setReadOnly(True)
        self.alias_copy_btn = QPushButton("Copy Alias Query")
        self.alias_copy_btn.clicked.connect(lambda: self._copy_to_clipboard(self.alias_output))
        alias_layout.addWidget(QLabel("Generated Alias Query (JSON):"))
        alias_layout.addWidget(self.alias_output)
        alias_layout.addWidget(self.alias_copy_btn)
        alias_widget.setLayout(alias_layout)
        output_tabs.addTab(alias_widget, "Alias Query")

        # Batch Tab
        batch_widget = QWidget()
        batch_layout = QVBoxLayout()
        self.batch_output = QPlainTextEdit()
        self.batch_output.setReadOnly(True)
        self.batch_copy_btn = QPushButton("Copy Batch JSON")
        self.batch_copy_btn.clicked.connect(lambda: self._copy_to_clipboard(self.batch_output))
        batch_layout.addWidget(QLabel("Generated Batch JSON:"))
        batch_layout.addWidget(self.batch_output)
        batch_layout.addWidget(self.batch_copy_btn)
        batch_widget.setLayout(batch_layout)
        output_tabs.addTab(batch_widget, "Batch JSON")

        main_splitter.addWidget(output_tabs, 0, 1)

        # Log box at the bottom
        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumHeight(100)
        
        layout.addLayout(main_splitter, 1)
        layout.addWidget(self.log_box)
        self.log("Ready to generate.")

    def _show_help(self):
        self._help_popup("Alias/Batch Generator Help",
"""Alias/Batch Generator tab
1. Paste a full GraphQL request JSON into the 'Base Query JSON' box.
   This JSON must include 'operationName', 'variables', and 'query'.
2. The tool will find the *first* key inside 'variables.input' (e.g., 'otpCode').
3. It will assume this key's value should be replaced with an incrementing number (e.g., "000001", "000002", ...).
4. Set the 'Number to Generate'.
5. Click 'Generate'.
6. The 'Alias Query' tab will show a single query JSON with many aliased operations.
7. The 'Batch JSON' tab will show a JSON array of individual query objects.
8. Use the 'Copy' buttons to copy the results.""")

    def run_generate(self):
        try:
            base_json_str = self.base_query_edit.toPlainText()
            base_data = json.loads(base_json_str)
            count = self.count_spin.value()

            query_str = base_data.get("query", "")
            variables = base_data.get("variables", {})
            input_vars = variables.get("input", {})

            if not query_str or not input_vars:
                self.log("Error: Base JSON must contain 'query' and 'variables.input'.")
                return

            # Find the operation call (e.g., 'verifyEmailChangeOtp')
            op_call_match = re.search(r'{\s*(\w+)\(input:\s*\$input\)', query_str.replace('\n', ' '))
            if not op_call_match:
                self.log("Error: Could not find operation call like 'opName(input: $input)' in query.")
                return
            op_call_name = op_call_match.group(1)

            # Find the return body (e.g., '{ success error __typename }')
            body_match = re.search(r'\(input:\s*\$input\)\s*({[\s\S]+})', query_str)
            if not body_match:
                self.log("Error: Could not extract return body from query.")
                return
            return_body = body_match.group(1).strip()
            
            # Simple body for batch
            simple_body = "{ success error __typename }"
            if "success" not in return_body:
                # If 'success' isn't in the body, try to find *any* field
                first_field_match = re.search(r'{\s*(\w+)', return_body)
                if first_field_match:
                    simple_body = f"{{ {first_field_match.group(1)} __typename }}"
                else:
                    simple_body = "{ __typename }" # Fallback
            
            # Find the variable key to increment (e.g., 'otpCode')
            if not input_vars:
                self.log("Error: 'variables.input' is empty.")
                return
            
            # Find the *first* string or number key to increment
            inc_key = None
            inc_val_type = "string"
            padding = 6 # Default padding
            
            for key, value in input_vars.items():
                if isinstance(value, str):
                    inc_key = key
                    inc_val_type = "string"
                    try:
                        # Try to detect padding from example
                        int(value)
                        padding = len(value)
                    except ValueError:
                        padding = 6 # Default
                    break
                elif isinstance(value, (int, float)):
                    inc_key = key
                    inc_val_type = "number"
                    break
            
            if not inc_key:
                self.log("Error: Could not find a string or number field in 'variables.input' to increment.")
                return

            self.log(f"Generating {count} operations...")
            self.log(f"Found operation: {op_call_name}")
            self.log(f"Found increment key: '{inc_key}' (type: {inc_val_type}, padding: {padding})")
            self.log(f"Found return body: {return_body}")

            # --- 1. Generate Alias Query ---
            alias_lines = []
            for i in range(1, count + 1):
                val_str = str(i).zfill(padding)
                if inc_val_type == "string":
                    val = json.dumps(val_str) # e.g., "000001"
                else:
                    val = val_str # e.g., 1
                
                alias_lines.append(f'  v{i}: {op_call_name}(input: {{ {inc_key}: {val} }}) {return_body}')
            
            alias_query_str = f"mutation VerifyMany {{\n{'\n'.join(alias_lines)}\n}}"
            alias_json = json.dumps({"query": alias_query_str}, indent=2)
            self.alias_output.setPlainText(alias_json)

            # --- 2. Generate Batch Query ---
            batch_list = []
            for i in range(1, count + 1):
                val_str = str(i).zfill(padding)
                if inc_val_type == "string":
                    val = json.dumps(val_str) # e.g., "000001"
                else:
                    val = val_str # e.g., 1
                
                batch_q_str = f"mutation {{ {op_call_name}(input: {{ {inc_key}: {val} }}) {simple_body} }}"
                batch_list.append({"query": batch_q_str})
            
            batch_json = json.dumps(batch_list, indent=2)
            self.batch_output.setPlainText(batch_json)

            self.log("Generation complete.")

        except Exception as e:
            self.log(f"Generation Failed: {e}\n{traceback.format_exc()}")
            QMessageBox.warning(self, "Error", f"Generation failed: {e}")

# ======================== Query Fixer Tab (Req 1 & updated) ========================

class FastFixerDialog(QDialog):
    """NEW Dialog for Request 1: Fast Fixer Pop-up."""
    def __init__(self, parent: 'QueryFixerTab'):
        super().__init__(parent)
        self.setWindowTitle("Quick Fixer Tool (No File Saving)")
        self.parent = parent
        self.resize(800, 600)
        self.log_signal = LogSignal()
        self.log_signal.text.connect(self.log)
        self.log_signal.output_ready.connect(self.set_output)
        
        v = QVBoxLayout(self)

        h = QHBoxLayout()
        self.input_type = QComboBox()
        self.input_type.addItems(["Query", "Mutation"])
        h.addWidget(QLabel("Operation Type:"))
        h.addWidget(self.input_type)
        h.addStretch(1)
        self.fix_btn = QPushButton("+ Fix List")
        self.fix_btn.clicked.connect(self.run_fast_fix)
        h.addWidget(self.fix_btn)
        v.addLayout(h)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        input_group = QGroupBox("Operation Names (One per line)")
        input_v = QVBoxLayout()
        self.input_list = QPlainTextEdit()
        self.input_list.setPlaceholderText("Enter operation names here (e.g., getUserName, createNewAccount)")
        input_v.addWidget(self.input_list)
        input_group.setLayout(input_v)
        splitter.addWidget(input_group)
        
        output_group = QGroupBox("Formatted Output (JSON)")
        output_v = QVBoxLayout()
        self.output_text = QPlainTextEdit()
        self.output_text.setReadOnly(True)
        self.copy_btn = QPushButton("Copy All")
        self.copy_btn.clicked.connect(self._copy_output)
        output_v.addWidget(self.output_text)
        output_v.addWidget(self.copy_btn)
        output_group.setLayout(output_v)
        splitter.addWidget(output_group)
        
        splitter.setSizes([400, 400])
        v.addWidget(splitter)
        
        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumHeight(80)
        v.addWidget(self.log_box)

    def log(self, msg: str):
        self.log_box.appendPlainText(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    
    def set_output(self, output: str):
        self.output_text.setPlainText(output)
        self.fix_btn.setEnabled(True)

    def _copy_output(self):
        try:
            QGuiApplication.clipboard().setText(self.output_text.toPlainText())
            self.log("Copied output to clipboard.")
        except Exception as e:
            self.log(f"Error copying: {e}")

    def run_fast_fix(self):
        url = self.parent.url_edit.text().strip()
        if not url:
            QMessageBox.warning(self, "Missing", "Enter GraphQL URL in the main tab."); return
            
        op_names_raw = self.input_list.toPlainText()
        op_names = [n.strip() for n in op_names_raw.splitlines() if n.strip()]
        op_type = self.input_type.currentText().lower()
        
        if not op_names:
            self.log("No operation names entered.")
            return

        # Use the parent's shared config/logic
        self.parent._GRAPHQL_ENDPOINT = url
        self.parent._HEADERS = self.parent._headers()
        
        self.fix_btn.setEnabled(False)
        self.log_box.clear()
        
        # Runnable for background thread
        def worker_task():
            self.log_signal.text.emit(f"Starting quick fix for {len(op_names)} {op_type.upper()} operations...")
            full_output = []
            
            for idx, op_name in enumerate(op_names):
                if self.parent._stop_event.is_set():
                    self.log_signal.text.emit("🛑 Quick Fix stopped by user.")
                    break
                    
                self.log_signal.text.emit(f"[{idx+1}/{len(op_names)}] Discovering: {op_name}")
                
                try:
                    actual_name, arguments, status, is_scalar = self.parent._discover_op_signature(op_name, op_type, verbose=False)
                    
                    if status.startswith("VALID") or (status == "ERROR" and arguments):
                        formatted_json = self.parent._format_op_as_json(actual_name, arguments, op_type, is_scalar)
                        full_output.append(formatted_json)
                        self.log_signal.text.emit(f"  ✅ Fixed: {actual_name} ({len(arguments)} args) -> Status: {status}")
                    else:
                        full_output.append(f"# ERROR: Could not fix {op_name} (Status: {status})")
                        self.log_signal.text.emit(f"  ❌ Failed: {op_name} -> Status: {status}")
                        
                except Exception as e:
                    self.log_signal.text.emit(f"  ❌ FATAL ERROR for {op_name}: {e}")

            final_output = '\n\n'.join(full_output) # Use double newline as separator
            self.log_signal.text.emit("\nQuick fix complete. Output ready.")
            self.log_signal.output_ready.emit(final_output) # Signal completion and set output

        # Start the worker thread
        threading.Thread(target=worker_task, daemon=True).start()


class QueryFixerTab(BaseTab):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        # Set up persistent fields
        self.url_edit = self._create_persistent_input(QLineEdit, "fixer_url", placeholder="https://example.com/graphql")
        self.jwt_edit = self._create_persistent_input(QLineEdit, "fixer_jwt", placeholder="JWT")
        self.cookie_edit = self._create_persistent_input(QLineEdit, "fixer_cookie", placeholder="cookie1=a; cookie2=b")
        self.extra_hdrs = self._create_persistent_input(QPlainTextEdit, "fixer_extra_hdrs", placeholder="X-Forwarded-For: 127.0.0.1")
        self.mutation_folder = self._create_persistent_input(QLineEdit, "fixer_mut_folder", placeholder="Folder for Mutation .txt files")
        self.query_folder = self._create_persistent_input(QLineEdit, "fixer_qry_folder", placeholder="Folder for Query .txt files (Optional)")
        self.output_base_folder = self._create_persistent_input(QLineEdit, "fixer_out_base", placeholder="Base folder to save results (creates Mutation_fixed/ and Query_fixed/)")
        self.threads_spin = self._create_persistent_input(QSpinBox, "fixer_threads", default_value=8)
        self.threads_spin.setRange(1, 32)


        top = QHBoxLayout()
        help_btn = QPushButton("Help"); help_btn.clicked.connect(self._show_help)
        # New button for the quick fixer dialog (Request 1)
        fast_fix_btn = QPushButton("Quick Fix List +"); fast_fix_btn.clicked.connect(self.open_fast_fixer)
        top.addStretch(1); top.addWidget(help_btn); top.addWidget(fast_fix_btn)
        layout.addLayout(top)

        auth_box = QGroupBox("Endpoint & Auth"); af = QFormLayout()
        af.addRow("GraphQL URL:", self.url_edit); af.addRow("JWT:", self.jwt_edit)
        af.addRow("Cookies:", self.cookie_edit); af.addRow("Extra headers:", self.extra_hdrs)
        
        clear_auth_btn = QPushButton("Clear Auth/Headers"); 
        clear_auth_btn.clicked.connect(lambda: self._clear_inputs([self.url_edit, self.jwt_edit, self.cookie_edit, self.extra_hdrs]))
        af.addWidget(clear_auth_btn)
        
        auth_box.setLayout(af); layout.addWidget(auth_box)

        io_box = QGroupBox("Input / Output / Threads"); iof = QFormLayout()
        
        b1 = QPushButton("Browse Muts…"); b1.clicked.connect(lambda: self._pick_input(self.mutation_folder))
        hb1 = QHBoxLayout(); hb1.addWidget(self.mutation_folder); hb1.addWidget(b1)
        
        b2 = QPushButton("Browse Qrys…"); b2.clicked.connect(lambda: self._pick_input(self.query_folder))
        hb2 = QHBoxLayout(); hb2.addWidget(self.query_folder); hb2.addWidget(b2)
        
        b3 = QPushButton("Browse Output…"); b3.clicked.connect(self._pick_output_base)
        hb3 = QHBoxLayout(); hb3.addWidget(self.output_base_folder); hb3.addWidget(b3)
        
        hb_threads = QHBoxLayout()
        hb_threads.addWidget(QLabel("Worker Threads:"))
        hb_threads.addWidget(self.threads_spin)
        hb_threads.addStretch(1)

        clear_io_btn = QPushButton("Clear Input/Output");
        clear_io_btn.clicked.connect(lambda: self._clear_inputs([self.mutation_folder, self.query_folder, self.output_base_folder, self.threads_spin]))


        iof.addRow("Mutation Input:", hb1)
        iof.addRow("Query Input:", hb2)
        iof.addRow("Output Base Dir:", hb3)
        iof.addRow(hb_threads)
        iof.addWidget(clear_io_btn)
        io_box.setLayout(iof); layout.addWidget(io_box)

        # Run/Stop buttons
        hb_run = QHBoxLayout()
        self.run_btn = QPushButton("Run Query Fixer (Batch Mode)")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.run_btn.clicked.connect(self.run_fixer)
        self.stop_btn.clicked.connect(self.stop_fixer)
        hb_run.addWidget(self.run_btn)
        hb_run.addWidget(self.stop_btn)
        layout.addLayout(hb_run)
        
        self.pbar = QProgressBar(); self.pbar.setMaximum(1); self.pbar.setValue(0)
        self.rps_lbl = QLabel("RPS: 0.0") 
        hb_prog = QHBoxLayout(); hb_prog.addWidget(self.pbar, 1); hb_prog.addWidget(self.rps_lbl)
        layout.addLayout(hb_prog)

        self.log_box = QPlainTextEdit(); self.log_box.setReadOnly(True)
        layout.addWidget(self.log_box)

        # Variables to hold config for the thread
        self._GRAPHQL_ENDPOINT = ""
        self._MUTATION_FOLDER = ""
        self._QUERY_FOLDER = ""
        self._OUTPUT_BASE_FOLDER = ""
        self._HEADERS = {}
        
    def open_fast_fixer(self):
        """Opens the new FastFixerDialog pop-up (Request 1)."""
        dlg = FastFixerDialog(self)
        dlg.exec()

    def _show_help(self):
        self._help_popup("Query Fixer Help",
"""Query Fixer tab
• This tool discovers the correct arguments for queries and mutations by making live requests.
• The **Quick Fix List** button opens a pop-up for fast, unsaved, bulk fixing of operation names.
• **Batch Fix:** Choose separate folders for your .txt files (from Monitor/Introspection) and an output base dir.
• Results are saved to Mutation_fixed/ and Query_fixed/ subfolders.
• The batch fixer runs using multiple threads for speed.""")

    def _pick_input(self, target_line_edit: QLineEdit):
        d = self._pick_dir("Choose Input Folder")
        if d: target_line_edit.setText(d)

    def _pick_output_base(self):
        d = self._pick_dir("Choose Output Base Folder")
        if d: self.output_base_folder.setText(d)
        
    def _headers(self):
        return build_headers(self.jwt_edit.text(), self.cookie_edit.text(), self.extra_hdrs.toPlainText())

    def _extract_mutation_name(self, file_path):
        """Extract the operation name from the GQL file (works for both MUTATION and QUERY)."""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        mutation_name_match = re.search(r'(?:MUTATION|QUERY):\s*(\w+)', content)
        if mutation_name_match:
            return mutation_name_match.group(1)
        return None

    def _test_mutation(self, mutation, variables=None):
        """Send GraphQL operation to endpoint and return response."""
        if self._stop_event.is_set(): raise InterruptedError()
        payload = {"query": mutation, "variables": variables or {}}
        try:
            response = requests.post(self._GRAPHQL_ENDPOINT, json=payload, headers=self._HEADERS, timeout=10)
            return response.json()
        except Exception as e:
            return {"errors": [{"message": f"Request failed: {str(e)}"}]}

    def _extract_required_argument(self, error_message):
        """Extract required argument from error message."""
        pattern = r'argument "(\w+)" of type "([^"]+)" is required'
        match = re.search(pattern, error_message)
        if match:
            return {'name': match.group(1), 'type': match.group(2), 'required': '!' in match.group(2)}
        return None

    def _extract_type_mismatch(self, error_message):
        """Extract type mismatch to fix the argument type."""
        pattern = r'Variable "\$(\w+)" of type "([^"]+)" used in position expecting type "([^"]+)"'
        match = re.search(pattern, error_message)
        if match:
            return {'name': match.group(1), 'type': match.group(3), 'required': '!' in match.group(3)}
        return None

    def _extract_nested_field_requirement(self, error_message):
        """Extract nested field requirements from complex input types."""
        pattern = r'Field "(\w+)" of required type "([^"]+)" was not provided'
        match = re.search(pattern, error_message)
        if match:
            return {'name': match.group(1), 'type': match.group(2)}
        return None

    def _get_placeholder_value(self, arg_type, nested_fields=None):
        """Generate placeholder values for different argument types."""
        base_type = arg_type.replace('!', '').strip()
        if base_type.startswith('['): return []
        elif 'String' in base_type or 'ID' in base_type: return "test_value"
        elif 'Int' in base_type: return 1
        elif 'Float' in base_type: return 1.0
        elif 'Boolean' in base_type: return True
        else:
            if nested_fields:
                obj = {}
                for field in nested_fields:
                    obj[field['name']] = self._get_placeholder_value(field['type'])
                return obj
            return {}

    def _build_simple_op(self, op_name, op_type, is_scalar=False):
        """Build a simple op (query or mutation) with no arguments."""
        root_op = op_type.lower()
        if is_scalar:
            return f"{root_op} {{ {op_name} }}"
        else:
            return f"{root_op} {{ {op_name} {{ __typename }} }}"

    def _build_op_with_args(self, op_name, arguments, op_type, is_scalar=False):
        """Build an operation (query or mutation) with the discovered arguments."""
        root_op = op_type.lower()
        op_cap = op_name[0].upper() + op_name[1:]
        arg_definitions = ", ".join([f"${arg['name']}: {arg['type']}" for arg in arguments])
        arg_usage = ", ".join([f"{arg['name']}: ${arg['name']}" for arg in arguments])
        if is_scalar:
            return f"{root_op} {op_cap}({arg_definitions}) {{ {op_name}({arg_usage}) }}"
        else:
            return f"{root_op} {op_cap}({arg_definitions}) {{ {op_name}({arg_usage}) {{ __typename }} }}"

    def _is_valid_response(self, response):
        """Check if response indicates a valid operation."""
        if not isinstance(response, dict):
            if isinstance(response, list) and len(response) == 1 and isinstance(response[0], dict):
                response = response[0]
            else:
                return False, None

        if "data" in response and response["data"] is not None:
            if isinstance(response["data"], dict) and response["data"].get(list(response["data"].keys())[0]) is not None:
                return True, "VALID_DATA"
        
        if "errors" in response:
            error_codes = [err.get("extensions", {}).get("code", "") for err in response["errors"]]
            error_messages = [err.get("message", "") for err in response["errors"]]
            
            if any("UNAUTHENTICATED" in code for code in error_codes): return True, "VALID_AUTH_REQUIRED"
            if any(word in msg.lower() for msg in error_messages for word in ["forbidden", "unauthorized", "access denied"]): return True, "VALID_FORBIDDEN"
            
            if "data" in response and response["data"] is None:
                 if not any("Cannot query field" in msg for msg in error_messages) and \
                    not any("must not have a selection" in msg for msg in error_messages) and \
                    not any("argument" in msg for msg in error_messages):
                     return True, "VALID_NULL_DATA"
        return False, None

    def _format_op_as_json(self, op_name, arguments, op_type, is_scalar=False):
        """Format the operation as a JSON payload with variables."""
        root_op = op_type.lower()
        op_cap = op_name[0].upper() + op_name[1:]
        
        if arguments:
            arg_definitions = ", ".join([f"${arg['name']}: {arg['type']}" for arg in arguments])
            arg_usage = ", ".join([f"{arg['name']}: ${arg['name']}" for arg in arguments])
            
            if is_scalar:
                op_str = f"{root_op} {op_cap}({arg_definitions}) {{\n    {op_name}({arg_usage})\n}}"
            else:
                op_str = f"{root_op} {op_cap}({arg_definitions}) {{\n    {op_name}({arg_usage}) {{\n        __typename\n    }}\n}}"
            
            variables = {}
            for arg in arguments:
                if 'nested_fields' in arg and arg['nested_fields']:
                    nested_obj = {}
                    for field in arg['nested_fields']:
                        nested_obj[field['name']] = self._get_placeholder_value(field['type'])
                    variables[arg['name']] = nested_obj
                else:
                    variables[arg['name']] = self._get_placeholder_value(arg['type'])
        else:
            if is_scalar:
                op_str = f"{root_op} {op_cap} {{\n    {op_name}\n}}"
            else:
                op_str = f"{root_op} {op_cap} {{\n    {op_name} {{ __typename }}\n}}"
            variables = {}
        
        payload = {"query": op_str, "variables": variables}
        return json.dumps(payload, separators=(',', ':'))

    def _discover_op_signature(self, op_name, op_type, verbose=False):
        """Discover the full signature of an operation by testing it."""
        max_iterations = 20
        
        op_names_to_try = [op_name]
        if op_name[0].isupper():
            lowercase_first = op_name[0].lower() + op_name[1:]
            op_names_to_try.append(lowercase_first)
        
        for attempt_name in op_names_to_try:
            if verbose: self.log(f"    Trying: {attempt_name}")
            arguments = []; nested_fields = {}; is_scalar = False; iteration = 0
            
            while iteration < max_iterations:
                if self._stop_event.is_set(): raise InterruptedError()
                iteration += 1
                
                if arguments:
                    mutation = self._build_op_with_args(attempt_name, arguments, op_type, is_scalar) 
                    variables = {}
                    for arg in arguments:
                        if arg['name'] in nested_fields and nested_fields[arg['name']]:
                            variables[arg['name']] = self._get_placeholder_value(arg['type'], nested_fields[arg['name']])
                        else:
                            variables[arg['name']] = self._get_placeholder_value(arg['type'])
                else:
                    mutation = self._build_simple_op(attempt_name, op_type, is_scalar)
                    variables = {}
                
                response = self._test_mutation(mutation, variables)
                if verbose and "errors" in response:
                    errors = [err.get("message", "") for err in response["errors"]]
                    for err in errors[:3]: self.log(f"    Error: {err[:150]}")
                
                valid, status = self._is_valid_response(response)
                if valid:
                    for arg in arguments:
                        if arg['name'] in nested_fields and nested_fields[arg['name']]: arg['nested_fields'] = nested_fields[arg['name']]
                    return attempt_name, arguments, status, is_scalar
                
                if "errors" not in response: break
                
                error_messages = [err.get("message", "") for err in response["errors"]]
                
                if any("Cannot query field" in msg for msg in error_messages): break
                if any("must not have a selection" in msg for msg in error_messages):
                    is_scalar = True
                    if verbose: self.log(f"    Detected scalar field"); continue
                
                found_new_arg = False
                
                for msg in error_messages:
                    new_arg = self._extract_required_argument(msg)
                    if new_arg and not any(arg['name'] == new_arg['name'] for arg in arguments):
                        arguments.append(new_arg); found_new_arg = True
                        if verbose: self.log(f"    Added argument: {new_arg['name']} ({new_arg['type']})"); break
                    
                    type_fix = self._extract_type_mismatch(msg)
                    if type_fix:
                        for arg in arguments:
                            if arg['name'] == type_fix['name']:
                                arg['type'] = type_fix['type']; arg['required'] = type_fix['required']
                                found_new_arg = True
                                if verbose: self.log(f"    Fixed type for {arg['name']}: {type_fix['type']}"); break
                        if found_new_arg: break
                
                if not found_new_arg:
                    for msg in error_messages:
                        nested_req = self._extract_nested_field_requirement(msg)
                        if nested_req:
                            for arg in reversed(arguments):
                                base_type = arg['type'].replace('!', '').strip()
                                if base_type not in ['String', 'Int', 'Float', 'Boolean', 'ID'] and not base_type.startswith('['):
                                    if arg['name'] not in nested_fields: nested_fields[arg['name']] = []
                                    if not any(f['name'] == nested_req['name'] for f in nested_fields[arg['name']]):
                                        nested_fields[arg['name']].append(nested_req); found_new_arg = True
                                        if verbose: self.log(f"    Added nested field to {arg['name']}: {nested_req['name']} ({nested_req['type']})"); break
                            if found_new_arg: break
                
                if not found_new_arg:
                    if verbose: self.log(f"    No new arguments or fields found")
                    for arg in arguments:
                        if arg['name'] in nested_fields and nested_fields[arg['name']]: arg['nested_fields'] = nested_fields[arg['name']]
                    return attempt_name, arguments, "ERROR", is_scalar
            
        return op_name, arguments, "INVALID_FIELD", False

    def _save_result(self, file_name, op_name, arguments, status, output_path, op_type, is_scalar=False):
        """Save the result in the new format."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if status.startswith("VALID"): description = f"Valid {op_type} ({status}) - Auth/permissions may be required."
        elif status == "INVALID_FIELD": description = f"{op_type.capitalize()} field does not exist in schema."
        else: description = f"Error during discovery ({status}). See logs."
        
        content = f"""================================================================================
{op_type.upper()}: {op_name}
================================================================================
Generated at: {timestamp}
Description: {description}
ARGUMENTS:
----------------------------------------
"""
        
        if arguments:
            for arg in arguments:
                req_status = "required" if arg.get('required', False) else "optional"
                content += f"• {arg['name']} ({arg['type']}) - {req_status}\n"
                if 'nested_fields' in arg and arg['nested_fields']:
                    for field in arg['nested_fields']: content += f"  - {field['name']} ({field['type']})\n"
        else: content += "No arguments required.\n"
        
        content += "\nRETURN TYPE:\n----------------------------------------\n"
        content += "See return fields\n"
        
        if status.startswith("VALID") or (status == "ERROR" and arguments):
            content += f"\nFORMATTED {op_type.upper()}:\n----------------------------------------\n"
            content += self._format_op_as_json(op_name, arguments, op_type, is_scalar) + "\n"
        
        output_file = output_path / file_name
        with open(output_file, 'w', encoding='utf-8') as f: f.write(content)

    # --- Worker function for concurrent processing ---
    def _process_one_file(self, job: Tuple[Path, str, Path]):
        file_path, op_type, output_folder = job
        op_name = self._extract_mutation_name(file_path)
        
        if self._stop_event.is_set(): raise InterruptedError()

        if not op_name: 
            self.log(f"  ❌ Failed: {file_path.name} -> Could not extract op name.")
            return op_type, "error"
        
        try:
            actual_name, arguments, status, is_scalar = self._discover_op_signature(op_name, op_type, verbose=False)
            
            if self._stop_event.is_set(): raise InterruptedError()
            
            os.makedirs(output_folder, exist_ok=True)
            self._save_result(file_path.name, actual_name, arguments, status, output_folder, op_type, is_scalar)
            
            if status.startswith("VALID"): 
                self.log(f"  ✅ Fixed: {file_path.name} ({actual_name}) -> Status: {status}")
                return op_type, "valid"
            elif status == "INVALID_FIELD": 
                self.log(f"  ❌ Invalid: {file_path.name} -> Status: {status}")
                return op_type, "invalid"
            else: 
                self.log(f"  ⚠️  Error: {file_path.name} -> Status: {status}")
                return op_type, "error"
                
        except InterruptedError:
            raise
        except Exception as e:
            self.log(f"  ❌ Exception: {file_path.name} -> Error: {e}")
            return op_type, "error"

    def _run_fixer_logic(self):
        """Batch fixer logic using ThreadPoolExecutor."""
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._stop_event.clear()
        self.log_box.clear()

        try:
            output_base_path = Path(self._OUTPUT_BASE_FOLDER)
            os.makedirs(output_base_path, exist_ok=True)
            files_to_process = []
            
            # File collection
            if self._MUTATION_FOLDER and Path(self._MUTATION_FOLDER).exists():
                mutation_files = list(Path(self._MUTATION_FOLDER).glob("*.txt"))
                mutation_out_path = output_base_path / "Mutation_fixed"
                files_to_process.extend([(f, "mutation", mutation_out_path) for f in mutation_files])
            
            if self._QUERY_FOLDER and Path(self._QUERY_FOLDER).exists():
                query_files = list(Path(self._QUERY_FOLDER).glob("*.txt"))
                query_out_path = output_base_path / "Query_fixed"
                files_to_process.extend([(f, "query", query_out_path) for f in query_files])
                
            if not files_to_process:
                self.log(f"No .txt files found in provided input folders."); return
            
            total_files = len(files_to_process)
            threads = self.threads_spin.value()
            self.log(f"Starting Query Fixer (Batch Mode)...")
            self.log(f"Found {total_files} total operations to test using {threads} threads.")
            self.log("-" * 40)
            
            results = {'mutation_valid': 0, 'mutation_invalid': 0, 'mutation_error': 0,
                       'query_valid': 0, 'query_invalid': 0, 'query_error': 0}
            
            done_count = 0
            
            with cf.ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(self._process_one_file, job): job for job in files_to_process}
                
                for future in cf.as_completed(futures):
                    if self._stop_event.is_set():
                        self.log("\n🛑 Stopping remaining tasks...")
                        # Cancel remaining futures
                        for f in futures: 
                            if not f.done(): f.cancel()
                        break
                        
                    try:
                        op_type, status = future.result()
                        results[f'{op_type}_{status}'] += 1
                    except InterruptedError:
                        break
                    except Exception as e:
                        self.log(f"  ⚠️  Future Error: {e}")
                        
                    done_count += 1
                    # Update progress bar on main thread
                    self.prog(done_count, total_files, 0.0)
            
            self.log("\n" + "=" * 80)
            self.log("Batch Fixer Finished.")
            
            total_mutations = sum(results[f'mutation_{k}'] for k in ['valid', 'invalid', 'error'])
            total_queries = sum(results[f'query_{k}'] for k in ['valid', 'invalid', 'error'])

            if total_mutations > 0:
                self.log(f"\n🔧 Mutations Processed ({total_mutations}):")
                self.log(f"  ✅ Valid Operations: {results['mutation_valid']}")
                self.log(f"  ❌ Invalid Field Names: {results['mutation_invalid']}")
                self.log(f"  ⚠️  Errors/Unresolved: {results['mutation_error']}")
                
            if total_queries > 0:
                self.log(f"\n🔍 Queries Processed ({total_queries}):")
                self.log(f"  ✅ Valid Operations: {results['query_valid']}")
                self.log(f"  ❌ Invalid Field Names: {results['query_invalid']}")
                self.log(f"  ⚠️  Errors/Unresolved: {results['query_error']}")
                
            self.log("\n" + "=" * 80)
            self.prog(total_files, total_files, 0.0)

        except Exception as e:
            self.log(f"FATAL ERROR: {e}\n{traceback.format_exc()}")
        finally:
            self.run_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)

    def run_fixer(self):
        self._GRAPHQL_ENDPOINT = self.url_edit.text().strip()
        self._MUTATION_FOLDER = self.mutation_folder.text().strip()
        self._QUERY_FOLDER = self.query_folder.text().strip()
        self._OUTPUT_BASE_FOLDER = self.output_base_folder.text().strip()
        
        if not self._GRAPHQL_ENDPOINT or not self._OUTPUT_BASE_FOLDER:
            QMessageBox.warning(self, "Missing Info", "Please provide URL and Output Base folders.")
            return

        if not self._MUTATION_FOLDER and not self._QUERY_FOLDER:
            QMessageBox.warning(self, "Missing Info", "Please provide at least one input folder (Mutation or Query).")
            return

        self._HEADERS = self._headers()
        self.log_box.clear()
        
        # Use a single dedicated thread for the executor to manage sub-threads
        threading.Thread(target=self._run_fixer_logic, daemon=True).start()

    def stop_fixer(self):
        self._stop_event.set()
        self.log("🛑 Stop signal sent. Waiting for active operations to complete...")


# ======================== Schema Search Tab (NEW for Req 2, Fixed for Req 5) ========================

class SchemaSearchTab(BaseTab):
    """NEW Tab (Request 2): Searches Introspection output files for specific field paths. Fixed for Req 5."""
    
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        # Set up persistent fields
        self.search_terms = self._create_persistent_input(QLineEdit, "search_terms", placeholder="Field names to search (comma-separated, e.g., userId, paymentAddressLine1)")
        self.input_folder = self._create_persistent_input(QLineEdit, "search_input_folder", placeholder="Base folder containing Query/ and Mutation/ folders")
        self.output_base = self._create_persistent_input(QLineEdit, "search_output_base", placeholder="Output base dir (e.g., Reports)")
        self.threads_spin = self._create_persistent_input(QSpinBox, "search_threads", default_value=8)
        self.threads_spin.setRange(1, 32)
        
        self.search_query = QComboBox(); 
        self.search_query.addItems(["Query Only", "Mutation Only", "Query and Mutation"])
        self.search_query.setCurrentText(self._load_setting("search_scope", "Query and Mutation"))
        self.search_query.currentTextChanged.connect(lambda t: self._save_setting("search_scope", t))


        top = QHBoxLayout()
        help_btn = QPushButton("Help"); help_btn.clicked.connect(self._show_help)
        top.addStretch(1); top.addWidget(help_btn)
        layout.addLayout(top)

        input_box = QGroupBox("Search Configuration")
        f = QFormLayout()
        
        b1 = QPushButton("Browse Input…"); b1.clicked.connect(lambda: self._pick_input(self.input_folder))
        hb1 = QHBoxLayout(); hb1.addWidget(self.input_folder); hb1.addWidget(b1)

        b2 = QPushButton("Browse Output…"); b2.clicked.connect(lambda: self._pick_out(self.output_base))
        hb2 = QHBoxLayout(); hb2.addWidget(self.output_base); hb2.addWidget(b2)

        hb_threads = QHBoxLayout()
        hb_threads.addWidget(QLabel("Worker Threads:"))
        hb_threads.addWidget(self.threads_spin)
        hb_threads.addStretch(1)
        
        clear_btn = QPushButton("Clear Inputs");
        clear_btn.clicked.connect(lambda: self._clear_inputs([self.search_terms, self.input_folder, self.output_base, self.threads_spin, self.search_query]))
        

        f.addRow("Search Fields:", self.search_terms)
        f.addRow("Introspection Input Dir:", hb1)
        f.addRow("Report Output Dir:", hb2)
        f.addRow("Search Scope:", self.search_query)
        f.addRow(hb_threads)
        f.addWidget(clear_btn)

        input_box.setLayout(f); layout.addWidget(input_box)

        # Run/Stop buttons
        hb_run = QHBoxLayout()
        self.run_btn = QPushButton("Run Schema Search & Report Generation")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.run_btn.clicked.connect(self.run_search)
        self.stop_btn.clicked.connect(self.stop_search)
        hb_run.addWidget(self.run_btn)
        hb_run.addWidget(self.stop_btn)
        layout.addLayout(hb_run)
        
        self.pbar = QProgressBar(); self.pbar.setMaximum(1); self.pbar.setValue(0)
        hb_prog = QHBoxLayout(); hb_prog.addWidget(self.pbar, 1); layout.addLayout(hb_prog)

        self.log_box = QPlainTextEdit(); self.log_box.setReadOnly(True)
        layout.addWidget(self.log_box)

    def _show_help(self):
        self._help_popup("Schema Search & Report Generator Help",
"""Schema Search tab
• Scans all .txt files generated by the Introspection tab (full details).
• Searches for the field names you specify, traversing nested object paths.
• **Multiple Search Terms:** A separate parent folder is created for each term.
• **Search Scope:** Now correctly supports searching Query, Mutation, or Both folders within the Input Dir.
• **Output Structure:** `{SearchTerm}_Reports/Query/OperationName.txt`""")

    def _pick_input(self, le: QLineEdit):
        d = self._pick_dir("Choose Introspection Output Folder")
        if d: le.setText(d)
        
    def _pick_out(self, le: QLineEdit):
        d = self._pick_dir("Choose Report Output Folder")
        if d: le.setText(d)

    def _find_paths_in_file(self, file_path: Path, search_term: str):
        """Scans a single file to find all paths to the search_term, preserving hierarchy."""
        if self._stop_event.is_set(): raise InterruptedError()
        paths_found = []
        path_components = [] 
        FIELDS_TO_IGNORE = ['id', 'uuid', '__typename'] 
        in_fields_block = False

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if self._stop_event.is_set(): raise InterruptedError()
                    
                    if "RETURN TYPE:" in line:
                        in_fields_block = False
                        continue
                    if "Fields:" in line:
                        in_fields_block = True
                        continue
                    if not in_fields_block or "ARGUMENTS:" in line or "GRAPHQL EXAMPLE:" in line:
                        continue

                    stripped_line = line.strip()
                    if not stripped_line or ':' not in stripped_line:
                        continue
                        
                    field_name_match = re.search(r'(?:•\s*|└─\s*)(\w+):', stripped_line)
                    if not field_name_match: continue
                        
                    field_name = field_name_match.group(1)
                    
                    # Determine depth: 0 for '•', >0 for '└─'
                    depth = -1 
                    if '•' in stripped_line:
                        depth = 0
                    elif '└─' in stripped_line:
                        indent_str = line.split('└─')[0]
                        depth = len(indent_str) // 4 

                    if depth == -1: continue 

                    # Prune path components for current depth
                    while path_components and path_components[-1][0] >= depth:
                        path_components.pop()
                    
                    path_components.append((depth, field_name))

                    if field_name == search_term:
                        final_path = [name for d, name in path_components if name not in FIELDS_TO_IGNORE]
                        path_str = ' -> '.join(final_path)
                        
                        if path_str and path_str not in paths_found:
                            paths_found.append(path_str)

        except InterruptedError:
            raise
        except Exception:
            # We don't log exceptions from file parsing to the main log to prevent spam
            pass 

        return paths_found

    def _create_report(self, original_file_path, output_dir_path, search_term, paths):
        """Creates the report file in the specified output structure."""
        if self._stop_event.is_set(): return
        
        output_file_path = output_dir_path / original_file_path.name
        
        # 1. Read the original file to extract the header (up to RETURN TYPE)
        header_lines = []
        try:
            with open(original_file_path, 'r', encoding='utf-8') as original_f:
                for line in original_f:
                    header_lines.append(line)
                    if "RETURN TYPE:" in line:
                        break 
            header_content = "".join(header_lines)

            # 2. Format the paths to be inserted
            paths_header = f"\n✨ PATH REPORT FOR FIELD: {search_term} ✨\n" + ("="*45) + "\n"
            paths_body = "\n".join([f"• {path}" for path in paths])
            paths_to_insert = paths_header + paths_body + "\n"

            # 3. Combine and write
            final_content = header_content + paths_to_insert

            with open(output_file_path, 'w', encoding='utf-8') as f:
                f.write(final_content)
        except Exception as e:
             self.log(f"  ❌ Error creating report for {original_file_path.name}: {e}")

    # --- Worker for thread pool ---
    def _search_one_file_for_all_terms(self, file_job: Tuple[Path, str, str]):
        file_path, op_type, output_base_dir = file_job
        search_terms = [t.strip() for t in self.search_terms.text().split(',') if t.strip()]
        found_in_terms = set()
        
        try:
            if self._stop_event.is_set(): raise InterruptedError()
            
            for search_term in search_terms:
                paths = self._find_paths_in_file(file_path, search_term)
                
                if paths:
                    term_report_base = Path(output_base_dir) / f"{search_term}_Reports"
                    op_type_out_dir = term_report_base / op_type
                    op_type_out_dir.mkdir(parents=True, exist_ok=True)
                    self._create_report(file_path, op_type_out_dir, search_term, paths)
                    found_in_terms.add(search_term)
            
        except InterruptedError:
            pass # Graceful exit
        except Exception:
            # Let the final results aggregation handle the count
            pass

        return file_path.name, op_type, found_in_terms
        
    def run_search(self):
        search_terms_raw = self.search_terms.text().strip()
        input_dir = self.input_folder.text().strip()
        output_base_dir = self.output_base.text().strip()
        scope = self.search_query.currentText()
        threads = self.threads_spin.value()
        
        if not search_terms_raw or not os.path.isdir(input_dir) or not output_base_dir:
            QMessageBox.warning(self, "Missing Info", "Please provide search fields, a valid input folder, and an output folder."); return

        search_terms = [t.strip() for t in search_terms_raw.split(',') if t.strip()]
        if not search_terms:
            QMessageBox.warning(self, "Missing Info", "Please enter at least one valid search field."); return

        def work():
            self.run_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self._stop_event.clear()
            self.log_box.clear()
            self.log("🚀 Starting Schema Search & Report Generation…")
            
            Path(output_base_dir).mkdir(exist_ok=True)
            
            all_files = []
            
            # --- Collect Files based on Scope (Fix 5) ---
            if scope in ("Query Only", "Query and Mutation"):
                q_dir = Path(input_dir) / "Query"
                if q_dir.exists():
                    all_files.extend([(f, "Query", output_base_dir) for f in q_dir.glob("*.txt")])
            
            if scope in ("Mutation Only", "Query and Mutation"):
                m_dir = Path(input_dir) / "Mutation"
                if m_dir.exists():
                    all_files.extend([(f, "Mutation", output_base_dir) for f in m_dir.glob("*.txt")])

            if not all_files:
                self.log("No relevant files found to search. Check your input directory structure (expecting Query/ and/or Mutation/ subfolders).");
                self.run_btn.setEnabled(True); self.stop_btn.setEnabled(False); return

            total_files = len(all_files)
            self.log(f"Found {total_files} files to scan in scope '{scope}'. Using {threads} threads.")
            
            # --- Concurrent Search ---
            all_found_terms = {term: 0 for term in search_terms}
            
            with cf.ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(self._search_one_file_for_all_terms, file_job): file_job for file_job in all_files}
                
                done_count = 0
                for future in cf.as_completed(futures):
                    if self._stop_event.is_set():
                        # Cancel remaining futures
                        for f in futures: 
                            if not f.done(): f.cancel()
                        break
                        
                    try:
                        _, _, found_in_terms = future.result()
                        for term in found_in_terms:
                            all_found_terms[term] += 1
                            
                    except Exception:
                        pass # Ignore exceptions from canceled/failed futures
                        
                    done_count += 1
                    self.prog(done_count, total_files, 0.0)

            # --- Final Summary ---
            self.log("\n" + "="*60)
            if self._stop_event.is_set():
                self.log("🛑 Schema Search Manually Stopped.")
            else:
                self.log("🎉 Schema Search Complete!")
                
            self.log("\n📊 Summary of Fields Found:")
            for term, count in all_found_terms.items():
                self.log(f"• {term}: Found in {count} operation files.")
            self.log("="*60)
            self.prog(total_files, total_files, 0.0)
            
            self.run_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)

        threading.Thread(target=work, daemon=True).start()
        
    def stop_search(self):
        self._stop_event.set()
        self.log("🛑 Stop signal sent. Waiting for active file searches to complete...")
        
# ======================== GraphQL Suite (Final Container) ========================

class GraphQLSuite(QWidget):
    def __init__(self, go_back_callback):
        super().__init__()
        v = QVBoxLayout(self)

        # Top bar with Back + title (Request 5: Center title)
        top = QHBoxLayout()
        back = QPushButton("← Back"); back.clicked.connect(go_back_callback)
        title = QLabel("GraphQL"); 
        title.setStyleSheet("font-size:20px; font-weight:600;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter) # Center alignment
        top.addWidget(back)
        top.addStretch(1)
        top.addWidget(title)
        top.addStretch(1)
        v.addLayout(top)

        tabs = QTabWidget()
        tabs.addTab(MonitorTab(), "Monitor")
        tabs.addTab(FuzzerTab(), "Fuzzer")
        tabs.addTab(IntrospectionTab(), "Introspection") # Container for Full/Monitor
        tabs.addTab(WordlistExtractorTab(), "Wordlist extractor")
        tabs.addTab(AliasBatchTab(), "Alias/Batch Gen")
        tabs.addTab(QueryFixerTab(), "Query Fixer")
        tabs.addTab(SchemaSearchTab(), "Schema Search & Report") # NEW tab
        v.addWidget(tabs)

# ======================== Dashboard & Main (Unchanged) ========================

class Dashboard(QWidget):
    def __init__(self, stacked: QStackedWidget):
        super().__init__()
        self.stacked = stacked
        lay = QVBoxLayout(self)
        title = QLabel("Pentest All in One")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        title.setStyleSheet("font-size:28px;font-weight:600;")
        lay.addWidget(title)
        grid = QGridLayout()
        def make_btn(text, handler):
            b = QPushButton(text); b.setMinimumSize(260,140)
            b.setStyleSheet("""
                QPushButton {
                    border: 2px solid #555; border-radius: 10px; padding: 18px; font-size:18px;
                    background: #1e1e1e; color: #eaeaea;
                }
                QPushButton:hover { background: #2a2a2a; }
            """)
            b.clicked.connect(handler); return b
        # First rectangle: GraphQL
        grid.addWidget(make_btn("GraphQL", self.open_graphql), 0, 0)
        # Placeholders for future modules:
        grid.addWidget(make_btn("HTTP Sniffer (coming soon)", lambda: QMessageBox.information(self,"Info","Coming soon")), 0, 1)
        grid.addWidget(make_btn("Websocket (coming soon)", lambda: QMessageBox.information(self,"Info","Coming soon")), 1, 0)
        grid.addWidget(make_btn("Wordlists (coming soon)", lambda: QMessageBox.information(self,"Info","Coming soon")), 1, 1)
        lay.addLayout(grid); lay.addStretch(1)
    def open_graphql(self):
        self.stacked.setCurrentIndex(1)

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Pentest All in One")
        self.resize(1200, 860)
        v = QVBoxLayout(self)
        self.stacked = QStackedWidget()
        self.dashboard = Dashboard(self.stacked)
        self.graphql = GraphQLSuite(self.go_back)
        self.stacked.addWidget(self.dashboard)   # index 0
        self.stacked.addWidget(self.graphql)     # index 1
        v.addWidget(self.stacked)
    def go_back(self):
        self.stacked.setCurrentIndex(0)

def main():
    app = QApplication(sys.argv)
    w = MainWindow(); w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
