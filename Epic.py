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
Authorized testing only.
"""

import sys, os, re, json, time, threading, traceback, glob, concurrent.futures as cf
from typing import Dict, List, Tuple, Optional, Set, Any
from datetime import datetime
from urllib.parse import urljoin

from PyQt6.QtWidgets import (
    QApplication, QWidget, QStackedWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QSpinBox, QComboBox, QPlainTextEdit, QMessageBox,
    QGroupBox, QFormLayout, QProgressBar, QDialog, QTextEdit, QGridLayout, QTabWidget
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ======================== Shared logging / signals ========================

class LogSignal(QObject):
    text = pyqtSignal(str)
    progress = pyqtSignal(int, int, float)   # done, total, rps

class BaseTab(QWidget):
    def __init__(self):
        super().__init__()
        self.log_signal = LogSignal()
        self.log_signal.text.connect(self._append_log)
        self.log_signal.progress.connect(self._update_progress)
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

# ======================== HTTP helpers ========================

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

# ======================== Small utils ========================

def _sanitize(path: str) -> str:
    path = re.sub(r'^\.\.?[/\\]webpack:[/\\_]+', '', path)
    path = re.sub(r'^\.\.?[/\\]', '', path)
    path = re.sub(r'[<>:"|?*]', '_', path)
    return path.replace('/', '_').replace('\\', '_')

# ======================== Extractors (COMBINED, like your script) ========================

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

# ======================== Rate limiter (Fuzzer) ========================

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

# ======================== Monitor Tab ========================

class MonitorTab(BaseTab):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)

        top = QHBoxLayout()
        help_btn = QPushButton("Help"); help_btn.clicked.connect(self._show_help)
        top.addStretch(1); top.addWidget(help_btn)
        lay.addLayout(top)

        cfg = QGroupBox("Monitor (High-Speed)")
        f = QFormLayout()
        self.config_path = QLineEdit(); self.config_path.setPlaceholderText("config.json (hosts[], cookies)")
        b1 = QPushButton("Browse…"); b1.clicked.connect(self._pick_config)
        hb1 = QHBoxLayout(); hb1.addWidget(self.config_path); hb1.addWidget(b1)

        self.js_txt = QLineEdit(); self.js_txt.setPlaceholderText("JS.txt (list of bundle URLs)")
        b2 = QPushButton("Browse…"); b2.clicked.connect(self._pick_js)
        hb2 = QHBoxLayout(); hb2.addWidget(self.js_txt); hb2.addWidget(b2)

        self.out_dir = QLineEdit(); self.out_dir.setPlaceholderText("Output base dir (e.g., graphql_monitor)")
        b3 = QPushButton("Choose…"); b3.clicked.connect(self._pick_out)
        hb3 = QHBoxLayout(); hb3.addWidget(self.out_dir); hb3.addWidget(b3)

        self.js_threads = QSpinBox(); self.js_threads.setRange(1, 256); self.js_threads.setValue(50)
        self.ts_threads = QSpinBox(); self.ts_threads.setRange(1, 256); self.ts_threads.setValue(50)

        ex_btn = QPushButton("Show config.json example"); ex_btn.clicked.connect(self._show_config_example)

        f.addRow("config.json:", hb1)
        f.addRow("JS.txt:", hb2)
        f.addRow("Output dir:", hb3)
        f.addRow("JS/Map threads:", self.js_threads)
        f.addRow("TS threads:", self.ts_threads)
        f.addWidget(ex_btn)
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
• Shows a final summary with exact counts matching files on disk""")

    def _pick_config(self):
        f, _ = QFileDialog.getOpenFileName(self, "config.json", "", "JSON (*.json);;All Files (*)")
        if f: self.config_path.setText(f)
    def _pick_js(self):
        f, _ = QFileDialog.getOpenFileName(self, "JS.txt", "", "Text (*.txt);;All Files (*)")
        if f: self.js_txt.setText(f)
    def _pick_out(self):
        d = QFileDialog.getExistingDirectory(self, "Choose output directory")
        if d: self.out_dir.setText(d)
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

    def run_monitor(self):
        cfg = self.config_path.text().strip()
        jsfile = self.js_txt.text().strip()
        base = self.out_dir.text().strip() or os.path.join(os.getcwd(), "graphql_monitor")
        if not os.path.exists(cfg) or not os.path.exists(jsfile):
            QMessageBox.warning(self, "Missing", "Provide config.json and JS.txt"); return

        def work():
            try:
                # Banner
                self.log("=" * 60)
                self.log("GraphQL Monitor v3.1 - JS URL Edition (COMBINED EXTRACTORS)")
                self.log("=" * 60)
                self.log("Features:")
                self.log("  ✓ Download JS files from URLs in JS.txt")
                self.log("  ✓ Original TypeScript extraction (inline, gql blocks, ts types)")
                self.log("  ✓ NEW: gql template literals extraction (from extractor v2)")
                self.log("  ✓ NEW: TypeScript '...Args' type definition extraction (from extractor v2)")
                self.log("  ✓ Ultra-fast downloads")
                self.log("  ✓ Old config format support")
                self.log("=" * 60)
                self.log("")

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
                GRAPHQL_API_DIR = os.path.join(OUTPUT_DIR,"GraphQL_API")
                GRAPHQL_NEW_DIR = os.path.join(OUTPUT_DIR,"GraphQL_NEW")
                os.makedirs(OUTPUT_DIR, exist_ok=True)
                os.makedirs(TS_DIR, exist_ok=True)
                os.makedirs(MAP_CACHE_DIR, exist_ok=True)
                os.makedirs(JS_FOLDER, exist_ok=True)

                # Step 0
                self.log(f"Step 0: Downloading JS files from {jsfile}")
                self.log("=" * 60)
                js_urls = [l.strip() for l in open(jsfile,'r',encoding='utf-8') if l.strip() and not l.strip().startswith('#')]
                js_total_count = len(js_urls); js_downloaded_count = 0
                self.log(f"Found {js_total_count} URLs to download")
                self.log(f"Using {self.js_threads.value()} parallel workers...\n")
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

                self.log(f"\nJS Download Summary:")
                self.log(f"URLs processed: {js_total_count}")
                self.log(f"JS files downloaded: {js_downloaded_count}")

                # Step 1
                self.log(f"\nStep 1: Downloading TypeScript files from source maps")
                self.log(f"Hosts: {', '.join(hosts)}\n")
                local_js_files = [f for f in glob.glob(os.path.join(JS_FOLDER, '*.js*')) if not f.endswith('.map')]
                if not local_js_files:
                    self.log("No JS files found. Skipping TypeScript extraction.")
                else:
                    self.log(f"Found {len(local_js_files)} JS files for processing")
                    self.log(f"Using {self.js_threads.value()} parallel workers with aggressive connection pooling...\n")
                    sourcemap_found_count = 0; ts_in_maps_count = 0; ts_extracted_count = 0; ts_downloaded_count = 0

                    def process_js_file(js_path: str):
                        nonlocal sourcemap_found_count, ts_in_maps_count, ts_extracted_count, ts_downloaded_count
                        try:
                            txt = open(js_path,'rb').read().decode('utf-8', errors='ignore')
                            m = re.search(r'//# sourceMappingURL=(.+\.map)', txt)
                            if not m: return
                            sourcemap_found_count += 1
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
                                        ts_in_maps_count += 1; ts_extracted_count +=1
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

                    self.log(f"\nDownload Summary:")
                    self.log(f"JS files processed: {len(local_js_files)}")
                    self.log(f"Source maps found: {sourcemap_found_count}")
                    self.log(f"TS files in maps: {ts_in_maps_count}")
                    self.log(f"TS extracted: {ts_extracted_count}")
                    self.log(f"TS downloaded: {ts_downloaded_count}")

                # Step 2
                self.log(f"\nStep 2: Extracting GraphQL operations from TypeScript/JS files")
                all_ops = self._extract_ops_dir(TS_DIR, extra_js_folder=JS_FOLDER)
                if not all_ops:
                    self.log("No GraphQL operations found"); return
                self.log(f"Extracted {len(all_ops)} total operations")

                # Step 3+4: history & NEW with exact counts
                self.log(f"\nStep 3: Comparing with history and saving operations")
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
                # Save history AFTER computing new
                json.dump(cur, open(hist_file,'w'), indent=2)

                GRAPHQL_NEW_DIR = os.path.join(base,"GraphQL_NEW")
                if os.path.exists(GRAPHQL_NEW_DIR):
                    import shutil; shutil.rmtree(GRAPHQL_NEW_DIR)
                os.makedirs(GRAPHQL_NEW_DIR, exist_ok=True)

                # Write NEW files and count by category
                new_mut, new_qry, new_sub = {}, {}, {}
                def find_op(root, name):
                    return all_ops.get((root, name)) or all_ops.get((root.capitalize(), name))
                for key, meta in new_map.items():
                    root, name = key.split(':',1)
                    op = find_op(root, name)
                    if not op: continue
                    subdir = os.path.join(GRAPHQL_NEW_DIR, root)
                    os.makedirs(subdir, exist_ok=True)
                    with open(os.path.join(subdir, f"{name}.txt"), 'w', encoding='utf-8') as f:
                        f.write("="*80+"\n"); f.write(f"{root.upper()}: {name}\n"); f.write("="*80+"\n")
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
                    if root=="Mutation": new_mut[name]=1
                    elif root=="Query": new_qry[name]=1
                    elif root=="Subscription": new_sub[name]=1

                # FINAL block (exact match with files)
                total_new = len(new_map)
                self.log("\n" + "="*60)
                self.log(f"🎯 FOUND {total_new} NEW OPERATIONS THIS RUN!")
                self.log("="*60)
                self.log(f"Writing NEW operations to {GRAPHQL_NEW_DIR}...")

                self.log("\n📊 NEW operations breakdown:")
                self.log(f"  🔴 NEW Mutations: {len(new_mut)}")
                for op_name in sorted(new_mut.keys()): self.log(f"     ✓ {op_name}")
                if new_qry:
                    self.log(f"  🔵 NEW Queries: {len(new_qry)}")
                    for op_name in sorted(new_qry.keys()): self.log(f"     ✓ {op_name}")
                if new_sub:
                    self.log(f"  🟢 NEW Subscriptions: {len(new_sub)}")
                    for op_name in sorted(new_sub.keys()): self.log(f"     ✓ {op_name}")
                if total_new == 0:
                    self.log("\n" + "="*60); self.log("✓ No new operations found this run"); self.log("="*60)

                # Summary from CURRENT (unique counts)
                unique_mut = {k.split(':',1)[1] for k in cur if k.startswith("Mutation:")}
                unique_qry = {k.split(':',1)[1] for k in cur if k.startswith("Query:")}
                unique_subs = {k.split(':',1)[1] for k in cur if k.startswith("Subscription:")}
                self.log(f"\n📈 Summary:")
                self.log(f"Total Mutations: {len(unique_mut)}")
                self.log(f"Total Queries: {len(unique_qry)}")
                self.log(f"Total Subscriptions: {len(unique_subs)}")
                self.log(f"\n🆕 New this run:")
                self.log(f"  New Mutations: {len(new_mut)}")
                self.log(f"  New Queries: {len(new_qry)}")
                self.log(f"  New Subscriptions: {len(new_sub)}")
                self.log(f"  TOTAL NEW: {total_new}")
                self.log("\n" + "=" * 60); self.log("Monitoring complete!"); self.log("=" * 60); self.log("")
                self.prog(1,1,0.0)
            except Exception as e:
                self.log(f"[Monitor] ERROR: {e}\n{traceback.format_exc()}")

        threading.Thread(target=work, daemon=True).start()

# ======================== Fuzzer Tab ========================

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

        top = QHBoxLayout()
        help_btn = QPushButton("Help"); help_btn.clicked.connect(self._show_help)
        top.addStretch(1); top.addWidget(help_btn)
        layout.addLayout(top)

        auth_box = QGroupBox("Endpoint & Auth"); af = QFormLayout()
        self.url_edit = QLineEdit(); self.url_edit.setPlaceholderText("https://example.com/graphql")
        self.jwt_edit = QLineEdit(); self.jwt_edit.setPlaceholderText("JWT")
        self.cookie_edit = QLineEdit(); self.cookie_edit.setPlaceholderText("cookie1=a; cookie2=b")
        self.extra_hdrs = QPlainTextEdit(); self.extra_hdrs.setPlaceholderText("X-Forwarded-For: 127.0.0.1")
        af.addRow("GraphQL URL:", self.url_edit); af.addRow("JWT:", self.jwt_edit)
        af.addRow("Cookies:", self.cookie_edit); af.addRow("Extra headers:", self.extra_hdrs)
        auth_box.setLayout(af); layout.addWidget(auth_box)

        rate_box = QGroupBox("Rate Control"); rf = QFormLayout()
        self.threads_spin = QSpinBox(); self.threads_spin.setRange(1,256); self.threads_spin.setValue(12)
        self.target_rps  = QSpinBox(); self.target_rps.setRange(1,500); self.target_rps.setValue(30)
        rf.addRow("Threads:", self.threads_spin); rf.addRow("Target RPS:", self.target_rps)
        rate_box.setLayout(rf); layout.addWidget(rate_box)

        root_box = QGroupBox("Root Field Fuzzer"); rff = QFormLayout()
        self.op_combo = QComboBox(); self.op_combo.addItems(["query","mutation"])
        self.nested_edit = QLineEdit("fsdfsdfsd")
        self.root_wordlist = QLineEdit(); br = QPushButton("Browse…"); br.clicked.connect(self._pick_root_words)
        hb = QHBoxLayout(); hb.addWidget(self.root_wordlist); hb.addWidget(br)
        self.btn_run_root = QPushButton("Run Root Fuzzer"); self.btn_run_root.clicked.connect(self.run_root_fuzzer)
        rff.addRow("Operation type:", self.op_combo)
        rff.addRow("Nested field:", self.nested_edit)
        rff.addRow("Wordlist:", hb)
        rff.addRow(self.btn_run_root)
        root_box.setLayout(rff); layout.addWidget(root_box)

        qf_box = QGroupBox("Per-Operation Field Brute-Forcer"); qff = QFormLayout()
        self.root_toggle = QComboBox(); self.root_toggle.addItems(["Query","Mutation"])
        self.op_names_path = QLineEdit(); bq = QPushButton("Browse ops…"); bq.clicked.connect(self._pick_opnames)
        hb2 = QHBoxLayout(); hb2.addWidget(self.op_names_path); hb2.addWidget(bq)
        self.field_words_path = QLineEdit(); bf = QPushButton("Browse fields…"); bf.clicked.connect(self._pick_fields)
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
    def _pick_root_words(self):
        f, _ = QFileDialog.getOpenFileName(self, "Wordlist", "", "Text (*.txt);;All Files (*)")
        if f: self.root_wordlist.setText(f)
    def _pick_opnames(self):
        f, _ = QFileDialog.getOpenFileName(self, "operations.txt", "", "Text (*.txt);;All Files (*)")
        if f: self.op_names_path.setText(f)
    def _pick_fields(self):
        f, _ = QFileDialog.getOpenFileName(self, "fields wordlist", "", "Text (*.txt);;All Files (*)")
        if f: self.field_words_path.setText(f)

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

# ======================== Introspection Tab (Normal + Custom; no fuzz/wordlist) ========================

class DeepIntrospector:
    def __init__(self, endpoint: str, headers: Dict[str,str], out_base: str, log_fn=print):
        self.endpoint = endpoint
        self.headers = headers
        self.out_base = out_base
        self.type_cache: Dict[str, Any] = {}
        self.processed_types: Set[str] = set()
        self.request_count = 0
        self.start_time = time.time()
        self.log = log_fn
        for folder in ['Query','Mutation','Subscription']:
            os.makedirs(os.path.join(self.out_base, folder), exist_ok=True)
    def _post(self, query: str, variables: Dict=None) -> Dict:
        self.request_count += 1
        payload = {"query": query}
        if variables: payload["variables"] = variables
        r = safe_post(self.endpoint, self.headers, payload, timeout=45)
        if r is None: raise RuntimeError("No response")
        if r.status_code in (401,403): raise PermissionError(f"Forbidden ({r.status_code})")
        r.raise_for_status(); return r.json()
    def unwrap(self, t: Dict) -> Optional[str]:
        if not t: return None
        kind = t.get("kind"); name = t.get("name"); ofType = t.get("ofType")
        if kind in ("NON_NULL","LIST") and ofType: return self.unwrap(ofType)
        return name
    def is_scalar(self, name: Optional[str]) -> bool:
        return name in {"Int","Float","String","Boolean","ID","DateTime","Date","Time","JSON"}
    def schema(self) -> Dict:
        q = """
        query ComprehensiveIntrospection {
          __schema {
            queryType { name fields {
              name description args { name description defaultValue type { kind name ofType { kind name ofType { kind name ofType { kind name }}}}}
              type { kind name ofType { kind name ofType { kind name ofType { kind name }}}}
              isDeprecated deprecationReason
            } }
            mutationType { name fields {
              name description args { name description defaultValue type { kind name ofType { kind name ofType { kind name ofType { kind name }}}}}
              type { kind name ofType { kind name ofType { kind name ofType { kind name }}}}
              isDeprecated deprecationReason
            } }
            subscriptionType { name fields {
              name description args { name description defaultValue type { kind name ofType { kind name ofType { kind name ofType { kind name }}}}}
              type { kind name ofType { kind name ofType { kind name ofType { kind name }}}}
              isDeprecated deprecationReason
            } }
          }
        }"""
        return self._post(q)
    def get_type(self, type_name: str) -> Optional[Dict]:
        if not type_name or self.is_scalar(type_name): return None
        if type_name in self.type_cache: return self.type_cache[type_name]
        if type_name in self.processed_types: return self.type_cache.get(type_name)
        self.processed_types.add(type_name)
        q = """
        query GetTypeDetails($typeName: String!) {
          __type(name: $typeName) {
            name kind description
            fields { name description type { kind name ofType { kind name ofType { kind name }}} }
            inputFields { name description type { kind name ofType { kind name ofType { kind name }}} }
            enumValues { name description isDeprecated deprecationReason }
          }
        }"""
        try:
            data = self._post(q, {"typeName": type_name}); node = data["data"]["__type"]
            self.type_cache[type_name] = node; return node
        except Exception as e:
            self.log(f"⚠️  Could not introspect type {type_name}: {e}")
            return None
    def _fmt_type_details(self, type_info: Dict) -> Dict:
        if not type_info: return {}
        out = {"name": type_info.get("name"), "kind": type_info.get("kind"), "description": type_info.get("description")}
        if isinstance(type_info.get("fields"), list):
            out["fields"] = {}
            for f in type_info["fields"]:
                if isinstance(f, dict) and "name" in f and "type" in f:
                    out["fields"][f["name"]] = {"type": self.unwrap(f["type"]), "description": f.get("description")}
        if isinstance(type_info.get("inputFields"), list):
            out["input_fields"] = {}
            for f in type_info["inputFields"]:
                if isinstance(f, dict) and "name" in f and "type" in f:
                    tname = self.unwrap(f["type"])
                    req = (f.get("type",{}).get("kind")=="NON_NULL")
                    out["input_fields"][f["name"]] = {"type": tname, "required": req, "description": f.get("description")}
        if isinstance(type_info.get("enumValues"), list):
            out["enum_values"] = [{"name": e.get("name"), "description": e.get("description")} for e in type_info["enumValues"] if isinstance(e, dict)]
        return out
    def _add_nested_fields(self, content: List[str], type_name: str, indent: str, visited: set):
        if not type_name or self.is_scalar(type_name) or type_name in visited: return
        visited.add(type_name)
        ti = self.type_cache.get(type_name)
        if ti and isinstance(ti.get("fields"), list):
            for fld in ti["fields"]:
                if isinstance(fld, dict) and "name" in fld and "type" in fld:
                    t2 = self.unwrap(fld["type"])
                    content.append(f"{indent}└─ {fld['name']}: {t2}")
                    if t2 and not self.is_scalar(t2) and t2 not in visited:
                        if t2 not in self.type_cache: self.get_type(t2)
                        self._add_nested_fields(content, t2, indent+"    ", visited.copy())
        visited.remove(type_name)
    def _write_op_file(self, op: Dict, root: str):
        name = op["name"]; folder = os.path.join(self.out_base, root.capitalize())
        os.makedirs(folder, exist_ok=True)
        fp = os.path.join(folder, f"{name}.txt")
        lines=[]; lines.append("="*80); lines.append(f"{root.upper()}: {name}"); lines.append("="*80)
        lines.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"); lines.append("")
        if op.get("description"): lines.append(f"Description: {op['description']}"); lines.append("")
        if op.get("isDeprecated"): lines.append("⚠️  DEPRECATED"); 
        if op.get("deprecationReason"): lines.append(f"Reason: {op['deprecationReason']}"); lines.append("")
        # args
        lines.append("ARGUMENTS:"); lines.append("-"*40)
        args = op.get("args") or []
        if not args: lines.append("No arguments"); lines.append("")
        else:
            for a in args:
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
        # return type
        ret = op.get("unwrapped_return_type","Unknown")
        lines.append("RETURN TYPE:"); lines.append("-"*40); lines.append(f"Type: {ret}")
        rtd = op.get("return_type_details",{}).get("fields",{})
        if rtd:
            lines.append("Fields:")
            for fn, fi in rtd.items():
                lines.append(f"  • {fn}: {fi.get('type')}")
                if fi.get("description"): lines.append(f"    {fi['description']}")
                nested = fi.get("type")
                if nested and nested in self.type_cache and not self.is_scalar(nested):
                    self._add_nested_fields(lines, nested, "    ", set())
        lines.append("")
        # example
        lines.append("GRAPHQL EXAMPLE:"); lines.append("-"*40); lines.append(f"{root} {{")
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
        if rtd:
            for fn in list(rtd.keys()):
                lines.append(f"    {fn}")
                nested = rtd[fn].get("type")
                if nested and nested in self.type_cache and not self.is_scalar(nested):
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
        with open(fp,'w',encoding='utf-8') as f: f.write("\n".join(lines))
        self.log(f"📄 Created: {fp}")

    def _enrich_ops(self, ops: List[Dict]) -> List[Dict]:
        out=[]; total=len(ops); idx=0
        for field in ops:
            idx+=1; self.log(f"📝 [{idx}/{total}] Processing {field['name']}")
            node = field.copy()
            # args
            a2=[]
            for arg in (field.get("args") or []):
                an = arg.copy()
                tname = self.unwrap(arg["type"]); an["unwrapped_type"]=tname
                an["required"] = (arg.get("type",{}).get("kind")=="NON_NULL")
                if tname and not self.is_scalar(tname):
                    ti = self.get_type(tname)
                    if ti:
                        an["type_details"]=self._fmt_type_details(ti)
                        # eager nested
                        self._introspect_nested(ti)
                a2.append(an)
            node["args"]=a2
            # return type
            r = self.unwrap(field["type"]); node["unwrapped_return_type"]=r
            if r and not self.is_scalar(r):
                ti = self.get_type(r)
                if ti:
                    node["return_type_details"]=self._fmt_type_details(ti)
                    self._introspect_nested(ti)
            out.append(node)
        return out

    def _introspect_nested(self, type_info: Dict):
        if not type_info: return
        nest=set()
        if isinstance(type_info.get("fields"), list):
            for f in type_info["fields"]:
                tn = self.unwrap(f.get("type")); if_valid = tn and not self.is_scalar(tn)
                if if_valid: nest.add(tn)
        if isinstance(type_info.get("inputFields"), list):
            for f in type_info["inputFields"]:
                tn = self.unwrap(f.get("type")); if_valid = tn and not self.is_scalar(tn)
                if if_valid: nest.add(tn)
        for tn in list(nest):
            if tn not in self.processed_types: self.get_type(tn)

    def run(self):
        self.log("🚀 Starting complete schema introspection…")
        self.log(f"⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log("="*80)
        data = self.schema()
        sch = data["data"]["__schema"]
        res={}
        if sch.get("queryType") and sch["queryType"].get("fields"):
            self.log("📋 Processing Queries…")
            res["queries"]=self._enrich_ops(sch["queryType"]["fields"])
            for op in res["queries"]: self._write_op_file(op,"query")
            self.log(f"✅ Created {len(res['queries'])} query files"); self.log("="*40)
        if sch.get("mutationType") and sch["mutationType"].get("fields"):
            self.log("🔧 Processing Mutations…")
            res["mutations"]=self._enrich_ops(sch["mutationType"]["fields"])
            for op in res["mutations"]: self._write_op_file(op,"mutation")
            self.log(f"✅ Created {len(res['mutations'])} mutation files"); self.log("="*40)
        if sch.get("subscriptionType") and sch["subscriptionType"].get("fields"):
            self.log("📡 Processing Subscriptions…")
            res["subscriptions"]=self._enrich_ops(sch["subscriptionType"]["fields"])
            for op in res["subscriptions"]: self._write_op_file(op,"subscription")
            self.log(f"✅ Created {len(res['subscriptions'])} subscription files"); self.log("="*40)
        elapsed = time.time()-self.start_time; rps = self.request_count/max(elapsed,0.01)
        self.log("🎉 Schema introspection complete!")
        self.log("="*80)
        self.log("📈 FINAL STATISTICS:")
        self.log(f"   • Total requests: {self.request_count}")
        self.log(f"   • Total time: {elapsed:.1f} seconds")
        self.log(f"   • Average RPS: {rps:.2f} requests/second")
        self.log(f"   • Types processed: {len(self.type_cache)}")
        self.log(f"   • Query files: {len(res.get('queries', []))}")
        self.log(f"   • Mutation files: {len(res.get('mutations', []))}")
        self.log(f"   • Subscription files: {len(res.get('subscriptions', []))}")
        self.log("="*80)
        return res

class IntrospectionTab(BaseTab):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        top = QHBoxLayout()
        help_btn = QPushButton("Help"); help_btn.clicked.connect(self._show_help)
        top.addStretch(1); top.addWidget(help_btn)
        layout.addLayout(top)

        auth_box = QGroupBox("Endpoint & Auth"); af = QFormLayout()
        self.url = QLineEdit(); self.url.setPlaceholderText("https://example.com/graphql")
        self.jwt = QLineEdit(); self.jwt.setPlaceholderText("JWT")
        self.cookie = QLineEdit(); self.cookie.setPlaceholderText("session=…; other=…")
        self.extra = QPlainTextEdit(); self.extra.setPlaceholderText("X-Token: abc\nAccept: */*")
        af.addRow("GraphQL URL:", self.url); af.addRow("JWT:", self.jwt)
        af.addRow("Cookies:", self.cookie); af.addRow("Extra headers:", self.extra)
        auth_box.setLayout(af); layout.addWidget(auth_box)

        self.out_dir = QLineEdit(); self.out_dir.setPlaceholderText("Output base dir (defaults to CWD)")
        outbtn = QPushButton("Choose…"); outbtn.clicked.connect(self._pick_out)
        hb = QHBoxLayout(); hb.addWidget(self.out_dir); hb.addWidget(outbtn); layout.addLayout(hb)

        run_btn = QPushButton("Run Introspection (normal + custom)"); run_btn.clicked.connect(self.run_intro)
        layout.addWidget(run_btn)

        self.pbar = QProgressBar(); self.pbar.setMaximum(1); self.pbar.setValue(0)
        self.rps_lbl = QLabel("RPS: 0.0")
        pb = QHBoxLayout(); pb.addWidget(self.pbar,1); pb.addWidget(self.rps_lbl); layout.addLayout(pb)
        self.log_box = QPlainTextEdit(); self.log_box.setReadOnly(True); layout.addWidget(self.log_box)

    def _show_help(self):
        self._help_popup("Introspection Help",
"""Introspection tab
• Performs normal __schema introspection, then a deep custom walk of types
• For each Query/Mutation/Subscription field, writes a detailed .txt (args, input objects, return fields, sample query)
• No fuzzing here (as requested); if server forbids introspection, you’ll get a clear message""")

    def _pick_out(self):
        d = QFileDialog.getExistingDirectory(self, "Choose output directory")
        if d: self.out_dir.setText(d)
    def _headers(self):
        return build_headers(self.jwt.text(), self.cookie.text(), self.extra.toPlainText())

    def run_intro(self):
        url = self.url.text().strip()
        if not url:
            QMessageBox.warning(self, "Missing", "Enter GraphQL URL."); return
        out_base = self.out_dir.text().strip() or os.getcwd()
        headers = self._headers()

        def work():
            try:
                insp = DeepIntrospector(url, headers, out_base, log_fn=self.log)
                insp.run()
                self.prog(1,1,0.0)
            except PermissionError:
                self.log("Introspection forbidden: server returned 401/403 or equivalent error message.")
                QMessageBox.information(self, "Introspection", "Introspection fully disabled (forbidden).")
            except Exception as e:
                self.log(f"[Introspection] ERROR: {e}\n{traceback.format_exc()}")

        threading.Thread(target=work, daemon=True).start()

# ======================== Wordlist Extractor Tab ========================

class WordlistExtractorTab(BaseTab):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        top = QHBoxLayout()
        help_btn = QPushButton("Help"); help_btn.clicked.connect(self._show_help)
        top.addStretch(1); top.addWidget(help_btn)
        layout.addLayout(top)

        io = QGroupBox("Wordlist extractor")
        f = QFormLayout()
        self.folder_edit = QLineEdit(); self.folder_edit.setPlaceholderText("Folder that contains .txt files (recursive)")
        b1 = QPushButton("Browse…"); b1.clicked.connect(self._pick_folder)
        hb1 = QHBoxLayout(); hb1.addWidget(self.folder_edit); hb1.addWidget(b1)

        self.output_edit = QLineEdit(); self.output_edit.setPlaceholderText("Output wordlist file (e.g., wordlist.txt)")
        b2 = QPushButton("Save as…"); b2.clicked.connect(self._pick_output)
        hb2 = QHBoxLayout(); hb2.addWidget(self.output_edit); hb2.addWidget(b2)

        self.minlen = QSpinBox(); self.minlen.setRange(1,50); self.minlen.setValue(1)
        self.lowercase = QComboBox(); self.lowercase.addItems(["keep", "lowercase"])

        f.addRow("Source folder:", hb1)
        f.addRow("Output file:", hb2)
        f.addRow("Min word length:", self.minlen)
        f.addRow("Case:", self.lowercase)
        io.setLayout(f)
        layout.addWidget(io)

        run = QPushButton("Extract unique words"); run.clicked.connect(self.run_extract)
        layout.addWidget(run)

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

    def _pick_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Choose folder with .txt files")
        if d:
            self.folder_edit.setText(d)
            default_out = os.path.join(d, "wordlist_extracted.txt")
            self.output_edit.setText(default_out)

    def _pick_output(self):
        f, _ = QFileDialog.getSaveFileName(self, "Save wordlist as", self.output_edit.text().strip() or "wordlist.txt", "Text (*.txt);;All Files (*)")
        if f: self.output_edit.setText(f)

    def run_extract(self):
        folder = self.folder_edit.text().strip()
        outpath = self.output_edit.text().strip()
        if not os.path.isdir(folder):
            QMessageBox.warning(self, "Missing", "Pick a valid folder."); return
        if not outpath:
            QMessageBox.warning(self, "Missing", "Pick an output file path."); return

        def work():
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

        threading.Thread(target=work, daemon=True).start()

# ======================== GraphQL Suite (with Back button) ========================

class GraphQLSuite(QWidget):
    def __init__(self, go_back_callback):
        super().__init__()
        v = QVBoxLayout(self)

        # Top bar with Back + title
        top = QHBoxLayout()
        back = QPushButton("← Back"); back.clicked.connect(go_back_callback)
        title = QLabel("GraphQL"); title.setStyleSheet("font-size:20px; font-weight:600;")
        top.addWidget(back); top.addStretch(1); top.addWidget(title); top.addStretch(5)
        v.addLayout(top)

        tabs = QTabWidget()
        tabs.addTab(MonitorTab(), "Monitor")
        tabs.addTab(FuzzerTab(), "Fuzzer")
        tabs.addTab(IntrospectionTab(), "Introspection")
        tabs.addTab(WordlistExtractorTab(), "Wordlist extractor")
        v.addWidget(tabs)

# ======================== Dashboard & Main ========================

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
