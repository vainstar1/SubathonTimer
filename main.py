import json
import os
import queue
import socket
import ssl
import threading
import time
import traceback
import webbrowser
import urllib.request
import urllib.parse
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, Any
from datetime import datetime

try:
    from zoneinfo import ZoneInfo
    NY_TZ = ZoneInfo("America/New_York")
except Exception:
    NY_TZ = None

APP_TITLE = "Subathon Timer (GUI)"
STATE_FILE = "subathon_state.json"
CONFIG_FILE = "subathon_config.json"
TIMER_FILE = "timer.txt"
SUBS_FILE = "total_subs.txt"

TW_VALIDATE = "https://id.twitch.tv/oauth2/validate"
TW_TOKEN = "https://id.twitch.tv/oauth2/token"


def now_ms() -> int:
    return int(time.time() * 1000)


def fmt_hms(total_sec: int) -> str:
    total_sec = max(0, int(total_sec))
    h = total_sec // 3600
    m = (total_sec % 3600) // 60
    s = total_sec % 60
    return f"{h}:{m:02d}:{s:02d}"


def parse_duration(s: str) -> Optional[int]:
    t = s.strip().lower()
    if not t:
        return None
    if ":" in t:
        parts = [p for p in t.split(":") if p != ""]
        if len(parts) == 3:
            h, m, s2 = parts
            if h.isdigit() and m.isdigit() and s2.isdigit():
                return int(h) * 3600 + int(m) * 60 + int(s2)
        elif len(parts) == 2:
            m, s2 = parts
            if m.isdigit() and s2.isdigit():
                return int(m) * 60 + int(s2)
        return None
    if t.isdigit():
        return int(t)
    return None


def http_get_json(url: str, headers: Dict[str, str]) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


def http_post_form(url: str, data: Dict[str, str]) -> Dict[str, Any]:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


class Timer:
    def __init__(self):
        self.running = False
        self.end_at: Optional[int] = None
        self.remaining = 0
        self.base_seconds = 3600
        self._lock = threading.Lock()

    def start(self, seconds: int):
        with self._lock:
            seconds = max(0, int(seconds))
            self.base_seconds = seconds
            self.running = True
            self.end_at = now_ms() + seconds * 1000
            self.remaining = 0

    def pause(self):
        with self._lock:
            if self.running:
                self.remaining = self._get_remaining_unlocked()
                self.running = False
                self.end_at = None

    def resume(self):
        with self._lock:
            if not self.running:
                self.running = True
                self.end_at = now_ms() + self.remaining * 1000
                self.remaining = 0

    def reset(self, seconds: int):
        with self._lock:
            seconds = max(0, int(seconds))
            self.running = False
            self.end_at = None
            self.remaining = seconds

    def add_seconds(self, delta: int):
        with self._lock:
            cur = self._get_remaining_unlocked()
            nxt = max(0, cur + int(delta))
            if self.running:
                self.end_at = now_ms() + nxt * 1000
            else:
                self.remaining = nxt

    def get_remaining(self) -> int:
        with self._lock:
            return self._get_remaining_unlocked()

    def _get_remaining_unlocked(self) -> int:
        if not self.running or self.end_at is None:
            return max(0, int(self.remaining))
        return max(0, int((self.end_at - now_ms()) / 1000 + 0.999))

    def save(self):
        with self._lock:
            state = {
                "running": self.running,
                "end_at": self.end_at,
                "remaining": self.remaining,
                "base_seconds": self.base_seconds,
            }
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)

    def load(self):
        if not os.path.exists(STATE_FILE):
            return
        try:
            st = json.load(open(STATE_FILE, "r", encoding="utf-8"))
            self.running = bool(st.get("running", False))
            self.end_at = st.get("end_at")
            self.remaining = int(st.get("remaining", 0))
            self.base_seconds = int(st.get("base_seconds", 3600))
            if self.running and self.get_remaining() == 0:
                self.running = False
                self.end_at = None
                self.remaining = 0
        except Exception:
            pass


@dataclass
class Rules:
    minutes_t1: int = 5
    minutes_t2: int = 7
    minutes_t3: int = 10
    bits_t1: int = 300
    bits_t2: int = 600
    bits_t3: int = 1750
    per_cheer_thresholds: bool = True


@dataclass
class TwitchCFG:
    channel: str = "MomoSeventh"
    bot_username: str = ""
    oauth_token: str = ""
    client_id: str = ""
    client_secret: str = ""
    refresh_token: str = ""
    expires_at: int = 0
    auto_refresh: bool = True


@dataclass
class AppConfig:
    rules: Rules = field(default_factory=Rules)
    twitch: TwitchCFG = field(default_factory=TwitchCFG)
    write_timer_file: bool = True
    timer_path: str = os.path.abspath(TIMER_FILE)
    write_subs_file: bool = True
    subs_path: str = os.path.abspath(SUBS_FILE)
    total_subs: int = 0

    def to_json(self) -> Dict[str, Any]:
        return {
            "rules": asdict(self.rules),
            "twitch": asdict(self.twitch),
            "write_timer_file": self.write_timer_file,
            "timer_path": self.timer_path,
            "write_subs_file": self.write_subs_file,
            "subs_path": self.subs_path,
            "total_subs": self.total_subs,
        }

    @staticmethod
    def from_json(d: Dict[str, Any]) -> "AppConfig":
        cfg = AppConfig()
        if "rules" in d:
            cfg.rules = Rules(**{**asdict(cfg.rules), **d["rules"]})
        if "twitch" in d:
            base = asdict(cfg.twitch)
            base.update(d["twitch"])
            cfg.twitch = TwitchCFG(**base)
        cfg.write_timer_file = bool(d.get("write_timer_file", True))
        cfg.timer_path = d.get("timer_path", cfg.timer_path)
        cfg.write_subs_file = bool(d.get("write_subs_file", True))
        cfg.subs_path = d.get("subs_path", cfg.subs_path)
        cfg.total_subs = int(d.get("total_subs", 0))
        return cfg


def parse_tags(tag_str: str) -> Dict[str, str]:
    out = {}
    for part in tag_str.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
        else:
            out[part] = ""
    return out


class TwitchChatThread(threading.Thread):
    def __init__(self, channel: str, username: str, token: str, event_q: queue.Queue):
        super().__init__(daemon=True)
        self.channel = channel
        self.username = username
        self.token = token
        self.event_q = event_q
        self._stop = threading.Event()
        self.sock = None
        self.massgift_ids = set()

    def stop(self):
        self._stop.set()
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

    def _send(self, s: str):
        try:
            self.sock.send((s + "\r\n").encode("utf-8"))
        except Exception:
            pass

    def run(self):
        try:
            self.event_q.put(('status', {'msg': "Connecting"}))
            host, port = "irc.chat.twitch.tv", 6697
            raw_sock = socket.create_connection((host, port), timeout=15)
            ctx = ssl.create_default_context()
            self.sock = ctx.wrap_socket(raw_sock, server_hostname=host)
            self.sock.settimeout(0.5)
            tok = self.token if self.token.startswith("oauth:") else f"oauth:{self.token}"
            self._send(f"PASS {tok}")
            self._send(f"NICK {self.username}")
            self._send("CAP REQ :twitch.tv/tags twitch.tv/commands twitch.tv/membership")
            chan = f"#{self.channel.lower()}"
            self._send(f"JOIN {chan}")
            self.event_q.put(('status', {'msg': f"Joining #{self.channel}"}))
            buff = b""
            last_pong = time.time()
            joined = False
            while not self._stop.is_set():
                try:
                    data = self.sock.recv(4096)
                    if not data:
                        raise ConnectionError("socket closed")
                    buff += data
                except socket.timeout:
                    pass
                except Exception as e:
                    self.event_q.put(('status', {'msg': f"Socket error: {e}"}))
                    break
                while b"\r\n" in buff:
                    line, buff = buff.split(b"\r\n", 1)
                    txt = line.decode("utf-8", errors="ignore")
                    if txt.startswith("PING "):
                        self._send("PONG :tmi.twitch.tv")
                        last_pong = time.time()
                        continue
                    if "Login authentication failed" in txt:
                        self.event_q.put(('auth_failed', {}))
                        return
                    parts = txt.split(" ", 3)
                    if len(parts) >= 2 and parts[1] == "001":
                        self.event_q.put(('status', {'msg': "Connected"}))
                    if " :End of /NAMES list" in txt and not joined:
                        joined = True
                        self.event_q.put(('status', {'msg': f"Listening to #{self.channel}"}))
                    if txt.startswith("@"):
                        try:
                            tags_part, rest = txt.split(" ", 1)
                            tags = parse_tags(tags_part[1:])
                            rest_parts = rest.split(" ", 2)
                            cmd = rest_parts[1] if len(rest_parts) >= 2 else None
                            if cmd == "PRIVMSG":
                                bits = tags.get("bits")
                                if bits and bits.isdigit():
                                    user = tags.get("display-name") or tags.get("login") or "Unknown"
                                    self.event_q.put(('bits', {'amount': int(bits), 'user': user}))
                            elif cmd == "USERNOTICE":
                                msg_id = tags.get("msg-id", "")
                                plan = tags.get("msg-param-sub-plan", "1000")
                                tier = 1 if plan == "1000" else 2 if plan == "2000" else 3
                                if msg_id in ("sub", "resub"):
                                    user = tags.get("display-name") or tags.get("login") or "Unknown"
                                    self.event_q.put(('sub', {'tier': tier, 'count': 1, 'user': user, 'gift': False}))
                                elif msg_id in ("subgift", "anonsubgift"):
                                    origin_id = tags.get("msg-param-origin-id", "")
                                    if origin_id and origin_id in self.massgift_ids:
                                        continue
                                    gifter = "Anonymous" if msg_id == "anonsubgift" else (tags.get("display-name") or tags.get("login") or "Unknown")
                                    self.event_q.put(('sub', {'tier': tier, 'count': 1, 'user': gifter, 'gift': True}))
                                elif msg_id in ("submysterygift", "anonsubmysterygift"):
                                    count = int(tags.get("msg-param-mass-gift-count", "0") or "0")
                                    origin_id = tags.get("msg-param-origin-id", "")
                                    if origin_id:
                                        self.massgift_ids.add(origin_id)
                                    gifter = "Anonymous" if msg_id == "anonsubmysterygift" else (tags.get("display-name") or tags.get("login") or "Unknown")
                                    if count > 0:
                                        self.event_q.put(('sub', {'tier': tier, 'count': count, 'user': gifter, 'gift': True, 'mass': True}))
                        except Exception:
                            pass
                if time.time() - last_pong > 120:
                    self._send("PING :tmi.twitch.tv")
                    last_pong = time.time()
            self.event_q.put(('status', {'msg': "Disconnected"}))
        except Exception as e:
            self.event_q.put(('status', {'msg': f"Error: {e}"}))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.configure(bg="black")
        self.timer = Timer()
        self.timer.load()
        self.cfg = self._load_config()
        self.event_q: queue.Queue = queue.Queue()
        self.twitch_thread: Optional[TwitchChatThread] = None
        self.refresh_thread: Optional[threading.Thread] = None
        self.refresh_ev = threading.Event()
        self._build_ui()
        self.after(0, self._auto_connect_on_startup)
        self._tick()

    def safe(self, fn):
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                traceback.print_exc()
                messagebox.showerror(APP_TITLE, f"{type(e).__name__}: {e}")
        return wrapper

    def _build_ui(self):
        self.timer_var = tk.StringVar(value=fmt_hms(self.timer.get_remaining()))
        lbl = tk.Label(self, textvariable=self.timer_var, fg="red", bg="black", font=("Segoe UI", 72, "bold"))
        lbl.grid(row=0, column=0, columnspan=6, padx=16, pady=(16, 8), sticky="ew")
        btn_start = ttk.Button(self, text="Start…", command=self.safe(self._start_dialog))
        btn_pause = ttk.Button(self, text="Pause", command=self.safe(self._pause))
        btn_resume = ttk.Button(self, text="Resume", command=self.safe(self._resume))
        btn_set = ttk.Button(self, text="Set Time…", command=self.safe(self._set_time_dialog))
        btn_add60 = ttk.Button(self, text="+60s", command=self.safe(lambda: self._add_seconds(60)))
        for i, b in enumerate([btn_start, btn_pause, btn_resume, btn_set, btn_add60]):
            b.grid(row=1, column=i, padx=6, pady=6, sticky="ew")
        self.btn_t1 = ttk.Button(self, text="Add T1 (+5m)", command=self.safe(self._add_t1))
        self.btn_t2 = ttk.Button(self, text="Add T2 (+7m)", command=self.safe(self._add_t2))
        self.btn_t3 = ttk.Button(self, text="Add T3 (+10m)", command=self.safe(self._add_t3))
        self.btn_t1.grid(row=2, column=0, padx=6, pady=6, sticky="ew")
        self.btn_t2.grid(row=2, column=1, padx=6, pady=6, sticky="ew")
        self.btn_t3.grid(row=2, column=2, padx=6, pady=6, sticky="ew")
        frm_rules = ttk.LabelFrame(self, text="Rules")
        frm_rules.grid(row=3, column=0, columnspan=3, padx=8, pady=8, sticky="nsew")
        self.minutes_t1 = tk.IntVar(value=self.cfg.rules.minutes_t1)
        self.minutes_t2 = tk.IntVar(value=self.cfg.rules.minutes_t2)
        self.minutes_t3 = tk.IntVar(value=self.cfg.rules.minutes_t3)
        self.bits_t1 = tk.IntVar(value=self.cfg.rules.bits_t1)
        self.bits_t2 = tk.IntVar(value=self.cfg.rules.bits_t2)
        self.bits_t3 = tk.IntVar(value=self.cfg.rules.bits_t3)
        self.per_cheer = tk.BooleanVar(value=self.cfg.rules.per_cheer_thresholds)

        def labeled(row, col, text, var):
            ttk.Label(frm_rules, text=text).grid(row=row, column=col, sticky="w")
            e = ttk.Entry(frm_rules, width=8, textvariable=var)
            e.grid(row=row, column=col + 1, padx=6, pady=2)
            return e

        labeled(0, 0, "T1 minutes:", self.minutes_t1)
        labeled(1, 0, "T2 minutes:", self.minutes_t2)
        labeled(2, 0, "T3 minutes:", self.minutes_t3)
        labeled(0, 2, "Bits ≥T1:", self.bits_t1)
        labeled(1, 2, "Bits ≥T2:", self.bits_t2)
        labeled(2, 2, "Bits ≥T3:", self.bits_t3)
        ttk.Checkbutton(frm_rules, text="Use per-cheer thresholds (default)", variable=self.per_cheer).grid(row=3, column=0, columnspan=4, sticky="w", pady=4)
        ttk.Button(frm_rules, text="Save Rules", command=self.safe(self._save_rules)).grid(row=4, column=0, pady=6, sticky="w")
        frm_t = ttk.LabelFrame(self, text="Twitch Tracking")
        frm_t.grid(row=3, column=3, columnspan=3, padx=8, pady=8, sticky="nsew")
        self.twitch_status = tk.StringVar(value="Disconnected")
        self.twitch_channel = tk.StringVar(value=self.cfg.twitch.channel)
        self.twitch_user = tk.StringVar(value=self.cfg.twitch.bot_username)
        self.twitch_token = tk.StringVar(value=self.cfg.twitch.oauth_token)
        self.twitch_client_id = tk.StringVar(value=self.cfg.twitch.client_id)
        self.twitch_client_secret = tk.StringVar(value=self.cfg.twitch.client_secret)
        self.twitch_refresh = tk.StringVar(value=self.cfg.twitch.refresh_token)
        self.auto_refresh_var = tk.BooleanVar(value=self.cfg.twitch.auto_refresh)
        self.expires_label = tk.StringVar(value="")
        ttk.Label(frm_t, text="Channel").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm_t, textvariable=self.twitch_channel, width=18).grid(row=0, column=1, sticky="w")
        ttk.Label(frm_t, text="Bot Username").grid(row=1, column=0, sticky="w")
        ttk.Entry(frm_t, textvariable=self.twitch_user, width=18).grid(row=1, column=1, sticky="w")
        ttk.Label(frm_t, text="OAuth (chat) token").grid(row=2, column=0, sticky="w")
        ttk.Entry(frm_t, textvariable=self.twitch_token, width=28, show="•").grid(row=2, column=1, sticky="w")
        ttk.Button(frm_t, text="Get Chat Token", command=lambda: webbrowser.open("https://twitchtokengenerator.com/")).grid(row=2, column=2, padx=6)
        ttk.Label(frm_t, text="Client ID").grid(row=3, column=0, sticky="w")
        ttk.Entry(frm_t, textvariable=self.twitch_client_id, width=24).grid(row=3, column=1, sticky="w")
        ttk.Label(frm_t, text="Client Secret").grid(row=4, column=0, sticky="w")
        ttk.Entry(frm_t, textvariable=self.twitch_client_secret, width=24, show="•").grid(row=4, column=1, sticky="w")
        ttk.Label(frm_t, text="Refresh Token").grid(row=5, column=0, sticky="w")
        ttk.Entry(frm_t, textvariable=self.twitch_refresh, width=28, show="•").grid(row=5, column=1, sticky="w")
        ttk.Checkbutton(frm_t, text="Auto-refresh", variable=self.auto_refresh_var).grid(row=6, column=0, sticky="w")
        ttk.Button(frm_t, text="Validate", command=self.safe(self._validate_token)).grid(row=6, column=1, sticky="w")
        ttk.Label(frm_t, textvariable=self.expires_label, foreground="gray").grid(row=6, column=2, sticky="w")
        ttk.Button(frm_t, text="Connect", command=self.safe(self._twitch_connect)).grid(row=7, column=0, pady=6, sticky="w")
        ttk.Button(frm_t, text="Disconnect", command=self.safe(self._twitch_disconnect)).grid(row=7, column=1, pady=6, sticky="w")
        ttk.Label(frm_t, textvariable=self.twitch_status, foreground="green").grid(row=7, column=2, sticky="w")
        frm_subs = ttk.LabelFrame(self, text="Total Subs")
        frm_subs.grid(row=4, column=0, columnspan=6, padx=8, pady=8, sticky="ew")
        self.total_subs_var = tk.IntVar(value=self.cfg.total_subs)
        ttk.Label(frm_subs, text="Total Subs:").grid(row=0, column=0, sticky="w")
        self.total_subs_entry = ttk.Entry(frm_subs, width=10)
        self.total_subs_entry.insert(0, str(self.total_subs_var.get()))
        self.total_subs_entry.grid(row=0, column=1, padx=6, sticky="w")
        ttk.Button(frm_subs, text="Update", command=self.safe(self._update_total_subs_from_entry)).grid(row=0, column=2, padx=6, sticky="w")
        ttk.Button(frm_subs, text="+1", command=self.safe(lambda: self._inc_subs(1))).grid(row=0, column=3, padx=6, sticky="w")
        ttk.Button(frm_subs, text="-1", command=self.safe(lambda: self._inc_subs(-1))).grid(row=0, column=4, padx=6, sticky="w")
        self.write_subs_file_var = tk.BooleanVar(value=self.cfg.write_subs_file)
        self.subs_path_var = tk.StringVar(value=self.cfg.subs_path)
        ttk.Checkbutton(frm_subs, text="Write subs to file", variable=self.write_subs_file_var).grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(frm_subs, textvariable=self.subs_path_var, width=60).grid(row=1, column=1, columnspan=3, sticky="w", padx=6, pady=(6, 0))
        ttk.Button(frm_subs, text="Browse…", command=self.safe(self._pick_subs_path)).grid(row=1, column=4, padx=6, pady=(6, 0))
        frm_out = ttk.LabelFrame(self, text="OBS Text Output")
        frm_out.grid(row=5, column=0, columnspan=6, padx=8, pady=(0, 8), sticky="ew")
        self.write_file_var = tk.BooleanVar(value=self.cfg.write_timer_file)
        self.timer_path_var = tk.StringVar(value=self.cfg.timer_path)
        ttk.Checkbutton(frm_out, text="Write timer to file", variable=self.write_file_var).grid(row=0, column=0, sticky="w")
        ttk.Entry(frm_out, textvariable=self.timer_path_var, width=60).grid(row=0, column=1, sticky="w", padx=6)
        ttk.Button(frm_out, text="Browse…", command=self.safe(self._pick_path)).grid(row=0, column=2, padx=6)
        self.log = tk.Text(self, height=8, bg="#111", fg="#bbb")
        self.log.grid(row=6, column=0, columnspan=6, padx=8, pady=(0, 8), sticky="nsew")
        for c in range(6):
            self.grid_columnconfigure(c, weight=1)
        self.grid_rowconfigure(6, weight=1)
        self._refresh_rule_labels()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._render_expiry()

    def _start_dialog(self):
        sec = self._ask_duration("Start with what time? (HH:MM:SS or MM:SS or seconds)", fmt_hms(self.timer.base_seconds))
        if sec is not None:
            self.timer.start(sec)
            self._log(f"start {fmt_hms(sec)}")

    def _set_time_dialog(self):
        sec = self._ask_duration("Set remaining time to (HH:MM:SS or MM:SS or seconds)", fmt_hms(self.timer.get_remaining() or self.timer.base_seconds))
        if sec is not None:
            self.timer.reset(sec)
            self._log(f"set to {fmt_hms(sec)}")

    def _pause(self):
        self.timer.pause()
        self._log("pause")

    def _resume(self):
        self.timer.resume()
        self._log("resume")

    def _add_seconds(self, s: int):
        self.timer.add_seconds(s)
        self._log(f"+{s}s")

    def _add_t1(self):
        mins = self.minutes_t1.get()
        self.timer.add_seconds(mins * 60)
        self._log(f"+{mins}m (T1)")

    def _add_t2(self):
        mins = self.minutes_t2.get()
        self.timer.add_seconds(mins * 60)
        self._log(f"+{mins}m (T2)")

    def _add_t3(self):
        mins = self.minutes_t3.get()
        self.timer.add_seconds(mins * 60)
        self._log(f"+{mins}m (T3)")

    def _save_rules(self):
        self.cfg.rules = Rules(
            minutes_t1=self.minutes_t1.get(),
            minutes_t2=self.minutes_t2.get(),
            minutes_t3=self.minutes_t3.get(),
            bits_t1=self.bits_t1.get(),
            bits_t2=self.bits_t2.get(),
            bits_t3=self.bits_t3.get(),
            per_cheer_thresholds=self.per_cheer.get(),
        )
        self._save_config()
        self._refresh_rule_labels()
        self._log("rules saved")

    def _refresh_rule_labels(self):
        self.btn_t1.config(text=f"Add T1 (+{self.minutes_t1.get()}m)")
        self.btn_t2.config(text=f"Add T2 (+{self.minutes_t2.get()}m)")
        self.btn_t3.config(text=f"Add T3 (+{self.minutes_t3.get()}m)")

    def _pick_path(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="timer.txt")
        if p:
            self.timer_path_var.set(p)
            self._save_config()

    def _pick_subs_path(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="total_subs.txt")
        if p:
            self.subs_path_var.set(p)
            self._save_config()

    def _validate_token(self):
        tok = self.twitch_token.get().strip()
        if not tok:
            messagebox.showinfo(APP_TITLE, "Paste an access token first.")
            return
        try:
            info = http_get_json(TW_VALIDATE, {"Authorization": f"OAuth {tok}"})
            sec = int(info.get("expires_in", 0))
            self.cfg.twitch.expires_at = int(time.time()) + sec
            self._save_oauth_fields()
            self._render_expiry()
            self._log(f"token valid, expires in {sec}s for user {info.get('login','?')}")
        except Exception as e:
            self._log(f"validate failed: {e}")
            messagebox.showerror(APP_TITLE, f"Validate failed: {e}")

    def _refresh_worker(self, wake_margin: int = 300):
        while not self.refresh_ev.is_set():
            if not self.auto_refresh_var.get():
                time.sleep(5)
                continue
            cid = self.twitch_client_id.get().strip()
            csec = self.twitch_client_secret.get().strip()
            rtok = self.twitch_refresh.get().strip()
            if not (cid and csec and rtok):
                time.sleep(5)
                continue
            now = int(time.time())
            exp = int(self.cfg.twitch.expires_at or 0)
            sleep_for = 15
            if exp > 0:
                left = exp - now
                if left <= wake_margin:
                    try:
                        data = {
                            "grant_type": "refresh_token",
                            "refresh_token": rtok,
                            "client_id": cid,
                            "client_secret": csec,
                        }
                        res = http_post_form(TW_TOKEN, data)
                        at = res.get("access_token", "")
                        new_rt = res.get("refresh_token", rtok)
                        ex = int(res.get("expires_in", 14400))
                        if at:
                            self.twitch_token.set(at)
                            self.twitch_refresh.set(new_rt)
                            self.cfg.twitch.oauth_token = at
                            self.cfg.twitch.refresh_token = new_rt
                            self.cfg.twitch.expires_at = int(time.time()) + ex
                            self._save_config()
                            self._render_expiry()
                            self._log("token refreshed")
                            if self.twitch_thread:
                                try:
                                    self.twitch_thread.stop()
                                except Exception:
                                    pass
                            self.twitch_thread = TwitchChatThread(
                                self.twitch_channel.get().strip() or "MomoSeventh",
                                self.twitch_user.get().strip(),
                                at,
                                self.event_q,
                            )
                            self.twitch_thread.start()
                        else:
                            self._log("refresh failed: no access_token in response")
                    except Exception as e:
                        self._log(f"refresh failed: {e}")
                    sleep_for = 60
                else:
                    sleep_for = max(5, min(300, left - wake_margin))
            time.sleep(sleep_for)

    def _start_refresh_thread(self):
        if self.refresh_thread and self.refresh_thread.is_alive():
            return
        self.refresh_ev.clear()
        self.refresh_thread = threading.Thread(target=self._refresh_worker, daemon=True)
        self.refresh_thread.start()

    def _stop_refresh_thread(self):
        self.refresh_ev.set()

    def _twitch_connect(self, silent: bool = False):
        user = self.twitch_user.get().strip()
        token = self.twitch_token.get().strip()
        chan = (self.twitch_channel.get().strip() or "MomoSeventh")
        if not (user and token):
            if silent:
                self._log("auto-connect failed: missing credentials")
                return
            messagebox.showinfo(APP_TITLE, "Provide Bot Username and OAuth token to connect.")
            return
        if self.twitch_thread:
            if not silent:
                messagebox.showinfo(APP_TITLE, "Already connected.")
            return
        self._save_oauth_fields()
        self.twitch_thread = TwitchChatThread(chan, user, token, self.event_q)
        self.twitch_thread.start()
        self._start_refresh_thread()
        if self.cfg.twitch.expires_at == 0:
            try:
                info = http_get_json(TW_VALIDATE, {"Authorization": f"OAuth {token}"})
                self.cfg.twitch.expires_at = int(time.time()) + int(info.get("expires_in", 0))
                self._save_config()
                self._render_expiry()
            except Exception:
                pass

    def _twitch_disconnect(self):
        if self.twitch_thread:
            self.twitch_thread.stop()
            self.twitch_thread = None
        self._set_status("Disconnected")

    def _tick(self):
        rem = self.timer.get_remaining()
        self.timer_var.set(fmt_hms(rem))
        if self.write_file_var.get():
            try:
                with open(self.timer_path_var.get(), "w", encoding="utf-8") as f:
                    f.write(fmt_hms(rem) + "\n")
            except Exception:
                pass
        if self.write_subs_file_var.get():
            self._write_subs_file()
        try:
            while True:
                ev, data = self.event_q.get_nowait()
                if ev == "status":
                    self._set_status(data.get("msg", ""))
                elif ev == "bits":
                    self._handle_bits(data)
                elif ev == "sub":
                    self._handle_sub(data)
                elif ev == "auth_failed":
                    self._log("auth failed; attempting refresh")
                    self._try_immediate_refresh_and_reconnect()
        except queue.Empty:
            pass
        if self.timer.running and rem == 0:
            self.timer.pause()
            self._log("finished")
        self._render_expiry()
        self.after(200, self._tick)

    def _try_immediate_refresh_and_reconnect(self):
        cid = self.twitch_client_id.get().strip()
        csec = self.twitch_client_secret.get().strip()
        rtok = self.twitch_refresh.get().strip()
        if not (cid and csec and rtok):
            self._log("no refresh credentials; please fill Client ID/Secret and Refresh Token")
            messagebox.showerror(APP_TITLE, "Login failed and no refresh credentials are set.")
            return
        try:
            res = http_post_form(TW_TOKEN, {
                "grant_type": "refresh_token",
                "refresh_token": rtok,
                "client_id": cid,
                "client_secret": csec
            })
            at = res.get("access_token", "")
            new_rt = res.get("refresh_token", rtok)
            ex = int(res.get("expires_in", 14400))
            if at:
                self.twitch_token.set(at)
                self.twitch_refresh.set(new_rt)
                self.cfg.twitch.oauth_token = at
                self.cfg.twitch.refresh_token = new_rt
                self.cfg.twitch.expires_at = int(time.time()) + ex
                self._save_config()
                self._render_expiry()
                self._log("token refreshed; reconnecting")
                if self.twitch_thread:
                    try:
                        self.twitch_thread.stop()
                    except Exception:
                        pass
                self.twitch_thread = TwitchChatThread(
                    self.twitch_channel.get().strip() or "MomoSeventh",
                    self.twitch_user.get().strip(),
                    at,
                    self.event_q
                )
                self.twitch_thread.start()
            else:
                self._log("refresh failed: no access_token")
        except Exception as e:
            self._log(f"refresh error: {e}")

    def _handle_sub(self, data: Dict[str, Any]):
        tier = int(data.get("tier", 1))
        count = int(data.get("count", 1))
        user = data.get("user") or "Unknown"
        gift = bool(data.get("gift", False))
        mins = self.minutes_t1.get() if tier == 1 else self.minutes_t2.get() if tier == 2 else self.minutes_t3.get()
        add = mins * 60 * max(1, count)
        self.timer.add_seconds(add)
        self._bump_subs(count)
        if gift:
            self._log(f"sub gift by {user} T{tier} x{count} -> +{mins * count}m")
        else:
            self._log(f"sub by {user} T{tier} x{count} -> +{mins * count}m")

    def _handle_bits(self, data: Dict[str, Any]):
        amount = int(data.get("amount", 0))
        user = data.get("user") or "Unknown"
        if amount < 0:
            return
        t1, t2, t3 = self.bits_t1.get(), self.bits_t2.get(), self.bits_t3.get()
        add_m = 0
        if amount >= max(t1, t2, t3):
            add_m = self.minutes_t3.get()
        elif amount >= max(t1, t2):
            add_m = self.minutes_t2.get()
        elif amount >= t1:
            add_m = self.minutes_t1.get()
        if add_m > 0:
            self.timer.add_seconds(add_m * 60)
            self._log(f"cheer {amount} by {user} -> +{add_m}m")
        else:
            self._log(f"cheer {amount} by {user} (below threshold)")

    def _ask_duration(self, prompt: str, default_str: str) -> Optional[int]:
        win = tk.Toplevel(self)
        win.title("Set Time")
        ttk.Label(win, text=prompt).grid(row=0, column=0, padx=8, pady=8)
        var = tk.StringVar(value=default_str)
        e = ttk.Entry(win, textvariable=var, width=16)
        e.grid(row=0, column=1, padx=8, pady=8)
        e.focus_set()
        result = {"val": None}

        def ok():
            secs = parse_duration(var.get())
            if secs is None:
                messagebox.showerror(APP_TITLE, "Enter HH:MM:SS, MM:SS, or seconds.")
                return
            result["val"] = secs
            win.destroy()

        ttk.Button(win, text="OK", command=ok).grid(row=1, column=0, columnspan=2, pady=8)
        win.grab_set()
        self.wait_window(win)
        return result["val"]

    def _log(self, msg: str):
        if NY_TZ:
            ts = datetime.now(NY_TZ).strftime("%I:%M:%S %p %Z")
        else:
            ts = time.strftime("%I:%M:%S %p")
        try:
            self.log.insert("end", f"[{ts}] {msg}\n")
            self.log.see("end")
        except Exception:
            pass

    def _set_status(self, msg: str):
        self.twitch_status.set(msg)
        self._log(f"[twitch] {msg}")

    def _render_expiry(self):
        exp = int(self.cfg.twitch.expires_at or 0)
        if exp > 0:
            left = max(0, exp - int(time.time()))
            self.expires_label.set(f"Expires in {left}s")
        else:
            self.expires_label.set("")

    def _save_oauth_fields(self):
        self.cfg.twitch.channel = self.twitch_channel.get().strip() or "MomoSeventh"
        self.cfg.twitch.bot_username = self.twitch_user.get().strip()
        self.cfg.twitch.oauth_token = self.twitch_token.get().strip()
        self.cfg.twitch.client_id = self.twitch_client_id.get().strip()
        self.cfg.twitch.client_secret = self.twitch_client_secret.get().strip()
        self.cfg.twitch.refresh_token = self.twitch_refresh.get().strip()
        self.cfg.twitch.auto_refresh = bool(self.auto_refresh_var.get())
        self._save_config()

    def _save_config(self):
        self.cfg.write_timer_file = bool(self.write_file_var.get())
        self.cfg.timer_path = self.timer_path_var.get()
        self.cfg.write_subs_file = bool(self.write_subs_file_var.get())
        self.cfg.subs_path = self.subs_path_var.get()
        self.cfg.total_subs = int(self.total_subs_var.get())
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(self.cfg.to_json(), f, indent=2)
        self.timer.save()

    def _load_config(self) -> AppConfig:
        if os.path.exists(CONFIG_FILE):
            try:
                return AppConfig.from_json(json.load(open(CONFIG_FILE, "r", encoding="utf-8")))
            except Exception:
                pass
        return AppConfig()

    def _on_close(self):
        try:
            self.timer.pause()
            self.timer.save()
            self._twitch_disconnect()
            self._stop_refresh_thread()
            self._save_config()
            self._log("paused on exit")
        finally:
            self.destroy()

    def _auto_connect_on_startup(self):
        user = self.twitch_user.get().strip()
        token = self.twitch_token.get().strip()
        if user and token:
            self._log("attempting auto-connect")
            self._twitch_connect(silent=True)
        else:
            self._log("auto-connect skipped: missing bot username or token")

    def _write_subs_file(self):
        if not self.write_subs_file_var.get():
            return
        try:
            with open(self.subs_path_var.get(), "w", encoding="utf-8") as f:
                f.write(str(int(self.total_subs_var.get())) + "\n")
        except Exception:
            pass

    def _bump_subs(self, n: int):
        self.total_subs_var.set(max(0, int(self.total_subs_var.get()) + int(n)))
        self.total_subs_entry.delete(0, "end")
        self.total_subs_entry.insert(0, str(self.total_subs_var.get()))
        self._write_subs_file()
        self._save_config()

    def _inc_subs(self, n: int):
        self._bump_subs(n)
        if n >= 0:
            self._log(f"manual subs +{n}")
        else:
            self._log(f"manual subs {n}")

    def _update_total_subs_from_entry(self):
        try:
            val = int(self.total_subs_entry.get().strip())
        except Exception:
            messagebox.showerror(APP_TITLE, "Enter a whole number for total subs.")
            return
        self.total_subs_var.set(max(0, val))
        self._write_subs_file()
        self._save_config()
        self._log(f"total subs set to {self.total_subs_var.get()}")


if __name__ == "__main__":
    app = App()
    app.mainloop()
