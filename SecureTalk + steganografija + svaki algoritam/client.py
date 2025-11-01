# client.py
import asyncio
import base64
import json
import queue
import threading
import uuid
import os
import subprocess
import sys
from datetime import datetime, timezone
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox

import websockets
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey

from stego import build_package, embed_bytes_into_image, extract_bytes_from_image, embed_file, extract_to_file, ALGORITHMS
from crypto_utils import encrypt_payload_aes_gcm, decrypt_payload_aes_gcm

SERVER_WS_TEMPLATE = "ws://{host}:{port}/ws"
CHUNK_SIZE = 128 * 1024  # 128 KB

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def _safe_filename(name: str) -> str:
    return os.path.basename(name)

class SecureTalkClient:
    def __init__(self, username: str, host: str = "127.0.0.1", port: int = 8765, room: str = "lobby"):
        self.username = username
        self.host = host
        self.port = port
        self.room = room or "lobby"

        # identity
        self.dh_priv = PrivateKey.generate()
        self.dh_pub = self.dh_priv.public_key
        self.sign_priv = SigningKey.generate()
        self.sign_pub = self.sign_priv.verify_key

        # peer state
        self.peers_dh = {}
        self.peers_sign = {}
        self.peer_boxes = {}
        self.username_to_uid = {}

        self.sync_send_q = queue.Queue()
        self.ws = None
        self.user_id = None

        # folders
        self.user_folder = os.path.join("users", self.username)
        self.received_folder = os.path.join(self.user_folder, "received")
        os.makedirs(self.received_folder, exist_ok=True)

        self.pending_files = {}

        # GUI
        self.root = tk.Tk()
        self.root.title(f"SecureTalk — {self.username}")
        self._build_gui()

        self.ws_thread = None

    # -------------------
    # Logging & chat UI
    # -------------------
    def _safe_ui_call(self, fn, *a, **kw):
        """Ensure UI call runs in main thread via root.after."""
        try:
            if threading.current_thread() is threading.main_thread():
                fn(*a, **kw)
            else:
                self.root.after(0, lambda: fn(*a, **kw))
        except Exception:
            # best-effort
            pass

    def _log(self, text: str):
        """Log to console and to the side Log panel (NOT in main chat)."""
        print(f"[CLIENT:{self.username}] {text}")
        # append to log_text in thread-safe manner
        self._safe_ui_call(self._append_log, text)

    def _append_log(self, text: str):
        try:
            self.log_text.config(state="normal")
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.log_text.insert("end", f"{ts} {text}\n")
            self.log_text.see("end")
            self.log_text.config(state="disabled")
        except Exception:
            pass

    def _append_chat(self, sender: str, content: str):
        """Append a chat message to the chat widget (thread-safe)."""
        def _do():
            try:
                self.chat.config(state="normal")
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.chat.insert("end", f"{ts} {sender}: {content}\n")
                self.chat.see("end")
                self.chat.config(state="disabled")
            except Exception:
                pass
        self._safe_ui_call(_do)

    # -------------------
    # GUI build
    # -------------------
    def _build_gui(self):
        frm_top = ttk.Frame(self.root, padding=8)
        frm_top.pack(fill="x")
        ttk.Label(frm_top, text=f"Korisnik: {self.username}").pack(side="left")
        self.room_var = tk.StringVar(value=self.room)
        ttk.Entry(frm_top, textvariable=self.room_var, width=20).pack(side="left", padx=8)
        ttk.Button(frm_top, text="Join sobu", command=self.join_room).pack(side="left")
        ttk.Button(frm_top, text="Osveži članove", command=self.refresh_members).pack(side="left", padx=6)

        frm_mid = ttk.Frame(self.root, padding=8)
        frm_mid.pack(fill="both", expand=True)

        # Left: chat area
        left = ttk.Frame(frm_mid)
        left.pack(side="left", fill="both", expand=True)

        self.chat = tk.Text(left, state="disabled", height=18, wrap="word")
        self.chat.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(left, command=self.chat.yview)
        self.chat.configure(yscrollcommand=sb.set)
        sb.pack(side="left", fill="y")

        # Right: controls + Log area
        right = ttk.Frame(frm_mid, width=300)
        right.pack(side="left", fill="y", padx=8)

        ttk.Button(right, text="Pošalji fajl (stego)", command=self.send_stego).pack(fill="x", pady=2)
        ttk.Button(right, text="Pošalji fajl (raw)", command=self.send_file_raw).pack(fill="x", pady=2)
        ttk.Button(right, text="Prikaži primljene", command=self.show_received_files).pack(fill="x", pady=6)

        # Log label and text area
        ttk.Label(right, text="Log:").pack(anchor="w", pady=(8,0))
        self.log_text = tk.Text(right, state="disabled", width=40, height=18, wrap="none")
        self.log_text.pack(fill="both", expand=False)
        log_sb = ttk.Scrollbar(right, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_sb.set)
        log_sb.pack(side="left", fill="y")

        frm_bottom = ttk.Frame(self.root, padding=8)
        frm_bottom.pack(fill="x")
        self.msg_var = tk.StringVar()
        ttk.Entry(frm_bottom, textvariable=self.msg_var, width=60).pack(side="left", padx=(0,6))
        ttk.Button(frm_bottom, text="Pošalji", command=self.send_message).pack(side="left")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # -------------------
    # crypto helpers
    # -------------------
    def _ensure_box(self, peer_id: str):
        if peer_id in self.peer_boxes:
            return self.peer_boxes[peer_id]
        pub_b64 = self.peers_dh.get(peer_id)
        if not pub_b64:
            return None
        try:
            pub = PublicKey(base64.b64decode(pub_b64))
            box = Box(self.dh_priv, pub)
            self.peer_boxes[peer_id] = box
            return box
        except Exception:
            return None

    def _encrypt_for(self, peer_id: str, plaintext: bytes) -> str:
        box = self._ensure_box(peer_id)
        if not box:
            raise RuntimeError("Peer key missing")
        nonce = os.urandom(24)
        ct = box.encrypt(plaintext, nonce)
        return base64.b64encode(ct).decode()

    def _decrypt_from(self, peer_id: str, b64cipher: str) -> bytes:
        box = self._ensure_box(peer_id)
        if not box:
            raise RuntimeError("No session with peer")
        ct = base64.b64decode(b64cipher.encode())
        pt = box.decrypt(ct)
        return pt

    # -------------------
    # websocket loop
    # -------------------
    async def _ws_loop(self):
        url = SERVER_WS_TEMPLATE.format(host=self.host, port=self.port)
        self._log(f"Connecting to {url} ...")
        async with websockets.connect(url, max_size=50_000_000) as ws:
            self.ws = ws
            msg = json.loads(await ws.recv())
            self.user_id = msg.get("user_id")
            self._log(f"• Povezano (user_id={self.user_id})")

            # register
            await ws.send(json.dumps({
                "type": "register",
                "username": self.username,
                "pub_dh": base64.b64encode(bytes(self.dh_pub)).decode(),
                "pub_sign": base64.b64encode(bytes(self.sign_pub)).decode()
            }))
            self._log("REGISTERING with server ...")

            await ws.send(json.dumps({"type": "join_room", "room": self.room}))
            self._log(f"Sent join_room '{self.room}'")

            loop = asyncio.get_event_loop()

            async def sender_task():
                while True:
                    payload = await loop.run_in_executor(None, self.sync_send_q.get)
                    try:
                        await ws.send(json.dumps(payload))
                    except Exception:
                        break

            async def receiver_task():
                while True:
                    raw = await ws.recv()
                    data = json.loads(raw)
                    await self._handle_server(data)

            await asyncio.gather(sender_task(), receiver_task())

    async def _handle_server(self, data: dict):
        t = data.get("type")
        if t == "room_joined":
            room = data.get("room")
            members = data.get("members", [])
            self.room = room
            self.username_to_uid.clear()
            for m in members:
                uid = m["user_id"]
                uname = m.get("username")
                if uname:
                    self.username_to_uid[uname] = uid
                if uid != self.user_id and m.get("pub_dh"):
                    self.peers_dh[uid] = m.get("pub_dh")
                    self.peers_sign[uid] = m.get("pub_sign")
                    self.peer_boxes.pop(uid, None)
            self._log(f"• Ušao si u sobu '{room}'. Članova: {len(members)}")
            self._log("Room joined: " + ", ".join([m.get("username") for m in members if m.get("username")]))

        elif t == "presence":
            ev = data.get("event")
            u = data.get("user", {})
            uid = u.get("user_id")
            uname = u.get("username")
            if ev == "join":
                if uname:
                    self.username_to_uid[uname] = uid
                if uid != self.user_id and u.get("pub_dh"):
                    self.peers_dh[uid] = u.get("pub_dh")
                    self.peers_sign[uid] = u.get("pub_sign")
                    self.peer_boxes.pop(uid, None)
                self._log(f"✅ {uname or uid[:6]} se priključio.")
            elif ev == "leave":
                if uname:
                    self.username_to_uid.pop(uname, None)
                self.peers_dh.pop(uid, None)
                self.peers_sign.pop(uid, None)
                self.peer_boxes.pop(uid, None)
                self._log(f"❌ {uname or uid[:6]} je napustio sobu.")

        elif t == "message":
            frm = data.get("from")
            cipher = data.get("cipher")
            try:
                pt = self._decrypt_from(frm, cipher)
                text = pt.decode("utf-8")
            except Exception:
                text = "⚠️ [Neuspešno dešifrovanje]"
            uname = next((n for n,u in self.username_to_uid.items() if u==frm), None)
            label = uname if uname else frm[:6]
            # chat message (goes to chat pane)
            self._append_chat(label, text)

        elif t == "file":
            frm = data.get("from")
            try:
                box = self._ensure_box(frm)
                if not box:
                    raise RuntimeError("Nema kripto sesije sa pošiljaocem")
                cipher_meta_b64 = data.get("cipher_meta")
                if not cipher_meta_b64:
                    raise RuntimeError("Nema meta podataka u poruci")
                meta_json = box.decrypt(base64.b64decode(cipher_meta_b64)).decode()
                meta = json.loads(meta_json)
                filename = _safe_filename(meta.get("filename", f"file_{now_iso()}"))

                msg_id = data.get("msg_id") or f"m_{uuid.uuid4().hex}"
                chunk_index = int(data.get("chunk_index", 0))
                chunk_total = int(data.get("chunk_total", 1))
                is_last = bool(data.get("is_last", chunk_index == chunk_total - 1))

                cipher_chunks = data.get("cipher_chunks", [])
                if not cipher_chunks:
                    raise RuntimeError("Nema chunkova u poruci")
                chunk_b64 = cipher_chunks[0]
                chunk_bytes = box.decrypt(base64.b64decode(chunk_b64))

                # store into received folder for the target user
                basepath = os.path.join(self.received_folder, f"recv_{filename}")
                base, ext = os.path.splitext(basepath)
                counter = 1
                final_tmp = basepath
                while os.path.exists(final_tmp) and (chunk_index == 0):
                    final_tmp = f"{base}_{counter}{ext}"
                    counter += 1

                # append chunk
                if (frm, msg_id) not in self.pending_files:
                    with open(final_tmp, "wb") as wf:
                        wf.write(chunk_bytes)
                    self.pending_files[(frm, msg_id)] = {"meta": meta, "path": final_tmp, "received": 1, "total": chunk_total}
                else:
                    entry = self.pending_files[(frm, msg_id)]
                    with open(entry["path"], "ab") as wf:
                        wf.write(chunk_bytes)
                    entry["received"] += 1

                self._log(f"Received file chunk meta from {frm} filename={filename} algorithm_hint={meta.get('algorithm', meta.get('algorithm_hint', ''))}")
                entry = self.pending_files.get((frm, msg_id))
                if is_last or (entry and entry["received"] >= entry["total"]):
                    entry = self.pending_files.pop((frm, msg_id), None)
                    if not entry:
                        self._log("Warning: entry missing at finalize")
                        return
                    final_path = entry["path"]
                    uname = next((n for n,u in self.username_to_uid.items() if u==frm), None)
                    self._log(f"📎 Kompletan fajl primljen od {uname or frm[:6]}: {final_path}")
                    # attempt extraction using hint from filename (first 3 chars) or meta
                    alg_hint = meta.get('algorithm') or meta.get('algorithm_hint')
                    fname = os.path.basename(final_path)
                    prefix = fname[:3].upper()
                    if not alg_hint and prefix in ALGORITHMS:
                        alg_hint = prefix
                    if alg_hint:
                        self._log(f"Attempting extraction with hinted algorithm: {alg_hint}")
                        try:
                            md_inner, payload_bytes = extract_bytes_from_image(final_path, algorithm=alg_hint)
                            self._log(f"🔍 Extraction succeeded with {alg_hint}. Metadata: {md_inner}")
                            # show a short chat/system message to user
                            self._append_chat("SYSTEM", f"Fajl '{os.path.basename(final_path)}' ekstraktovan ({md_inner.get('original_filename','?')})")
                        except Exception as e:
                            self._log(f"🔍 Nije pronađen stego paket u slici (ili greška): {e}")
                    else:
                        self._log("No algorithm hint available, attempting autodetect...")
                        try:
                            md_inner, payload_bytes = extract_bytes_from_image(final_path, algorithm=None)
                            self._log(f"🔍 Extraction autodetect succeeded. Metadata: {md_inner}")
                            self._append_chat("SYSTEM", f"Fajl '{os.path.basename(final_path)}' ekstraktovan (autodetect)")
                        except Exception as e:
                            self._log(f"🔍 Autodetect extraction failed: {e}")
            except Exception as e:
                self._log(f"⚠️ Primljen fajl - neuspešno dešifrovanje / greška: {e}")
                try:
                    self.root.after(50, lambda: messagebox.showerror('Primanje fajla', f'Greška pri primanju fajla: {e}'))
                except Exception:
                    pass

        elif t == "room_members":
            members = data.get("members", [])
            names = [m.get("username", m.get("user_id")[:6]) for m in members]
            self._log(f"• Članovi sobe ({data.get('room')}): {', '.join(names)}")

        elif t == "error":
            self._log(f"⚠️ Server error: {data.get('message')}")

    # -------------------
    # GUI actions
    # -------------------
    def join_room(self):
        room = self.room_var.get().strip() or "lobby"
        self.peers_dh.clear(); self.peers_sign.clear(); self.peer_boxes.clear(); self.username_to_uid.clear()
        self.sync_send_q.put({"type": "join_room", "room": room})
        self._log(f"• Tražim pristup sobi '{room}'...")

    def refresh_members(self):
        self.sync_send_q.put({"type": "room_members"})
        self._log("Zahtjev za članove sobe poslat serveru.")

    def send_message(self):
        msg = self.msg_var.get().strip()
        if not msg:
            return
        cipher_dict = {}
        for uname, uid in self.username_to_uid.items():
            if uid == self.user_id:
                continue
            try:
                cipher = self._encrypt_for(uid, msg.encode("utf-8"))
                cipher_dict[uid] = cipher
            except Exception:
                continue
        if not cipher_dict:
            self._log("⚠️ Nema drugih članova ili nema kripto ključeva.")
            return
        payload = {"type": "message", "cipher_dict": cipher_dict, "msg_id": str(uuid.uuid4())}
        # show in chat (sender)
        self._append_chat(self.username, msg)
        self.msg_var.set("")
        self.sync_send_q.put(payload)

    def choose_recipient_uid(self):
        others = [u for u in self.username_to_uid.keys() if u != self.username]
        if not others:
            messagebox.showerror('Greška', 'Nema drugih korisnika u rosteru.')
            return None
        dlg = tk.Toplevel(self.root)
        dlg.title('Izaberi primaoca')
        ttk.Label(dlg, text='Primatelj:').pack(padx=8, pady=(8,0))
        sel_var = tk.StringVar()
        comb = ttk.Combobox(dlg, textvariable=sel_var, values=others, state='readonly')
        comb.pack(padx=8, pady=8)
        comb.current(0)
        result = {'uid': None}
        def on_ok():
            result['uid'] = self.username_to_uid.get(sel_var.get())
            dlg.destroy()
        def on_cancel():
            dlg.destroy()
        btns = ttk.Frame(dlg)
        btns.pack(pady=(0,8))
        ttk.Button(btns, text='OK', command=on_ok).pack(side='left', padx=8)
        ttk.Button(btns, text='Cancel', command=on_cancel).pack(side='left', padx=8)
        self.root.wait_window(dlg)
        return result['uid']

    def send_file_raw(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        uid = self.choose_recipient_uid()
        if not uid:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            messagebox.showerror("Greška", str(e)); return
        box = self._ensure_box(uid)
        if not box:
            messagebox.showerror('Greška', 'Nemate kripto sesiju sa tim korisnikom.')
            return
        meta = {"filename": _safe_filename(os.path.basename(path))}
        cipher_meta = base64.b64encode(box.encrypt(json.dumps(meta).encode(), os.urandom(24))).decode()
        total = (len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE
        msg_id = uuid.uuid4().hex
        for i in range(total):
            start = i*CHUNK_SIZE
            chunk = data[start:start+CHUNK_SIZE]
            cipher_chunk = base64.b64encode(box.encrypt(chunk, os.urandom(24))).decode()
            payload = {
                "type": "file",
                "to": uid,
                "cipher_meta": cipher_meta,
                "cipher_chunks": [cipher_chunk],
                "msg_id": msg_id,
                "chunk_index": i,
                "chunk_total": total,
                "is_last": (i == total-1)
            }
            self.sync_send_q.put(payload)
        self._log(f"📎 Poslat raw fajl: {os.path.basename(path)} -> {uid} (chunks={total})")

    def send_stego(self):
        cover = filedialog.askopenfilename(title='Odaberi cover image', filetypes=[('PNG images', '*.png'), ('BMP images', '*.bmp')])
        if not cover:
            return
        infile = filedialog.askopenfilename(title='Odaberi fajl koji se skriva')
        if not infile:
            return
        uid = self.choose_recipient_uid()
        if not uid:
            return
        # choose algorithm
        algs = list(ALGORITHMS.keys())
        dlg = tk.Toplevel(self.root)
        dlg.title('Izaberi algoritam')
        var = tk.StringVar(value=algs[0])
        ttk.Label(dlg, text='Algoritam:').pack(padx=8, pady=(8,0))
        comb = ttk.Combobox(dlg, textvariable=var, values=algs, state='readonly')
        comb.pack(padx=8, pady=8)
        comb.current(0)
        encrypt_payload = tk.BooleanVar(value=False)
        ttk.Checkbutton(dlg, text='Encrypt payload (AES-GCM)', variable=encrypt_payload).pack(padx=8, pady=(0,8))
        pw_var = tk.StringVar()
        ttk.Label(dlg, text='Lozinka (ako enkriptovano):').pack(padx=8)
        ttk.Entry(dlg, textvariable=pw_var, show='*').pack(padx=8, pady=(0,8))
        res = {'ok': False}
        def on_ok():
            res['ok'] = True
            res['alg'] = var.get()
            res['encrypt'] = encrypt_payload.get()
            res['pw'] = pw_var.get()
            dlg.destroy()
        def on_cancel():
            dlg.destroy()
        btns = ttk.Frame(dlg); btns.pack(pady=(0,8))
        ttk.Button(btns, text='OK', command=on_ok).pack(side='left', padx=8)
        ttk.Button(btns, text='Cancel', command=on_cancel).pack(side='left')
        self.root.wait_window(dlg)
        if not res.get('ok'):
            return
        algorithm = res.get('alg')
        password = res.get('pw') if res.get('encrypt') else None

        # output image name: prefix algorithm (3 letters) + original cover basename
        out_img = os.path.join(self.user_folder, f"{algorithm[:3].upper()}{os.path.basename(cover)}")
        try:
            embed_file(cover, infile, out_img, algorithm=algorithm, encrypt_password=password, metadata_extra={'sender_id': self.username, 'algorithm': algorithm[:3].upper()})
        except Exception as e:
            messagebox.showerror('Greška pri kreiranju stego slike', str(e)); return

        try:
            with open(out_img, 'rb') as f:
                data = f.read()
        except Exception as e:
            messagebox.showerror('Greška', str(e)); return

        box = self._ensure_box(uid)
        if not box:
            messagebox.showerror('Greška', 'Nemate kripto sesiju sa tim korisnikom.')
            return

        meta = {'filename': _safe_filename(os.path.basename(out_img)), 'algorithm': algorithm[:3].upper()}
        cipher_meta = base64.b64encode(box.encrypt(json.dumps(meta).encode(), os.urandom(24))).decode()
        total = (len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE
        msg_id = uuid.uuid4().hex
        for i in range(total):
            start = i*CHUNK_SIZE
            chunk = data[start:start+CHUNK_SIZE]
            cipher_chunk = base64.b64encode(box.encrypt(chunk, os.urandom(24))).decode()
            payload = {
                "type": "file",
                "to": uid,
                "cipher_meta": cipher_meta,
                "cipher_chunks": [cipher_chunk],
                "msg_id": msg_id,
                "chunk_index": i,
                "chunk_total": total,
                "is_last": (i == total-1)
            }
            self.sync_send_q.put(payload)
        self._log(f"📎 Poslat stego fajl: {os.path.basename(out_img)} -> {uid} (chunks={total})")

    # -------------------
    # received files UI
    # -------------------
    def show_received_files(self):
        try:
            files = sorted(os.listdir(self.received_folder))
        except Exception:
            files = []
        dlg = tk.Toplevel(self.root)
        dlg.title('Primljeni fajlovi')
        lb = tk.Listbox(dlg, width=80)
        lb.pack(side='left', fill='both', expand=True, padx=(8,0), pady=8)
        for f in files:
            lb.insert('end', f)
        sb = ttk.Scrollbar(dlg, command=lb.yview)
        lb.configure(yscrollcommand=sb.set)
        sb.pack(side='left', fill='y', padx=(0,8), pady=8)
        btn_frame = ttk.Frame(dlg); btn_frame.pack(fill='x', pady=(0,8))
        def open_selected():
            sel = lb.curselection()
            if not sel: return
            fname = lb.get(sel[0]); path = os.path.join(self.received_folder, fname)
            self.root.after(10, lambda: self._open_file(path))
        def extract_selected():
            sel = lb.curselection()
            if not sel: return
            fname = lb.get(sel[0]); path = os.path.join(self.received_folder, fname)
            self.root.after(10, lambda: self._try_extract_stego(path))
        ttk.Button(btn_frame, text='Open', command=open_selected).pack(side='left', padx=8)
        ttk.Button(btn_frame, text='Extract stego', command=extract_selected).pack(side='left')

    def _open_file(self, path):
        try:
            if os.name == 'nt':
                os.startfile(path)
            elif sys.platform == 'darwin':
                subprocess.call(['open', path])
            else:
                subprocess.call(['xdg-open', path])
        except Exception as e:
            try:
                messagebox.showerror('Open failed', str(e))
            except Exception:
                self._log(f"[Open failed] {e}")

    def _try_extract_stego(self, path):
        low = path.lower()
        if not low.endswith(('.png', '.bmp')):
            messagebox.showinfo('Nije image', 'Odabrani fajl nije PNG/BMP slika sa stego podacima.')
            return
        # extract hint from filename (first 3 characters)
        fname = os.path.basename(path)
        prefix = fname[:3].upper()
        alg_hint = prefix if prefix in ALGORITHMS else None
        if alg_hint:
            self._log(f"Extract requested; using filename hint: {alg_hint}")
        else:
            self._log("Extract requested; no filename hint found, will attempt autodetect")
        try:
            md_inner, payload_bytes = extract_bytes_from_image(path, algorithm=alg_hint)
        except Exception as e:
            messagebox.showerror('Extract failed', f'Neuspeo pokušaj ekstrakcije: {e}')
            return
        inner_name = _safe_filename(md_inner.get('original_filename', 'embedded.bin'))
        inner_path = os.path.join(self.received_folder, f"inner_{inner_name}")
        with open(inner_path, 'wb') as f:
            f.write(payload_bytes)
        if md_inner.get('crypto') == 'AES-GCM':
            pw = simpledialog.askstring('Decrypt hidden payload', f"Unesite lozinku za '{inner_name}':", show='*')
            if not pw:
                return
            try:
                salt = base64.b64decode(md_inner['salt'])
                iv = base64.b64decode(md_inner['iv'])
                pt = decrypt_payload_aes_gcm(payload_bytes, pw, salt, iv)
                final_name = _safe_filename(md_inner.get('original_filename', 'extracted.bin'))
                final_path = os.path.join(self.received_folder, final_name)
                with open(final_path, 'wb') as f:
                    f.write(pt)
                try:
                    txt = pt.decode('utf-8')
                    messagebox.showinfo('Hidden message decrypted', f'Decrypted and saved to: {final_path}\n\n{txt}')
                except Exception:
                    messagebox.showinfo('Hidden message decrypted', f'Decrypted and saved to: {final_path}')
            except Exception as e:
                messagebox.showerror('Decrypt failed', str(e))
        else:
            try:
                txt = payload_bytes.decode('utf-8')
                messagebox.showinfo('Hidden message', f'Poruka: {txt}')
            except Exception:
                messagebox.showinfo('Hidden payload', f'Payload saved to: {inner_path}')

    def on_close(self):
        try:
            self.sync_send_q.put({"type": "leave_room"})
        except Exception:
            pass
        self.root.destroy()

    def start_ws_thread(self):
        def _thread_run():
            asyncio.run(self._ws_loop())
        self.ws_thread = threading.Thread(target=_thread_run, daemon=True)
        self.ws_thread.start()

    def run(self):
        self.start_ws_thread()
        self.root.mainloop()

# convenience
def run_gui(username: str, host: str = "127.0.0.1", port: int = 8765):
    client = SecureTalkClient(username, host, port)
    client.run()

if __name__ == "__main__":
    uname = simpledialog.askstring("SecureTalk", "Unesite username:") or f"user_{uuid.uuid4().hex[:6]}"
    room = simpledialog.askstring("Soba", "Unesite sobu (prazno = lobby)") or "lobby"
    c = SecureTalkClient(uname, "127.0.0.1", 8765, room)
    c.run()
