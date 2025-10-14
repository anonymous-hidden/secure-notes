# SecureNotes - full application
# Save as e.g. client_app.py and run with Python 3.8+
# Requires: cryptography, pillow
# pip install cryptography pillow

import os
import json
import base64
import hashlib
import hmac
import secrets
import time
import re
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext, colorchooser, filedialog
import tkinter.font as tkfont
from cryptography.fernet import Fernet, InvalidToken

# Pillow (for robust image loading/scaling)
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

# ---------------- CONFIG ----------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_PATH = os.path.join(SCRIPT_DIR, "users.json")
SALT_BYTES = 16
ENC_SALT_BYTES = 16
PBKDF2_ITERATIONS = 300_000
MIN_PASSWORD_LEN = 12
AUTOSAVE_INTERVAL = 30  # seconds

# ---------------- UTILITIES ----------------
def load_users():
    if os.path.exists(USERS_PATH):
        try:
            with open(USERS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_users(users):
    with open(USERS_PATH, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)

USERS = load_users()  # username -> {"pw_hash":..., "enc_salt": base64...}

def now_ts():
    return int(time.time())

# ---------------- PASSWORD / KEY ----------------
def password_hash(password: str) -> str:
    salt = secrets.token_bytes(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return base64.b64encode(salt + dk).decode("utf-8")

def password_verify(password: str, stored: str) -> bool:
    try:
        raw = base64.b64decode(stored)
        salt = raw[:SALT_BYTES]
        stored_dk = raw[SALT_BYTES:]
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
        return hmac.compare_digest(dk, stored_dk)
    except Exception:
        return False

def derive_fernet_key(password: str, enc_salt: bytes) -> bytes:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), enc_salt, PBKDF2_ITERATIONS, dklen=32)
    return base64.urlsafe_b64encode(dk)

def safe_username(username: str) -> str:
    return "".join(c for c in username if c.isalnum() or c in "-_") or "user"

def notes_path(username: str) -> str:
    return os.path.join(SCRIPT_DIR, f"{safe_username(username)}.notes.enc")

def load_notes(username: str, key: bytes) -> str:
    p = notes_path(username)
    if not os.path.exists(p):
        return ""
    cipher = Fernet(key)
    with open(p, "rb") as f:
        data = f.read()
    return cipher.decrypt(data).decode("utf-8")

def save_notes(username: str, key: bytes, content: str):
    cipher = Fernet(key)
    with open(notes_path(username), "wb") as f:
        f.write(cipher.encrypt(content.encode("utf-8")))

def password_strength_ok(pw: str):
    if len(pw) < MIN_PASSWORD_LEN:
        return False, f"Password must be at least {MIN_PASSWORD_LEN} chars."
    classes = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw)
    ])
    if classes < 3:
        return False, "Password must include at least 3 of: lowercase, uppercase, digits, symbols."
    return True, ""

# ---------------- GUI SETUP ----------------
root = tk.Tk()
root.title("SecureNotes")
root.geometry("1000x700")
root.minsize(800, 500)
root.configure(bg="#121212")

current_user = None
current_key = None
autosave_on = True
background_image_obj = None   # stores PIL ImageTk for resizing
background_source_path = None

# THEMES
THEMES = {
    "dark": {"bg": "#121212", "fg": "#ffffff", "entry_bg": "#1e1e1e", "btn_bg": "#2f7a2f"},
    "light": {"bg": "#ffffff", "fg": "#000000", "entry_bg": "#f5f5f5", "btn_bg": "#2f7a2f"},
}
current_theme = "dark"

# FRAMES (login, register, notes)
frames = {}
for name in ("login", "register", "notes"):
    f = tk.Frame(root, bg=THEMES[current_theme]["bg"])
    f.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.95, relheight=0.95)
    frames[name] = f

def show_frame(key):
    for f in frames.values():
        f.lower()
    frames[key].lift()

# ---------------- LOGIN FRAME ----------------
login_frame = frames["login"]

tk.Label(login_frame, text="🔐 SecureNotes", font=("Segoe UI", 28, "bold"),
         bg=THEMES[current_theme]["bg"], fg=THEMES[current_theme]["fg"]).pack(pady=(30, 6))

tk.Label(login_frame, text="Username", bg=THEMES[current_theme]["bg"], fg=THEMES[current_theme]["fg"]).pack()
entry_login_user = tk.Entry(login_frame, font=("Segoe UI", 12),
                            bg=THEMES[current_theme]["entry_bg"], fg=THEMES[current_theme]["fg"],
                            insertbackground=THEMES[current_theme]["fg"], width=30)
entry_login_user.pack(pady=6)

tk.Label(login_frame, text="Password", bg=THEMES[current_theme]["bg"], fg=THEMES[current_theme]["fg"]).pack()
entry_login_pass = tk.Entry(login_frame, font=("Segoe UI", 12), show="*",
                            bg=THEMES[current_theme]["entry_bg"], fg=THEMES[current_theme]["fg"],
                            insertbackground=THEMES[current_theme]["fg"], width=30)
entry_login_pass.pack(pady=6)

def attempt_login():
    global current_user, current_key
    username = entry_login_user.get().strip()
    password = entry_login_pass.get()
    if not username or not password:
        messagebox.showwarning("Missing fields", "Please enter both username and password.")
        return
    user = USERS.get(username)
    if not user:
        messagebox.showerror("Login failed", "User not found.")
        return
    if not password_verify(password, user.get("pw_hash", "")):
        messagebox.showerror("Login failed", "Incorrect password.")
        return
    # derive key
    enc_salt = base64.b64decode(user["enc_salt"])
    key = derive_fernet_key(password, enc_salt)
    # Try decrypting (just to confirm)
    try:
        _ = load_notes(username, key)
    except InvalidToken:
        messagebox.showerror("Login failed", "Could not decrypt notes. Wrong password or corrupted data.")
        return
    current_user = username
    current_key = key
    entry_login_user.delete(0, tk.END)
    entry_login_pass.delete(0, tk.END)
    load_notes_screen()
    show_frame("notes")

tk.Button(login_frame, text="Login", bg=THEMES[current_theme]["btn_bg"], fg="white",
          command=attempt_login, font=("Segoe UI", 12, "bold"), width=22).pack(pady=14)

def goto_register():
    entry_login_user.delete(0, tk.END)
    entry_login_pass.delete(0, tk.END)
    show_frame("register")

tk.Button(login_frame, text="Create account", bg=THEMES[current_theme]["bg"],
          fg="#1e90ff", relief="flat", command=goto_register).pack()

# ---------------- REGISTER FRAME ----------------
register_frame = frames["register"]

tk.Label(register_frame, text="Create Account", font=("Segoe UI", 24, "bold"),
         bg=THEMES[current_theme]["bg"], fg=THEMES[current_theme]["fg"]).pack(pady=(20, 10))

tk.Label(register_frame, text="Username", bg=THEMES[current_theme]["bg"], fg=THEMES[current_theme]["fg"]).pack()
entry_reg_user = tk.Entry(register_frame, font=("Segoe UI", 12),
                          bg=THEMES[current_theme]["entry_bg"], fg=THEMES[current_theme]["fg"],
                          insertbackground=THEMES[current_theme]["fg"], width=30)
entry_reg_user.pack(pady=6)

tk.Label(register_frame, text="Password", bg=THEMES[current_theme]["bg"], fg=THEMES[current_theme]["fg"]).pack()
entry_reg_pass = tk.Entry(register_frame, font=("Segoe UI", 12), show="*",
                          bg=THEMES[current_theme]["entry_bg"], fg=THEMES[current_theme]["fg"],
                          insertbackground=THEMES[current_theme]["fg"], width=30)
entry_reg_pass.pack(pady=6)

tk.Label(register_frame, text="Confirm Password", bg=THEMES[current_theme]["bg"], fg=THEMES[current_theme]["fg"]).pack()
entry_reg_confirm = tk.Entry(register_frame, font=("Segoe UI", 12), show="*",
                             bg=THEMES[current_theme]["entry_bg"], fg=THEMES[current_theme]["fg"],
                             insertbackground=THEMES[current_theme]["fg"], width=30)
entry_reg_confirm.pack(pady=6)

def attempt_register():
    username = entry_reg_user.get().strip()
    pw = entry_reg_pass.get()
    confirm = entry_reg_confirm.get()
    if not username or not pw or not confirm:
        messagebox.showwarning("Missing", "Please complete all fields.")
        return
    if username in USERS:
        messagebox.showerror("Error", "Username already exists.")
        return
    if pw != confirm:
        messagebox.showerror("Error", "Passwords do not match.")
        return
    ok, msg = password_strength_ok(pw)
    if not ok:
        messagebox.showerror("Weak password", msg)
        return
    # create user
    pw_hash = password_hash(pw)
    enc_salt = secrets.token_bytes(ENC_SALT_BYTES)
    USERS[username] = {"pw_hash": pw_hash, "enc_salt": base64.b64encode(enc_salt).decode("utf-8")}
    save_users(USERS)
    messagebox.showinfo("Success", f"Account {username} created. You may now login.")
    entry_reg_user.delete(0, tk.END)
    entry_reg_pass.delete(0, tk.END)
    entry_reg_confirm.delete(0, tk.END)
    show_frame("login")

tk.Button(register_frame, text="Register", bg=THEMES[current_theme]["btn_bg"], fg="white",
          command=attempt_register, font=("Segoe UI", 12, "bold"), width=22).pack(pady=12)

tk.Button(register_frame, text="Back to login", bg=THEMES[current_theme]["bg"],
          fg="#1e90ff", relief="flat", command=lambda: show_frame("login")).pack()

# ---------------- NOTES FRAME & UI ----------------
notes_frame = frames["notes"]

# Top bar
top_bar = tk.Frame(notes_frame, bg="#1e1e1e")
top_bar.pack(fill="x")

lbl_signed_in = tk.Label(top_bar, text="", bg="#1e1e1e", fg="white", font=("Segoe UI", 11, "bold"))
lbl_signed_in.pack(side="left", padx=10, pady=6)

btn_save = tk.Button(top_bar, text="💾 Save", bg=THEMES[current_theme]["btn_bg"], fg="white",
                     width=8)
btn_save.pack(side="left", padx=6)

btn_settings = tk.Button(top_bar, text="⚙️ Settings", bg=THEMES[current_theme]["btn_bg"], fg="white", width=9)
btn_settings.pack(side="left", padx=6)

btn_logout = tk.Button(top_bar, text="Logout", bg="#d9534f", fg="white", width=8)
btn_logout.pack(side="right", padx=10)

def do_logout():
    global current_user, current_key
    # clear state
    current_user = None
    current_key = None
    txt_notes.delete("1.0", tk.END)
    show_frame("login")
btn_logout.config(command=do_logout)

# Sidebar (tools)
sidebar = tk.Frame(notes_frame, width=170, bg="#1e1e1e")
sidebar.pack(side="left", fill="y", padx=(6,0), pady=6)

tk.Label(sidebar, text="Tools", bg="#1e1e1e", fg="white", font=("Segoe UI", 12, "bold")).pack(pady=(8,6))

# Font & size controls and others
fonts_list = ["Segoe UI", "Arial", "Courier", "Times New Roman", "Verdana",
              "Tahoma", "Comic Sans MS", "Georgia", "Impact", "Lucida Console"]
font_var = tk.StringVar(value="Segoe UI")
size_var = tk.IntVar(value=12)

tk.Label(sidebar, text="Font", bg="#1e1e1e", fg="white").pack(padx=8, anchor="w")
font_combo = ttk.Combobox(sidebar, values=fonts_list, textvariable=font_var, state="readonly")
font_combo.pack(fill="x", padx=8, pady=(0,6))
font_combo.set("Segoe UI")

tk.Label(sidebar, text="Size", bg="#1e1e1e", fg="white").pack(padx=8, anchor="w")
size_combo = ttk.Combobox(sidebar, values=[8,9,10,11,12,14,16,18,20,24,28,32,36,40], textvariable=size_var, state="readonly")
size_combo.pack(fill="x", padx=8, pady=(0,6))
size_combo.set(12)

# Text area (center)
txt_container = tk.Frame(notes_frame, bg=THEMES[current_theme]["bg"])
txt_container.pack(fill="both", expand=True, padx=6, pady=6)

# background label for image (placed behind text widget)
bg_label = tk.Label(txt_container)
bg_label.place(relx=0, rely=0, relwidth=1, relheight=1)

# text widget with scroll
text_frame = tk.Frame(txt_container)
text_frame.pack(fill="both", expand=True)

txt_notes = scrolledtext.ScrolledText(text_frame, wrap="word", undo=True)
txt_notes.pack(fill="both", expand=True)

# ---------------- TAGS / FORMATTING ----------------
def configure_tags_from_current_font():
    # Build tag fonts based on the current widget font (so tags match family/size)
    base_font = tkfont.Font(font=txt_notes.cget("font"))
    # Bold
    bf = tkfont.Font(family=base_font.actual()["family"], size=base_font.actual()["size"], weight="bold")
    txt_notes.tag_configure("bold", font=bf)
    # Italic
    itf = tkfont.Font(family=base_font.actual()["family"], size=base_font.actual()["size"], slant="italic")
    txt_notes.tag_configure("italic", font=itf)
    # Underline
    uf = tkfont.Font(family=base_font.actual()["family"], size=base_font.actual()["size"], underline=1)
    txt_notes.tag_configure("underline", font=uf)
    # Strike
    sf = tkfont.Font(family=base_font.actual()["family"], size=base_font.actual()["size"], overstrike=1)
    txt_notes.tag_configure("strike", font=sf)
    # Color tag default (color is set dynamically)
    txt_notes.tag_configure("color")  # color will be configured when used

# initial font config
def apply_font_to_widget():
    family = font_var.get()
    size = int(size_var.get())
    txt_notes.config(font=(family, size))
    configure_tags_from_current_font()

# bind font/size changes
def on_font_change(event=None):
    apply_font_to_widget()

font_combo.bind("<<ComboboxSelected>>", on_font_change)
size_combo.bind("<<ComboboxSelected>>", on_font_change)

apply_font_to_widget()

# robust toggle_tag: apply to selection or current word
def toggle_tag(tag_name):
    try:
        start = txt_notes.index("sel.first")
        end = txt_notes.index("sel.last")
    except tk.TclError:
        start = txt_notes.index("insert wordstart")
        end = txt_notes.index("insert wordend")
    # If tag present at start, remove from range
    if tag_name in txt_notes.tag_names(start):
        txt_notes.tag_remove(tag_name, start, end)
    else:
        txt_notes.tag_add(tag_name, start, end)

# color change (selection or word)
def change_text_color():
    col = colorchooser.askcolor()[1]
    if not col:
        return
    try:
        start = txt_notes.index("sel.first")
        end = txt_notes.index("sel.last")
    except tk.TclError:
        start = txt_notes.index("insert wordstart")
        end = txt_notes.index("insert wordend")
    tag_name = f"color_{col}"
    # configure tag if not exists
    if tag_name not in txt_notes.tag_names():
        txt_notes.tag_configure(tag_name, foreground=col)
    # apply
    # toggle: if the same color already applied, remove; else set
    if tag_name in txt_notes.tag_names(start):
        txt_notes.tag_remove(tag_name, start, end)
    else:
        # remove any other color tags in range (so color replaces previous)
        # collect color tags
        for t in txt_notes.tag_names():
            if t.startswith("color_"):
                try:
                    txt_notes.tag_remove(t, start, end)
                except Exception:
                    pass
        txt_notes.tag_add(tag_name, start, end)

# highlight (background)
def change_highlight_color():
    col = colorchooser.askcolor()[1]
    if not col:
        return
    try:
        start = txt_notes.index("sel.first")
        end = txt_notes.index("sel.last")
    except tk.TclError:
        start = txt_notes.index("insert wordstart")
        end = txt_notes.index("insert wordend")
    tag_name = f"hcolor_{col}"
    if tag_name not in txt_notes.tag_names():
        txt_notes.tag_configure(tag_name, background=col)
    # remove other highlight tags
    for t in txt_notes.tag_names():
        if t.startswith("hcolor_"):
            txt_notes.tag_remove(t, start, end)
    txt_notes.tag_add(tag_name, start, end)

# insert bullet
def insert_bullet_at_cursor():
    txt_notes.insert("insert", "• ")

# numbered insert: determine last number and increment
def insert_numbered_at_cursor():
    # find last numbered line anywhere in document (not just before cursor)
    full = txt_notes.get("1.0", "end-1c").splitlines()
    last_num = 0
    for line in full:
        m = re.match(r'^\s*(\d+)\.', line)
        if m:
            try:
                n = int(m.group(1))
                if n > last_num:
                    last_num = n
            except:
                pass
    next_num = last_num + 1
    txt_notes.insert("insert", f"{next_num}. ")

# strikethrough
def toggle_strike():
    toggle_tag("strike")

# ---------------- Sidebar buttons ----------------
btn_bold = tk.Button(sidebar, text="Bold", command=lambda: toggle_tag("bold"), bg="#2f7a2f", fg="white")
btn_bold.pack(fill="x", padx=8, pady=4)

btn_italic = tk.Button(sidebar, text="Italic", command=lambda: toggle_tag("italic"), bg="#2f7a2f", fg="white")
btn_italic.pack(fill="x", padx=8, pady=4)

btn_underline = tk.Button(sidebar, text="Underline", command=lambda: toggle_tag("underline"), bg="#2f7a2f", fg="white")
btn_underline.pack(fill="x", padx=8, pady=4)

btn_strike = tk.Button(sidebar, text="Strike", command=toggle_strike, bg="#2f7a2f", fg="white")
btn_strike.pack(fill="x", padx=8, pady=4)

btn_color = tk.Button(sidebar, text="Text Color", command=change_text_color, bg="#2f7a2f", fg="white")
btn_color.pack(fill="x", padx=8, pady=6)

btn_hcolor = tk.Button(sidebar, text="Highlight", command=change_highlight_color, bg="#2f7a2f", fg="white")
btn_hcolor.pack(fill="x", padx=8, pady=6)

btn_font = tk.Button(sidebar, text="Apply Font", command=on_font_change, bg="#2f7a2f", fg="white")
btn_font.pack(fill="x", padx=8, pady=6)

btn_bullet = tk.Button(sidebar, text="• Bullet", command=insert_bullet_at_cursor, bg="#2f7a2f", fg="white")
btn_bullet.pack(fill="x", padx=8, pady=4)

btn_number = tk.Button(sidebar, text="Number", command=insert_numbered_at_cursor, bg="#2f7a2f", fg="white")
btn_number.pack(fill="x", padx=8, pady=4)

# small spacer then autosave toggle in sidebar
tk.Label(sidebar, text="", bg="#1e1e1e").pack(pady=4)
def toggle_autosave_button():
    global autosave_on
    autosave_on = not autosave_on
    btn_autosave.config(text=f"Autosave: {'ON' if autosave_on else 'OFF'}")
btn_autosave = tk.Button(sidebar, text=f"Autosave: {'ON' if autosave_on else 'OFF'}", command=toggle_autosave_button, bg="#2f7a2f", fg="white")
btn_autosave.pack(fill="x", padx=8, pady=6)

# ---------------- BACKGROUND IMAGE support ----------------
def set_background_image(path=None):
    """
    Set background image from path (if given) or ask file dialog.
    Image is scaled to text area, preserving aspect ratio.
    """
    global background_image_obj, background_source_path
    if path is None:
        p = filedialog.askopenfilename(title="Choose background image",
                                       filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.gif;*.bmp"), ("All files", "*.*")])
        if not p:
            return
        path = p
    if not os.path.exists(path):
        messagebox.showerror("Error", "File not found.")
        return
    background_source_path = path

    # load (prefer PIL for scaling), else try PhotoImage (limited formats)
    try:
        if PIL_AVAILABLE:
            pil_img = Image.open(path)
            # resize to text area size
            w = max(200, txt_notes.winfo_width() or 800)
            h = max(200, txt_notes.winfo_height() or 600)
            pil_img = pil_img.convert("RGBA")
            pil_img.thumbnail((w, h), Image.LANCZOS)
            background_image_obj = ImageTk.PhotoImage(pil_img)
            bg_label.config(image=background_image_obj)
            bg_label.image = background_image_obj
            bg_label.lift()  # bring bg label forward
            bg_label.place(relx=0, rely=0, relwidth=1, relheight=1)
            bg_label.lower()  # send to back
        else:
            img = tk.PhotoImage(file=path)  # may fail for jpeg
            background_image_obj = img
            bg_label.config(image=img)
            bg_label.image = img
            bg_label.place(relx=0, rely=0, relwidth=1, relheight=1)
            bg_label.lower()
    except Exception as e:
        messagebox.showerror("Background error", f"Failed to load image:\n{e}")
        
# keep background scaled on resize
def on_text_resize(event):
    if not background_source_path:
        return
    try:
        if PIL_AVAILABLE:
            pil_img = Image.open(background_source_path).convert("RGBA")
            w = max(200, txt_notes.winfo_width() or 800)
            h = max(200, txt_notes.winfo_height() or 600)
            pil_img.thumbnail((w, h), Image.LANCZOS)
            img_tk = ImageTk.PhotoImage(pil_img)
            global background_image_obj
            background_image_obj = img_tk
            bg_label.config(image=img_tk)
            bg_label.image = img_tk
            bg_label.lower()
        else:
            # PhotoImage doesn't support dynamic resizing; do nothing
            pass
    except Exception:
        pass

# bind resize events for accurate background scaling
txt_notes.bind("<Configure>", on_text_resize)
root.bind("<Configure>", on_text_resize)

# ---------------- SETTINGS WINDOW ----------------
def open_settings():
    if not current_user:
        return
    s = tk.Toplevel(root)
    s.title("Settings")
    s.geometry("420x420")
    s.configure(bg="#222")

    tk.Label(s, text=f"Settings — {current_user}", bg="#222", fg="white", font=("Segoe UI", 14, "bold")).pack(pady=8)

    # Change username
    def change_username():
        newname = simpledialog.askstring("Change username", "Enter new username:", parent=s)
        if not newname:
            return
        newname = newname.strip()
        if not newname:
            return
        if newname in USERS:
            messagebox.showerror("Error", "Username already exists", parent=s)
            return
        # rename entry in USERS and rename notes file if exists
        USERS[newname] = USERS.pop(current_user)
        old_path = notes_path(current_user)
        new_path = notes_path(newname)
        if os.path.exists(old_path):
            os.rename(old_path, new_path)
        save_users(USERS)
        # update current_user
        nonlocal_current = globals()
        nonlocal_current['current_user'] = newname
        lbl_signed_in.config(text=f"Signed in as: {newname}")
        messagebox.showinfo("Success", f"Username changed to {newname}", parent=s)

    tk.Button(s, text="Change username", bg="#2f7a2f", fg="white", command=change_username).pack(fill="x", padx=20, pady=6)

    # Change password (must re-encrypt notes with new key)
    def change_password():
        oldpw = simpledialog.askstring("Current password", "Enter current password:", show="*", parent=s)
        if not oldpw:
            return
        if not password_verify(oldpw, USERS[current_user]["pw_hash"]):
            messagebox.showerror("Error", "Incorrect current password", parent=s)
            return
        newpw = simpledialog.askstring("New password", "Enter new password:", show="*", parent=s)
        if not newpw:
            return
        confirm = simpledialog.askstring("Confirm new password", "Confirm new password:", show="*", parent=s)
        if newpw != confirm:
            messagebox.showerror("Error", "Passwords do not match", parent=s)
            return
        ok, msg = password_strength_ok(newpw)
        if not ok:
            messagebox.showerror("Weak password", msg, parent=s)
            return
        # decrypt existing notes with current_key, then re-encrypt with new key
        try:
            current_content = load_notes(current_user, current_key)
        except Exception:
            current_content = txt_notes.get("1.0", "end-1c")
        # create new salt and hash
        new_pw_hash = password_hash(newpw)
        new_enc_salt = secrets.token_bytes(ENC_SALT_BYTES)
        new_key = derive_fernet_key(newpw, new_enc_salt)
        # save notes with new key
        save_notes(current_user, new_key, current_content)
        # update USERS
        USERS[current_user]["pw_hash"] = new_pw_hash
        USERS[current_user]["enc_salt"] = base64.b64encode(new_enc_salt).decode("utf-8")
        save_users(USERS)
        # update current_key in memory
        globals()['current_key'] = new_key
        messagebox.showinfo("Success", "Password changed and notes re-encrypted.", parent=s)

    tk.Button(s, text="Change password", bg="#2f7a2f", fg="white", command=change_password).pack(fill="x", padx=20, pady=6)

    # Delete account
    def delete_account():
        answer = messagebox.askyesno("Delete account", f"Are you sure you want to permanently delete {current_user}? This cannot be undone.", parent=s)
        if not answer:
            return
        # remove note file
        p = notes_path(current_user)
        if os.path.exists(p):
            os.remove(p)
        # remove user entry
        if current_user in USERS:
            USERS.pop(current_user)
            save_users(USERS)
        # clear state and close settings
        globals()['current_user'] = None
        globals()['current_key'] = None
        txt_notes.delete("1.0", "end")
        messagebox.showinfo("Deleted", "Account deleted.", parent=s)
        s.destroy()
        show_frame("login")
    tk.Button(s, text="Delete account", bg="#d9534f", fg="white", command=delete_account).pack(fill="x", padx=20, pady=6)

    # Change background image
    tk.Button(s, text="Change background image", bg="#2f7a2f", fg="white", command=lambda: set_background_image_dialog(s)).pack(fill="x", padx=20, pady=6)

    # Close
    tk.Button(s, text="Close", bg="#555", fg="white", command=s.destroy).pack(fill="x", padx=20, pady=12)

def set_background_image_dialog(parent=None):
    set_background_image()

btn_settings.config(command=open_settings)

# ---------------- SAVE / LOAD integration ----------------
def load_notes_screen():
    """
    Load notes for current_user into text widget and refresh UI
    """
    if not current_user or not current_key:
        return
    lbl_signed_in.config(text=f"Signed in as: {current_user}")
    try:
        content = load_notes(current_user, current_key)
    except InvalidToken:
        # Key mismatch / corrupted => clear and warn
        messagebox.showerror("Decryption error", "Could not decrypt notes with provided key. The file may be corrupted or password incorrect.")
        content = ""
    txt_notes.delete("1.0", "end")
    txt_notes.insert("1.0", content)
    apply_font_to_widget()

# save button hooking
def do_save_now():
    if not current_user or not current_key:
        messagebox.showwarning("Not signed in", "You must be signed in to save notes.")
        return
    content = txt_notes.get("1.0", "end-1c")
    save_notes(current_user, current_key, content)
    # Optionally show a small feedback
    # messagebox.showinfo("Saved", "Notes saved.")

btn_save.config(command=do_save_now)

# ---------------- AUTOSAVE LOOP ----------------
def autosave_loop():
    try:
        if autosave_on and current_user and current_key:
            content = txt_notes.get("1.0", "end-1c")
            save_notes(current_user, current_key, content)
    finally:
        root.after(AUTOSAVE_INTERVAL * 1000, autosave_loop)

root.after(AUTOSAVE_INTERVAL * 1000, autosave_loop)

# ---------------- BACKGROUND IMAGE helper (file dialog wrapper) ----------------
def set_background_image():
    # wrapper used by settings dialog / sidebar if needed
    set_background_image_dialog()

def set_background_image_dialog():
    # open file dialog and call set_background_image(path)
    p = filedialog.askopenfilename(title="Choose background image",
                                   filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.gif;*.bmp"), ("All files", "*.*")])
    if p:
        set_background_image(path=p)

# ---------------- FINAL START ----------------
# show login first
show_frame("login")

# ensure tags are configured when app starts
configure_tags_from_current_font()

# handle window close safely
def on_close():
    # prompt save if signed in
    if current_user and current_key:
        if messagebox.askyesno("Exit", "Save changes before exit?"):
            try:
                save_notes(current_user, current_key, txt_notes.get("1.0", "end-1c"))
            except Exception:
                pass
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_close)

# ensure the text widget has focus to accept keyboard input
txt_notes.focus_set()

root.mainloop()
