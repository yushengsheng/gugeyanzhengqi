#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
import tkinter as tk
from tkinter import messagebox
from urllib.parse import parse_qs, unquote, urlparse


APP_DIR = Path(__file__).resolve().parent
LEGACY_DATA_FILE = APP_DIR / "accounts.json"
INPUT_FILE = APP_DIR / "secrets.txt"
WINDOW_TITLE = "谷歌验证器"
SUPPORTED_ALGORITHMS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}


@dataclass
class OTPEntry:
    id: str
    label: str
    secret: str
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"

    @property
    def display_name(self) -> str:
        return self.label or mask_secret(self.secret)


def normalize_secret(secret: str) -> str:
    cleaned = "".join(secret.strip().split()).upper()
    if not cleaned:
        raise ValueError("密钥不能为空")
    return cleaned


def decode_secret(secret: str) -> bytes:
    normalized = normalize_secret(secret)
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    try:
        return base64.b32decode(normalized + padding, casefold=True)
    except Exception as exc:
        raise ValueError("密钥不是有效的 Base32 格式") from exc


def build_entry(
    *,
    label: str,
    secret: str,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
    entry_id: str | None = None,
) -> OTPEntry:
    normalized_secret = normalize_secret(secret)
    decode_secret(normalized_secret)

    normalized_algorithm = algorithm.strip().upper() or "SHA1"
    if normalized_algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"不支持的算法: {normalized_algorithm}")

    digits = int(digits)
    period = int(period)
    if digits <= 0:
        raise ValueError("位数必须大于 0")
    if period <= 0:
        raise ValueError("周期必须大于 0")

    return OTPEntry(
        id=entry_id or str(uuid.uuid4()),
        label=label.strip(),
        secret=normalized_secret,
        digits=digits,
        period=period,
        algorithm=normalized_algorithm,
    )


def generate_totp(entry: OTPEntry, for_time: int | None = None) -> tuple[str, int]:
    timestamp = int(for_time if for_time is not None else time.time())
    period = max(1, int(entry.period))
    counter = timestamp // period
    remaining = period - (timestamp % period)

    secret = decode_secret(entry.secret)
    digest_factory = SUPPORTED_ALGORITHMS.get(entry.algorithm.upper())
    if digest_factory is None:
        raise ValueError(f"不支持的算法: {entry.algorithm}")

    counter_bytes = counter.to_bytes(8, "big")
    digest = hmac.new(secret, counter_bytes, digest_factory).digest()
    offset = digest[-1] & 0x0F
    code_int = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    digits = max(1, int(entry.digits))
    code = str(code_int % (10**digits)).zfill(digits)
    return code, remaining


def format_code(code: str) -> str:
    if len(code) == 6:
        return f"{code[:3]} {code[3:]}"
    if len(code) == 8:
        return f"{code[:4]} {code[4:]}"
    return code


def mask_secret(secret: str) -> str:
    normalized = normalize_secret(secret)
    if len(normalized) <= 10:
        return normalized
    return f"{normalized[:6]}...{normalized[-4:]}"


def parse_otpauth_uri(uri: str, fallback_index: int) -> OTPEntry:
    parsed = urlparse(uri.strip())
    if parsed.scheme != "otpauth" or parsed.netloc.lower() != "totp":
        raise ValueError("只支持 otpauth://totp/... 格式")

    label_text = unquote(parsed.path.lstrip("/"))
    if ":" in label_text:
        issuer_from_label, account = [part.strip() for part in label_text.split(":", 1)]
        display_label = f"{issuer_from_label} {account}".strip()
    else:
        issuer_from_label = ""
        account = label_text.strip()
        display_label = account

    query = parse_qs(parsed.query)
    issuer = query.get("issuer", [issuer_from_label])[0].strip()
    if issuer and account:
        display_label = f"{issuer} {account}".strip()
    elif issuer:
        display_label = issuer

    return build_entry(
        label=display_label or f"密钥 {fallback_index:02d}",
        secret=query.get("secret", [""])[0],
        digits=int(query.get("digits", ["6"])[0] or "6"),
        period=int(query.get("period", ["30"])[0] or "30"),
        algorithm=query.get("algorithm", ["SHA1"])[0],
    )


def parse_manual_line(line: str, fallback_index: int) -> OTPEntry:
    stripped = line.strip()
    if not stripped:
        raise ValueError("空行")
    if stripped.startswith("#"):
        raise ValueError("注释行")
    if stripped.lower().startswith("otpauth://"):
        return parse_otpauth_uri(stripped, fallback_index)

    for separator in ("|", ",", "\t"):
        if separator not in stripped:
            continue
        parts = [part.strip() for part in stripped.split(separator)]
        if len(parts) < 2:
            continue
        if parts[1].lower().startswith("otpauth://"):
            entry = parse_otpauth_uri(parts[1], fallback_index)
            if parts[0]:
                entry.label = parts[0]
            return entry
        label = parts[0] or f"密钥 {fallback_index:02d}"
        secret = parts[1]
        digits = int(parts[2]) if len(parts) >= 3 and parts[2] else 6
        period = int(parts[3]) if len(parts) >= 4 and parts[3] else 30
        algorithm = parts[4] if len(parts) >= 5 and parts[4] else "SHA1"
        return build_entry(
            label=label,
            secret=secret,
            digits=digits,
            period=period,
            algorithm=algorithm,
        )

    return build_entry(
        label=f"密钥 {fallback_index:02d}",
        secret=stripped,
    )


def parse_bulk_text(raw_text: str) -> tuple[list[OTPEntry], list[str]]:
    entries: list[OTPEntry] = []
    errors: list[str] = []
    display_index = 1
    for line_number, raw_line in enumerate(raw_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            entries.append(parse_manual_line(line, display_index))
            display_index += 1
        except Exception as exc:
            errors.append(f"第 {line_number} 行: {exc}")
    return entries, errors


def migrate_legacy_input() -> str:
    if INPUT_FILE.exists():
        try:
            return INPUT_FILE.read_text(encoding="utf-8")
        except Exception:
            return ""

    if not LEGACY_DATA_FILE.exists():
        return ""

    try:
        raw_items = json.loads(LEGACY_DATA_FILE.read_text(encoding="utf-8"))
    except Exception:
        return ""

    lines: list[str] = []
    if isinstance(raw_items, list):
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            secret = str(item.get("secret", "")).strip()
            if not secret:
                continue
            issuer = str(item.get("issuer", "")).strip()
            account = str(item.get("account", "")).strip()
            label = " ".join(part for part in (issuer, account) if part).strip()
            digits = str(item.get("digits", 6)).strip()
            period = str(item.get("period", 30)).strip()
            algorithm = str(item.get("algorithm", "SHA1")).strip()
            if label:
                lines.append(",".join([label, secret, digits, period, algorithm]))
            else:
                lines.append(secret)
    migrated = "\n".join(lines)
    if migrated:
        save_input_text(migrated)
    return migrated


def save_input_text(raw_text: str) -> None:
    INPUT_FILE.write_text(raw_text, encoding="utf-8")


class AuthenticatorApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(WINDOW_TITLE)
        self.geometry("176x360")
        self.minsize(176, 120)
        self.resizable(False, False)
        self.configure(bg="#ECECEC")

        self.entries: list[OTPEntry] = []
        self.row_widgets: dict[str, dict[str, tk.Widget | tk.StringVar]] = {}
        self.page_size = 5
        self.page_start = 0
        self.is_topmost = False
        self._drag_start_x = 0
        self._drag_start_y = 0

        self._build_ui()
        self._load_saved_input()
        self.after(300, self.refresh_codes)

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        outer = tk.Frame(self, bg="#ECECEC")
        outer.grid(sticky="nsew", padx=2, pady=2)
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_rowconfigure(0, weight=1)

        main = tk.Frame(outer, bg="#ECECEC")
        main.grid(row=0, column=0, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        self.pin_button = tk.Button(
            self,
            text="顶",
            command=self.toggle_topmost,
            bg="#ECECEC",
            fg="#5A5A5A",
            activebackground="#ECECEC",
            activeforeground="#111111",
            relief="flat",
            bd=0,
            highlightthickness=0,
            font=("PingFang SC", 9, "bold"),
            cursor="hand2",
            padx=1,
            pady=0,
        )
        self.pin_button.place(relx=1.0, x=-8, y=8, anchor="ne")

        self.drag_handle = tk.Label(
            self,
            text="✦",
            bg="#ECECEC",
            fg="#9A9A9A",
            font=("PingFang SC", 8, "bold"),
            cursor="fleur",
            padx=0,
            pady=0,
        )
        self.drag_handle.place(relx=1.0, rely=1.0, x=-4, y=-3, anchor="se")
        self.drag_handle.bind("<ButtonPress-1>", self._start_window_drag)
        self.drag_handle.bind("<B1-Motion>", self._drag_window)

        left = tk.Frame(main, bg="#ECECEC")
        left.grid(row=0, column=0, sticky="nsew")
        left.grid_columnconfigure(0, weight=1)
        left.grid_rowconfigure(1, weight=1)

        input_card = self._make_card(left, height=62)
        input_card.grid(row=0, column=0, sticky="ew")
        input_card.grid_columnconfigure(0, weight=1)
        input_card.grid_rowconfigure(0, weight=1)

        self.input_text = tk.Text(
            input_card,
            height=3,
            wrap="none",
            bg="white",
            fg="#111111",
            insertbackground="#111111",
            relief="flat",
            bd=0,
            undo=True,
            font=("Menlo", 10),
            padx=6,
            pady=5,
        )
        self.input_text.grid(row=0, column=0, sticky="nsew", padx=2, pady=(0, 0))
        self.input_text.bind("<Command-Return>", lambda _event: self.read_from_input())
        self.input_text.bind("<Control-Return>", lambda _event: self.read_from_input())
        self.input_text.bind("<Command-v>", self._paste_shortcut)
        self.input_text.bind("<Command-V>", self._paste_shortcut)
        self.input_text.bind("<Control-v>", self._paste_shortcut)
        self.input_text.bind("<Control-V>", self._paste_shortcut)
        self.input_text.bind("<Button-3>", self._show_input_menu)
        self.input_text.bind("<Button-2>", self._show_input_menu)
        self.input_text.bind("<Control-Button-1>", self._show_input_menu)
        self.input_text.bind("<Double-Button-1>", self._select_all_input)
        self.input_text.bind("<Delete>", self._delete_selected_input)
        self.input_text.bind("<BackSpace>", self._delete_selected_input)

        accent = tk.Frame(input_card, bg="#1E78D6", height=3)
        accent.grid(row=1, column=0, sticky="ew", padx=0, pady=(0, 0))

        result_card = self._make_card(left)
        result_card.grid(row=1, column=0, sticky="nsew", pady=(4, 0))
        result_card.grid_columnconfigure(0, weight=1)
        result_card.grid_rowconfigure(0, weight=1)

        self.result_body = tk.Frame(result_card, bg="white")
        self.result_body.grid(row=0, column=0, sticky="nsew")
        self._bind_result_scroll(self.result_body)

        self.empty_label = tk.Frame(self.result_body, bg="white", height=1)
        self.empty_label.pack(fill="both", expand=True)

        self.input_menu = tk.Menu(self, tearoff=0)
        self.input_menu.add_command(label="粘贴", command=self._paste_from_menu)
        self.input_menu.add_separator()
        self.input_menu.add_command(label="读取", command=self.read_from_input)
        self.input_menu.add_command(label="清空", command=self.clear_all)

    def _make_card(self, parent: tk.Widget, height: int | None = None) -> tk.Frame:
        frame = tk.Frame(
            parent,
            bg="white",
            highlightbackground="#D8D8D8",
            highlightcolor="#D8D8D8",
            highlightthickness=1,
            bd=0,
        )
        if height is not None:
            frame.configure(height=height)
            frame.grid_propagate(False)
        return frame

    def _load_saved_input(self) -> None:
        saved_text = migrate_legacy_input()
        if saved_text:
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", saved_text)
            self.after_idle(lambda: self.read_from_input(show_popup=True))
        else:
            self.after_idle(self._fit_window_height)

    def _on_mousewheel(self, event) -> None:
        delta = event.delta
        if delta == 0:
            return
        self._change_page(-1 if delta > 0 else 1)

    def _on_mousewheel_linux(self, event) -> None:
        if event.num == 4:
            self._change_page(-1)
        elif event.num == 5:
            self._change_page(1)

    def _bind_result_scroll(self, widget: tk.Widget) -> None:
        widget.bind("<MouseWheel>", self._on_mousewheel)
        widget.bind("<Button-4>", self._on_mousewheel_linux)
        widget.bind("<Button-5>", self._on_mousewheel_linux)

    def _bind_result_scroll_recursive(self, widget: tk.Widget) -> None:
        self._bind_result_scroll(widget)
        for child in widget.winfo_children():
            self._bind_result_scroll_recursive(child)

    def _change_page(self, direction: int) -> None:
        if len(self.entries) <= self.page_size:
            return
        max_start = ((len(self.entries) - 1) // self.page_size) * self.page_size
        next_start = self.page_start + (direction * self.page_size)
        next_start = max(0, min(max_start, next_start))
        if next_start == self.page_start:
            return
        self.page_start = next_start
        self.rebuild_result_rows()

    def _paste_shortcut(self, _event=None):
        try:
            self.input_text.event_generate("<<Paste>>")
        except Exception:
            try:
                content = self.clipboard_get()
            except Exception:
                return "break"
            self.input_text.insert(tk.INSERT, content)
        self.after_idle(lambda: self.read_from_input(show_popup=True))
        return "break"

    def _paste_from_menu(self) -> None:
        self._paste_shortcut()

    def _show_input_menu(self, event):
        try:
            self.input_text.focus_set()
            self.input_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.input_menu.grab_release()
        return "break"

    def _select_all_input(self, _event=None):
        self.input_text.tag_add(tk.SEL, "1.0", "end-1c")
        self.input_text.mark_set(tk.INSERT, "1.0")
        self.input_text.see(tk.INSERT)
        return "break"

    def _selection_covers_all_input(self) -> bool:
        try:
            sel_start = self.input_text.index(tk.SEL_FIRST)
            sel_end = self.input_text.index(tk.SEL_LAST)
        except tk.TclError:
            return False
        return sel_start == "1.0" and sel_end == self.input_text.index("end-1c")

    def _delete_selected_input(self, _event=None):
        if self._selection_covers_all_input():
            self.clear_all()
            return "break"
        return None

    def toggle_topmost(self) -> None:
        self.is_topmost = not self.is_topmost
        self.attributes("-topmost", self.is_topmost)
        self.pin_button.configure(
            text="取" if self.is_topmost else "顶",
            fg="#111111" if self.is_topmost else "#5A5A5A",
        )

    def _start_window_drag(self, event) -> None:
        self._drag_start_x = event.x_root
        self._drag_start_y = event.y_root

    def _drag_window(self, event) -> None:
        delta_x = event.x_root - self._drag_start_x
        delta_y = event.y_root - self._drag_start_y
        next_x = self.winfo_x() + delta_x
        next_y = self.winfo_y() + delta_y
        self.geometry(f"+{next_x}+{next_y}")
        self._drag_start_x = event.x_root
        self._drag_start_y = event.y_root

    def _fit_window_height(self) -> None:
        self.update_idletasks()
        needed_height = self.winfo_reqheight()
        current_width = self.winfo_width()
        if current_width <= 1:
            current_width = 176
        self.geometry(f"{current_width}x{needed_height}")

    def read_from_input(self, show_popup: bool = True) -> None:
        raw_text = self.input_text.get("1.0", tk.END).strip()
        entries, errors = parse_bulk_text(raw_text)
        try:
            save_input_text(raw_text)
        except Exception:
            pass

        if not entries:
            self.entries = []
            self.rebuild_result_rows()
            if errors and show_popup:
                preview = "\n".join(errors[:10])
                if len(errors) > 10:
                    preview += f"\n... 其余 {len(errors) - 10} 条未显示"
                messagebox.showerror("读取失败", preview, parent=self)
            return

        self.entries = entries
        self.page_start = 0
        self.rebuild_result_rows()
        self.after_idle(self._fit_window_height)
        if errors and show_popup:
            preview = "\n".join(errors[:10])
            if len(errors) > 10:
                preview += f"\n... 其余 {len(errors) - 10} 条未显示"
            messagebox.showwarning("部分内容未读取", preview, parent=self)

    def clear_all(self) -> None:
        self.input_text.delete("1.0", tk.END)
        self.entries = []
        self.page_start = 0
        self.rebuild_result_rows()
        self.after_idle(self._fit_window_height)
        try:
            save_input_text("")
        except Exception:
            return

    def rebuild_result_rows(self) -> None:
        for child in list(self.result_body.winfo_children()):
            child.destroy()
        self.row_widgets.clear()

        if not self.entries:
            self.empty_label = tk.Frame(self.result_body, bg="white", height=1)
            self.empty_label.pack(fill="both", expand=True)
            self.after_idle(self._fit_window_height)
            return

        visible_entries = self.entries[self.page_start : self.page_start + self.page_size]
        for offset, entry in enumerate(visible_entries, start=1):
            index = self.page_start + offset
            row_block = tk.Frame(self.result_body, bg="white")
            row_block.pack(fill="x")

            row = tk.Frame(row_block, bg="white", padx=2, pady=6)
            row.pack(fill="x")

            top = tk.Frame(row, bg="white")
            top.pack(fill="x")

            left_label = tk.Label(
                top,
                text=f"{index:02d}:{entry.secret}",
                bg="white",
                fg="#424242",
                font=("Menlo", 9, "bold"),
                anchor="w",
            )
            left_label.pack(side="left", fill="x", expand=True, pady=(0, 1))

            remain_var = tk.StringVar(value="--s")
            code_var = tk.StringVar(value="------")
            code_line = tk.Frame(row, bg="white")
            code_line.pack(anchor="w")
            code_label = tk.Label(
                code_line,
                textvariable=code_var,
                bg="white",
                fg="#111111",
                font=("Menlo", 14, "bold"),
                anchor="w",
                cursor="hand2",
                pady=1,
            )
            code_label.pack(side="left")

            remain_label = tk.Label(
                code_line,
                textvariable=remain_var,
                bg="white",
                fg="#8A8A8A",
                font=("Menlo", 9, "bold"),
                padx=4,
            )
            remain_label.pack(side="left")

            copy_button = tk.Button(
                code_line,
                text="复制",
                command=lambda item_id=entry.id: self.copy_code(item_id),
                bg="white",
                fg="#111111",
                activebackground="#F7F7F7",
                activeforeground="#111111",
                relief="flat",
                bd=1,
                highlightbackground="#D8D8D8",
                highlightcolor="#D8D8D8",
                highlightthickness=1,
                font=("PingFang SC", 10, "bold"),
                padx=8,
                pady=1,
                cursor="hand2",
            )
            copy_button.pack(side="right", padx=(0, 0))

            separator = tk.Frame(row_block, bg="#EEEEEE", height=1)
            separator.pack(fill="x", padx=2)

            self.row_widgets[entry.id] = {
                "code_var": code_var,
                "remain_var": remain_var,
                "code_label": code_label,
                "remain_label": remain_label,
                "copy_button": copy_button,
            }

            self._bind_result_scroll_recursive(row_block)
            self._bind_copy_recursive(row_block, entry.id)

        self.after_idle(self._fit_window_height)

    def _bind_copy(self, widget: tk.Widget, entry_id: str) -> None:
        widget.bind("<Button-1>", lambda _event, item_id=entry_id: self.copy_code(item_id), add="+")

    def _bind_copy_recursive(self, widget: tk.Widget, entry_id: str) -> None:
        self._bind_copy(widget, entry_id)
        for child in widget.winfo_children():
            self._bind_copy_recursive(child, entry_id)

    def copy_code(self, entry_id: str) -> None:
        entry = next((item for item in self.entries if item.id == entry_id), None)
        if entry is None:
            return

        try:
            code, _remaining = generate_totp(entry)
        except Exception as exc:
            messagebox.showerror("复制失败", str(exc), parent=self)
            return

        self.clipboard_clear()
        self.clipboard_append(code)

    def refresh_codes(self) -> None:
        now = int(time.time())
        for entry in self.entries:
            widgets = self.row_widgets.get(entry.id)
            if widgets is None:
                continue
            try:
                code, remaining = generate_totp(entry, now)
                code_var = widgets["code_var"]
                remain_var = widgets["remain_var"]
                code_label = widgets["code_label"]
                remain_label = widgets["remain_label"]
                if isinstance(code_var, tk.StringVar):
                    code_var.set(format_code(code))
                if isinstance(remain_var, tk.StringVar):
                    remain_var.set(f"{remaining:02d}s")
                if isinstance(code_label, tk.Label):
                    code_label.configure(fg="#C65A11" if remaining <= 5 else "#111111")
                if isinstance(remain_label, tk.Label):
                    remain_label.configure(fg="#C65A11" if remaining <= 5 else "#8A8A8A")
            except Exception:
                code_var = widgets["code_var"]
                remain_var = widgets["remain_var"]
                if isinstance(code_var, tk.StringVar):
                    code_var.set("错误")
                if isinstance(remain_var, tk.StringVar):
                    remain_var.set("--s")

        self.after(1000, self.refresh_codes)


def main() -> None:
    app = AuthenticatorApp()
    app.mainloop()


if __name__ == "__main__":
    main()
