from __future__ import annotations

from pathlib import Path
from queue import Empty, Queue
from threading import Thread
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:  # pragma: no cover - drag-and-drop is optional
    DND_FILES = None
    BaseWindow = tk.Tk
    HAS_DRAG_AND_DROP = False
else:  # pragma: no cover - used in the desktop app
    BaseWindow = TkinterDnD.Tk
    HAS_DRAG_AND_DROP = True

from .files import ENCRYPTION_ALGORITHM, decrypt_file, encrypt_file
from .hashing import HASH_ALGORITHMS, format_hash_algorithm_label, hash_file, hash_text
from .passwords import (
    PasswordOptions,
    classify_entropy_bits,
    estimate_entropy_bits,
    estimate_pronounceable_entropy_bits,
    generate_password,
    generate_pronounceable_password,
)
from .preferences import load_preferences, save_preferences


AUTO_CLEAR_CLIPBOARD_MS = 30_000
PASSWORD_HISTORY_LIMIT = 25


class Tooltip:
    def __init__(self, widget: tk.Widget, text: str) -> None:
        self.widget = widget
        self.text = text
        self.tip_window: tk.Toplevel | None = None
        widget.bind("<Enter>", self._show, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _show(self, _event: tk.Event[tk.Widget]) -> None:
        if self.tip_window or not self.text:
            return

        x = self.widget.winfo_rootx() + 18
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        window = tk.Toplevel(self.widget)
        window.wm_overrideredirect(True)
        window.wm_geometry(f"+{x}+{y}")
        window.configure(bg="#0a1320")

        label = tk.Label(
            window,
            text=self.text,
            justify="left",
            background="#0f1b2a",
            foreground="#ecfffb",
            relief="solid",
            borderwidth=1,
            padx=10,
            pady=6,
            wraplength=280,
            font=("Segoe UI", 9),
        )
        label.pack()
        self.tip_window = window

    def _hide(self, _event: tk.Event[tk.Widget] | None = None) -> None:
        if self.tip_window is not None:
            self.tip_window.destroy()
            self.tip_window = None


class CryptoToolsApp(BaseWindow):
    def __init__(self) -> None:
        # app state
        self.preferences = load_preferences()
        self.password_history = list(self.preferences.get("password_history", []))[
            :PASSWORD_HISTORY_LIMIT
        ]

        super().__init__()
        self.title("Crypto Tools")
        self.geometry(str(self.preferences.get("window_geometry") or "1160x820"))
        self.minsize(980, 720)
        self.configure(bg="#08111c")

        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self._configure_styles()

        self.password_mode_var = tk.StringVar(
            value=str(self.preferences.get("password_mode", "random"))
        )
        self.length_var = tk.IntVar(value=int(self.preferences.get("length", 20)))
        self.word_count_var = tk.IntVar(value=int(self.preferences.get("word_count", 4)))
        self.uppercase_var = tk.BooleanVar(value=bool(self.preferences.get("uppercase", True)))
        self.lowercase_var = tk.BooleanVar(value=bool(self.preferences.get("lowercase", True)))
        self.numbers_var = tk.BooleanVar(value=bool(self.preferences.get("numbers", True)))
        self.symbols_var = tk.BooleanVar(value=bool(self.preferences.get("symbols", True)))
        self.generated_password_var = tk.StringVar()
        self.strength_var = tk.StringVar(value="Strength: --")
        self.entropy_var = tk.StringVar(value="Entropy: --")
        self.password_status_var = tk.StringVar(value="Ready to generate a password.")

        self.file_mode_var = tk.StringVar(value=str(self.preferences.get("file_mode", "encrypt")))
        self.file_path_var = tk.StringVar()
        self.output_path_var = tk.StringVar()
        self.file_password_var = tk.StringVar()
        self.file_password_confirm_var = tk.StringVar()
        self.show_file_password_var = tk.BooleanVar(
            value=bool(self.preferences.get("show_file_password", False))
        )
        self.overwrite_var = tk.BooleanVar(value=bool(self.preferences.get("overwrite", False)))
        self.file_progress_var = tk.DoubleVar(value=0.0)
        self.file_progress_text_var = tk.StringVar(value="Idle")
        self.file_status_var = tk.StringVar(
            value="Choose a file, set a password, and run encrypt or decrypt."
        )

        self.hash_algorithm_var = tk.StringVar(
            value=str(self.preferences.get("hash_algorithm", "sha256"))
        )
        self.hash_file_path_var = tk.StringVar()
        self.hash_output_var = tk.StringVar()
        self.hash_status_var = tk.StringVar(
            value="Hash text instantly or hash large files with progress feedback."
        )
        self.hash_progress_var = tk.DoubleVar(value=0.0)
        self.hash_progress_text_var = tk.StringVar(value="Idle")

        self.clipboard_clear_job: str | None = None
        self.file_queue: Queue[tuple[str, object, object]] | None = None
        self.file_worker_thread: Thread | None = None
        self.hash_queue: Queue[tuple[str, object, object]] | None = None
        self.hash_worker_thread: Thread | None = None

        self._build_layout()
        self._bind_shortcuts()
        self._refresh_history_list()
        self._update_password_mode_ui()
        self._update_file_mode_ui()
        self._preview_password()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_styles(self) -> None:
        # theme colors + widget styles
        self.style.configure(".", background="#08111c", foreground="#ebfffb")
        self.style.configure("Root.TFrame", background="#08111c")
        self.style.configure("Card.TFrame", background="#101b2a")
        self.style.configure(
            "Hero.TLabel",
            background="#08111c",
            foreground="#f2fffd",
            font=("Segoe UI Semibold", 28),
        )
        self.style.configure(
            "HeroSub.TLabel",
            background="#08111c",
            foreground="#a9c7c7",
            font=("Segoe UI", 11),
        )
        self.style.configure(
            "CardTitle.TLabel",
            background="#101b2a",
            foreground="#f2fffd",
            font=("Segoe UI Semibold", 18),
        )
        self.style.configure(
            "Muted.TLabel",
            background="#101b2a",
            foreground="#9fc1c2",
            font=("Segoe UI", 10),
        )
        self.style.configure(
            "TEntry",
            fieldbackground="#0c1622",
            foreground="#f4fffd",
            insertcolor="#f4fffd",
        )
        self.style.map(
            "TEntry",
            fieldbackground=[("readonly", "#0c1622")],
            foreground=[("readonly", "#f4fffd")],
        )
        self.style.configure(
            "Value.TLabel",
            background="#101b2a",
            foreground="#f2fffd",
            font=("Segoe UI Semibold", 11),
        )
        self.style.configure(
            "Primary.TButton",
            background="#74f5d5",
            foreground="#041311",
            borderwidth=0,
            padding=(16, 10),
            font=("Segoe UI Semibold", 10),
        )
        self.style.map(
            "Primary.TButton",
            background=[("active", "#8bf7df"), ("pressed", "#61debf")],
        )
        self.style.configure(
            "Secondary.TButton",
            background="#1d2a3d",
            foreground="#eef8f8",
            borderwidth=1,
            padding=(14, 10),
            font=("Segoe UI", 10),
        )
        self.style.map(
            "Secondary.TButton",
            background=[("active", "#273952"), ("pressed", "#172233")],
        )
        self.style.configure(
            "Section.TCheckbutton",
            background="#101b2a",
            foreground="#eef8f8",
            font=("Segoe UI", 10),
        )
        self.style.configure(
            "Section.TRadiobutton",
            background="#101b2a",
            foreground="#eef8f8",
            font=("Segoe UI", 10),
        )
        self.style.configure(
            "Crypto.TNotebook",
            background="#08111c",
            borderwidth=0,
            tabmargins=(0, 0, 0, 0),
        )
        self.style.configure(
            "Crypto.TNotebook.Tab",
            background="#101b2a",
            foreground="#d8ecec",
            padding=(16, 10),
            font=("Segoe UI Semibold", 10),
        )
        self.style.map(
            "Crypto.TNotebook.Tab",
            background=[("selected", "#123b3b"), ("active", "#152f38")],
            foreground=[("selected", "#74f5d5"), ("active", "#eef8f8")],
        )
        self.style.configure(
            "Accent.Horizontal.TProgressbar",
            troughcolor="#1d2938",
            bordercolor="#1d2938",
            background="#74f5d5",
            lightcolor="#74f5d5",
            darkcolor="#5ce0c0",
        )

    def _build_layout(self) -> None:
        root = ttk.Frame(self, padding=18, style="Root.TFrame")
        root.pack(fill="both", expand=True)

        hero = ttk.Frame(root, style="Root.TFrame")
        hero.pack(fill="x", pady=(0, 14))
        ttk.Label(hero, text="Crypto Tools", style="Hero.TLabel").pack(anchor="w")
        ttk.Label(
            hero,
            text=(
                "Generate strong passwords, keep a history, encrypt large files with progress, "
                "and hash text or files in one desktop app."
            ),
            style="HeroSub.TLabel",
            wraplength=980,
        ).pack(anchor="w", pady=(6, 0))

        notebook = ttk.Notebook(root, style="Crypto.TNotebook")
        notebook.pack(fill="both", expand=True)

        self.password_tab = ttk.Frame(notebook, padding=14, style="Root.TFrame")
        self.file_tab = ttk.Frame(notebook, padding=14, style="Root.TFrame")
        self.hash_tab = ttk.Frame(notebook, padding=14, style="Root.TFrame")
        notebook.add(self.password_tab, text="Passwords")
        notebook.add(self.file_tab, text="File Encryption")
        notebook.add(self.hash_tab, text="Hash Tools")

        self._build_password_tab()
        self._build_file_tab()
        self._build_hash_tab()

    def _build_password_tab(self) -> None:
        # controls left, history right
        self.password_tab.columnconfigure(0, weight=3)
        self.password_tab.columnconfigure(1, weight=2)

        controls = ttk.Frame(self.password_tab, padding=20, style="Card.TFrame")
        controls.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        history = ttk.Frame(self.password_tab, padding=20, style="Card.TFrame")
        history.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        ttk.Label(controls, text="Password Generator", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(
            controls,
            text="Use random characters or switch to pronounceable mode for memorable passphrases.",
            style="Muted.TLabel",
            wraplength=500,
        ).pack(anchor="w", pady=(4, 18))

        mode_row = ttk.Frame(controls, style="Card.TFrame")
        mode_row.pack(fill="x", pady=(0, 12))
        ttk.Radiobutton(
            mode_row,
            text="Random",
            value="random",
            variable=self.password_mode_var,
            style="Section.TRadiobutton",
            command=self._on_password_settings_changed,
        ).pack(side="left")
        ttk.Radiobutton(
            mode_row,
            text="Pronounceable",
            value="pronounceable",
            variable=self.password_mode_var,
            style="Section.TRadiobutton",
            command=self._on_password_settings_changed,
        ).pack(side="left", padx=(14, 0))

        self.random_controls = ttk.Frame(controls, style="Card.TFrame")
        self.random_controls.pack(fill="x")

        length_row = ttk.Frame(self.random_controls, style="Card.TFrame")
        length_row.pack(fill="x")
        ttk.Label(length_row, text="Length", style="Muted.TLabel").pack(side="left")
        ttk.Label(length_row, textvariable=self.length_var, style="Value.TLabel").pack(side="right")

        scale = tk.Scale(
            self.random_controls,
            from_=8,
            to=64,
            orient="horizontal",
            variable=self.length_var,
            bg="#101b2a",
            fg="#e9fffb",
            highlightthickness=0,
            troughcolor="#223043",
            activebackground="#74f5d5",
            command=lambda _value: self._preview_password(),
        )
        scale.pack(fill="x", pady=(8, 14))

        self.charset_checks: list[ttk.Checkbutton] = []
        for text, variable, tooltip in [
            ("Uppercase letters", self.uppercase_var, "Adds 26 uppercase characters."),
            ("Lowercase letters", self.lowercase_var, "Adds 26 lowercase characters."),
            ("Numbers", self.numbers_var, "Adds 10 digits to the character pool."),
            ("Symbols", self.symbols_var, "Adds punctuation for higher entropy."),
        ]:
            widget = ttk.Checkbutton(
                self.random_controls,
                text=text,
                variable=variable,
                style="Section.TCheckbutton",
                command=self._preview_password,
            )
            widget.pack(anchor="w", pady=4)
            Tooltip(widget, tooltip)
            self.charset_checks.append(widget)

        self.pronounceable_controls = ttk.Frame(controls, style="Card.TFrame")
        word_row = ttk.Frame(self.pronounceable_controls, style="Card.TFrame")
        word_row.pack(anchor="w")
        ttk.Label(word_row, text="Word Count", style="Muted.TLabel").pack(side="left")
        ttk.Spinbox(
            word_row,
            from_=3,
            to=8,
            textvariable=self.word_count_var,
            width=6,
            command=self._preview_password,
        ).pack(side="left", padx=(8, 0))
        ttk.Frame(self.pronounceable_controls, height=10, style="Card.TFrame").pack(fill="x")

        ttk.Label(controls, text="Generated Password", style="Muted.TLabel").pack(
            anchor="w", pady=(18, 6)
        )
        self.password_box = tk.Text(
            controls,
            height=4,
            wrap="word",
            bg="#0c1622",
            fg="#f4fffd",
            insertbackground="#f4fffd",
            relief="flat",
            padx=14,
            pady=14,
            font=("Cascadia Code", 13),
        )
        self.password_box.pack(fill="x")
        self.password_box.configure(state="disabled")

        ttk.Label(controls, textvariable=self.strength_var, style="Value.TLabel").pack(
            anchor="w", pady=(12, 2)
        )
        self.strength_meter = tk.Canvas(
            controls,
            width=320,
            height=24,
            bg="#101b2a",
            highlightthickness=0,
        )
        self.strength_meter.pack(anchor="w")
        self.strength_rectangles: list[int] = []
        for index in range(4):
            x0 = 10 + index * 76
            rectangle = self.strength_meter.create_rectangle(
                x0,
                6,
                x0 + 62,
                18,
                fill="#223043",
                outline="#223043",
            )
            self.strength_rectangles.append(rectangle)

        ttk.Label(controls, textvariable=self.entropy_var, style="Muted.TLabel").pack(
            anchor="w", pady=(8, 0)
        )
        ttk.Label(
            controls,
            textvariable=self.password_status_var,
            style="Muted.TLabel",
            wraplength=520,
        ).pack(anchor="w", pady=(4, 14))

        actions = ttk.Frame(controls, style="Card.TFrame")
        actions.pack(fill="x")
        ttk.Button(
            actions,
            text="Generate",
            command=self._generate_password_action,
            style="Primary.TButton",
        ).pack(side="left")
        ttk.Button(
            actions,
            text="Copy",
            command=self._copy_generated_password,
            style="Secondary.TButton",
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            actions,
            text="Clear Clipboard",
            command=self._clear_clipboard,
            style="Secondary.TButton",
        ).pack(side="left", padx=(10, 0))

        ttk.Label(history, text="Password History", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(
            history,
            text="Scroll back through previous generations. Double-click one to copy it again.",
            style="Muted.TLabel",
            wraplength=320,
        ).pack(anchor="w", pady=(4, 12))

        list_frame = ttk.Frame(history, style="Card.TFrame")
        list_frame.pack(fill="both", expand=True)
        self.history_listbox = tk.Listbox(
            list_frame,
            bg="#0c1622",
            fg="#f4fffd",
            selectbackground="#22415a",
            selectforeground="#f4fffd",
            borderwidth=0,
            highlightthickness=0,
            font=("Cascadia Code", 11),
        )
        self.history_listbox.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.history_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.history_listbox.configure(yscrollcommand=scrollbar.set)
        self.history_listbox.bind("<Double-Button-1>", self._copy_selected_history, add="+")

        history_actions = ttk.Frame(history, style="Card.TFrame")
        history_actions.pack(fill="x", pady=(12, 0))
        ttk.Button(
            history_actions,
            text="Copy Selected",
            command=self._copy_selected_history,
            style="Secondary.TButton",
        ).pack(side="left")
        ttk.Button(
            history_actions,
            text="Clear History",
            command=self._clear_history,
            style="Secondary.TButton",
        ).pack(side="left", padx=(10, 0))

    def _build_file_tab(self) -> None:
        card = ttk.Frame(self.file_tab, padding=20, style="Card.TFrame")
        card.pack(fill="both", expand=True)

        ttk.Label(card, text="File Encryption", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(
            card,
            text="Encrypt and decrypt files. Large files update the progress bar as they run.",
            style="Muted.TLabel",
            wraplength=860,
        ).pack(anchor="w", pady=(4, 12))
        ttk.Label(
            card,
            text=f"Algorithm: {ENCRYPTION_ALGORITHM}",
            style="Value.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            card,
            text=(
                "Tip: drag a file onto the input field."
                if HAS_DRAG_AND_DROP
                else "Drag-and-drop becomes available automatically when tkinterdnd2 is installed."
            ),
            style="Muted.TLabel",
            wraplength=860,
        ).pack(anchor="w", pady=(4, 18))

        mode_row = ttk.Frame(card, style="Card.TFrame")
        mode_row.pack(fill="x", pady=(0, 12))
        ttk.Radiobutton(
            mode_row,
            text="Encrypt",
            value="encrypt",
            variable=self.file_mode_var,
            style="Section.TRadiobutton",
            command=self._on_file_mode_changed,
        ).pack(side="left")
        ttk.Radiobutton(
            mode_row,
            text="Decrypt",
            value="decrypt",
            variable=self.file_mode_var,
            style="Section.TRadiobutton",
            command=self._on_file_mode_changed,
        ).pack(side="left", padx=(14, 0))

        self.file_input_entry = self._build_path_field(
            card,
            "Input File",
            self.file_path_var,
            self._choose_input_file,
        )
        self.file_output_entry = self._build_path_field(
            card,
            "Output File",
            self.output_path_var,
            self._choose_output_file,
        )
        self._register_drop_target(self.file_input_entry, self._handle_file_drop)

        ttk.Label(card, text="Password", style="Muted.TLabel").pack(anchor="w", pady=(8, 6))
        self.file_password_entry = ttk.Entry(card, textvariable=self.file_password_var, show="*")
        self.file_password_entry.pack(fill="x")

        self.confirm_password_frame = ttk.Frame(card, style="Card.TFrame")
        ttk.Label(self.confirm_password_frame, text="Confirm Password", style="Muted.TLabel").pack(
            anchor="w", pady=(8, 6)
        )
        self.file_confirm_entry = ttk.Entry(
            self.confirm_password_frame,
            textvariable=self.file_password_confirm_var,
            show="*",
        )
        self.file_confirm_entry.pack(fill="x")
        self.confirm_password_frame.pack(fill="x")

        self.file_show_password_check = ttk.Checkbutton(
            card,
            text="Show password",
            variable=self.show_file_password_var,
            style="Section.TCheckbutton",
            command=self._toggle_file_password_visibility,
        )
        self.file_show_password_check.pack(anchor="w", pady=(10, 0))
        ttk.Checkbutton(
            card,
            text="Overwrite existing output file",
            variable=self.overwrite_var,
            style="Section.TCheckbutton",
        ).pack(anchor="w", pady=(8, 0))

        ttk.Label(card, text="Progress", style="Muted.TLabel").pack(anchor="w", pady=(16, 6))
        ttk.Progressbar(
            card,
            variable=self.file_progress_var,
            maximum=100,
            style="Accent.Horizontal.TProgressbar",
        ).pack(fill="x")
        ttk.Label(card, textvariable=self.file_progress_text_var, style="Muted.TLabel").pack(
            anchor="w", pady=(6, 0)
        )
        ttk.Label(
            card,
            textvariable=self.file_status_var,
            style="Muted.TLabel",
            wraplength=860,
        ).pack(anchor="w", pady=(8, 14))

        self.file_run_button = ttk.Button(
            card,
            text="Run",
            command=self._run_file_operation,
            style="Primary.TButton",
        )
        self.file_run_button.pack(anchor="w")

    def _build_hash_tab(self) -> None:
        card = ttk.Frame(self.hash_tab, padding=20, style="Card.TFrame")
        card.pack(fill="both", expand=True)

        ttk.Label(card, text="Hash Tools", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(
            card,
            text="Create MD5 or SHA-256 hashes for quick checks, file verification, or comparison workflows.",
            style="Muted.TLabel",
            wraplength=860,
        ).pack(anchor="w", pady=(4, 18))

        algorithm_row = ttk.Frame(card, style="Card.TFrame")
        algorithm_row.pack(fill="x")
        ttk.Label(algorithm_row, text="Algorithm", style="Muted.TLabel").pack(side="left")
        algorithm_menu = ttk.Combobox(
            algorithm_row,
            textvariable=self.hash_algorithm_var,
            values=list(HASH_ALGORITHMS),
            state="readonly",
            width=10,
        )
        algorithm_menu.pack(side="left", padx=(10, 0))
        ttk.Label(
            algorithm_row,
            text="SHA-256 is recommended. MD5 is here for legacy compatibility checks.",
            style="Muted.TLabel",
        ).pack(side="left", padx=(12, 0))

        ttk.Label(card, text="Text Input", style="Muted.TLabel").pack(anchor="w", pady=(16, 6))
        self.hash_text_box = tk.Text(
            card,
            height=6,
            wrap="word",
            bg="#0c1622",
            fg="#f4fffd",
            insertbackground="#f4fffd",
            relief="flat",
            padx=12,
            pady=12,
            font=("Cascadia Code", 11),
        )
        self.hash_text_box.pack(fill="x")

        text_buttons = ttk.Frame(card, style="Card.TFrame")
        text_buttons.pack(fill="x", pady=(10, 12))
        ttk.Button(
            text_buttons,
            text="Hash Text",
            command=self._hash_text_action,
            style="Primary.TButton",
        ).pack(side="left")

        self.hash_file_entry = self._build_path_field(
            card,
            "File Input",
            self.hash_file_path_var,
            self._choose_hash_file,
        )
        self._register_drop_target(self.hash_file_entry, self._handle_hash_drop)

        hash_file_actions = ttk.Frame(card, style="Card.TFrame")
        hash_file_actions.pack(fill="x", pady=(10, 0))
        self.hash_file_button = ttk.Button(
            hash_file_actions,
            text="Hash File",
            command=self._hash_file_action,
            style="Primary.TButton",
        )
        self.hash_file_button.pack(side="left")

        ttk.Label(card, text="Progress", style="Muted.TLabel").pack(anchor="w", pady=(16, 6))
        ttk.Progressbar(
            card,
            variable=self.hash_progress_var,
            maximum=100,
            style="Accent.Horizontal.TProgressbar",
        ).pack(fill="x")
        ttk.Label(card, textvariable=self.hash_progress_text_var, style="Muted.TLabel").pack(
            anchor="w", pady=(6, 0)
        )

        ttk.Label(card, text="Digest", style="Muted.TLabel").pack(anchor="w", pady=(16, 6))
        self.hash_output_box = tk.Text(
            card,
            height=3,
            wrap="word",
            bg="#0c1622",
            fg="#f4fffd",
            insertbackground="#f4fffd",
            relief="flat",
            padx=12,
            pady=12,
            font=("Cascadia Code", 11),
        )
        self.hash_output_box.pack(fill="x")
        self.hash_output_box.configure(state="disabled")

        digest_actions = ttk.Frame(card, style="Card.TFrame")
        digest_actions.pack(fill="x", pady=(10, 0))
        ttk.Button(
            digest_actions,
            text="Copy Digest",
            command=self._copy_hash_output,
            style="Secondary.TButton",
        ).pack(side="left")

        ttk.Label(
            card,
            textvariable=self.hash_status_var,
            style="Muted.TLabel",
            wraplength=860,
        ).pack(anchor="w", pady=(12, 0))

    def _build_path_field(
        self,
        parent: ttk.Frame,
        label: str,
        variable: tk.StringVar,
        command: object,
    ) -> ttk.Entry:
        ttk.Label(parent, text=label, style="Muted.TLabel").pack(anchor="w", pady=(8, 6))
        row = ttk.Frame(parent, style="Card.TFrame")
        row.pack(fill="x")
        entry = ttk.Entry(row, textvariable=variable)
        entry.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse", command=command, style="Secondary.TButton").pack(
            side="left", padx=(10, 0)
        )
        return entry

    def _bind_shortcuts(self) -> None:
        self.bind_all("<Control-g>", self._generate_password_shortcut, add="+")
        self.bind_all("<Control-G>", self._generate_password_shortcut, add="+")
        self.bind_all("<Control-Shift-C>", self._copy_password_shortcut, add="+")
        self.bind_all("<Return>", self._handle_return_shortcut, add="+")

    def _collect_preferences(self) -> dict[str, object]:
        return {
            "window_geometry": self.geometry(),
            "password_mode": self.password_mode_var.get(),
            "length": self.length_var.get(),
            "word_count": self.word_count_var.get(),
            "uppercase": self.uppercase_var.get(),
            "lowercase": self.lowercase_var.get(),
            "numbers": self.numbers_var.get(),
            "symbols": self.symbols_var.get(),
            "password_history": self.password_history[:PASSWORD_HISTORY_LIMIT],
            "file_mode": self.file_mode_var.get(),
            "overwrite": self.overwrite_var.get(),
            "show_file_password": self.show_file_password_var.get(),
            "hash_algorithm": self.hash_algorithm_var.get(),
        }

    def _on_close(self) -> None:
        save_preferences(self._collect_preferences())
        self.destroy()

    def _password_options(self) -> PasswordOptions:
        return PasswordOptions(
            length=self.length_var.get(),
            uppercase=self.uppercase_var.get(),
            lowercase=self.lowercase_var.get(),
            numbers=self.numbers_var.get(),
            symbols=self.symbols_var.get(),
        )

    def _current_password_state(self) -> tuple[str, str, float]:
        if self.password_mode_var.get() == "pronounceable":
            password = generate_pronounceable_password(self.word_count_var.get())
            entropy = estimate_pronounceable_entropy_bits(self.word_count_var.get())
            return password, classify_entropy_bits(entropy), entropy

        options = self._password_options()
        password = generate_password(options)
        entropy = estimate_entropy_bits(options)
        return password, classify_entropy_bits(entropy), entropy

    def _set_password_display(self, value: str) -> None:
        self.password_box.configure(state="normal")
        self.password_box.delete("1.0", "end")
        self.password_box.insert("1.0", value)
        self.password_box.configure(state="disabled")

    def _set_hash_display(self, value: str) -> None:
        self.hash_output_box.configure(state="normal")
        self.hash_output_box.delete("1.0", "end")
        self.hash_output_box.insert("1.0", value)
        self.hash_output_box.configure(state="disabled")

    def _update_strength_meter(self, strength: str) -> None:
        active_counts = {"Weak": 1, "Fair": 2, "Strong": 3, "Insane": 4}
        colors = {
            "Weak": "#ff8b8b",
            "Fair": "#f6d46d",
            "Strong": "#6ee2a9",
            "Insane": "#74f5d5",
        }
        active = active_counts.get(strength, 0)
        color = colors.get(strength, "#223043")

        for index, rectangle in enumerate(self.strength_rectangles, start=1):
            fill = color if index <= active else "#223043"
            self.strength_meter.itemconfigure(rectangle, fill=fill, outline=fill)

    def _preview_password(self) -> None:
        try:
            password, strength, entropy = self._current_password_state()
        except ValueError as exc:
            self.generated_password_var.set("")
            self._set_password_display("")
            self.strength_var.set("Strength: --")
            self.entropy_var.set("Entropy: --")
            self.password_status_var.set(str(exc))
            self._update_strength_meter("Weak")
            return

        self.generated_password_var.set(password)
        self._set_password_display(password)
        self.strength_var.set(f"Strength: {strength}")
        self.entropy_var.set(f"Entropy: {entropy:.1f} bits")
        self.password_status_var.set("Preview updated.")
        self._update_strength_meter(strength)

    def _generate_password_action(self) -> None:
        self._preview_password()
        password = self.generated_password_var.get()
        if password:
            self._remember_password(password)
            self.password_status_var.set("Generated a new password.")

    def _remember_password(self, password: str) -> None:
        if password in self.password_history:
            self.password_history.remove(password)
        self.password_history.insert(0, password)
        del self.password_history[PASSWORD_HISTORY_LIMIT:]
        self._refresh_history_list()

    def _refresh_history_list(self) -> None:
        self.history_listbox.delete(0, "end")
        for item in self.password_history:
            self.history_listbox.insert("end", item)

    def _copy_generated_password(self) -> None:
        password = self.generated_password_var.get()
        if not password:
            messagebox.showwarning("Nothing to copy", "Generate a password first.")
            return

        self.clipboard_clear()
        self.clipboard_append(password)
        if self.clipboard_clear_job:
            self.after_cancel(self.clipboard_clear_job)
        self.clipboard_clear_job = self.after(
            AUTO_CLEAR_CLIPBOARD_MS,
            self._clear_clipboard_after_timeout,
        )
        self.password_status_var.set("Password copied. Clipboard clears in 30 seconds.")

    def _clear_clipboard_after_timeout(self) -> None:
        self.clipboard_clear()
        self.clipboard_clear_job = None
        self.password_status_var.set("Clipboard cleared.")

    def _clear_clipboard(self) -> None:
        if self.clipboard_clear_job:
            self.after_cancel(self.clipboard_clear_job)
            self.clipboard_clear_job = None
        self.clipboard_clear()
        self.password_status_var.set("Clipboard cleared.")

    def _copy_selected_history(self, _event: tk.Event[tk.Widget] | None = None) -> None:
        selection = self.history_listbox.curselection()
        if not selection:
            messagebox.showwarning("No selection", "Choose a password from the history first.")
            return

        password = self.history_listbox.get(selection[0])
        self.generated_password_var.set(password)
        self._set_password_display(password)
        self._copy_generated_password()

    def _clear_history(self) -> None:
        self.password_history.clear()
        self._refresh_history_list()
        self.password_status_var.set("Password history cleared.")

    def _update_password_mode_ui(self) -> None:
        self.random_controls.pack_forget()
        self.pronounceable_controls.pack_forget()

        if self.password_mode_var.get() == "pronounceable":
            self.pronounceable_controls.pack(fill="x")
        else:
            self.random_controls.pack(fill="x")

    def _on_password_settings_changed(self) -> None:
        self._update_password_mode_ui()
        self._preview_password()

    def _generate_password_shortcut(self, _event: tk.Event[tk.Widget]) -> str:
        self._generate_password_action()
        return "break"

    def _copy_password_shortcut(self, _event: tk.Event[tk.Widget]) -> str:
        self._copy_generated_password()
        return "break"

    def _handle_return_shortcut(self, _event: tk.Event[tk.Widget]) -> str | None:
        focus = self.focus_get()
        if focus is None or isinstance(focus, tk.Text):
            return None

        if self._widget_is_descendant(focus, self.file_tab):
            self._run_file_operation()
            return "break"

        return None

    def _widget_is_descendant(self, widget: tk.Widget, ancestor: tk.Widget) -> bool:
        current: tk.Widget | None = widget
        while current is not None:
            if current == ancestor:
                return True
            current = current.master
        return False

    def _toggle_file_password_visibility(self) -> None:
        show = "" if self.show_file_password_var.get() else "*"
        self.file_password_entry.configure(show=show)
        self.file_confirm_entry.configure(show=show)

    def _update_file_mode_ui(self) -> None:
        if self.file_mode_var.get() == "encrypt":
            self.confirm_password_frame.pack(fill="x", before=self.file_show_password_check)
        else:
            self.confirm_password_frame.pack_forget()

    def _on_file_mode_changed(self) -> None:
        self._update_file_mode_ui()
        self._suggest_output_path()

    def _choose_input_file(self) -> None:
        file_path = filedialog.askopenfilename(title="Choose a file")
        if not file_path:
            return

        self.file_path_var.set(file_path)
        self._suggest_output_path()

    def _choose_output_file(self) -> None:
        initial_name = Path(self.output_path_var.get()).name if self.output_path_var.get() else ""
        file_path = filedialog.asksaveasfilename(
            title="Choose where to save the output",
            initialfile=initial_name,
        )
        if file_path:
            self.output_path_var.set(file_path)

    def _suggest_output_path(self) -> None:
        source = self.file_path_var.get().strip()
        if not source:
            return

        source_path = Path(source)
        if self.file_mode_var.get() == "encrypt":
            suggestion = source_path.with_name(f"{source_path.name}.enc")
        else:
            if source_path.suffix == ".enc":
                original_name = source_path.stem
                original_path = Path(original_name)
                if original_path.suffix:
                    suggestion = source_path.with_name(
                        f"{original_path.stem}.decrypted{original_path.suffix}"
                    )
                else:
                    suggestion = source_path.with_name(f"{original_name}.decrypted")
            else:
                suggestion = source_path.with_name(f"{source_path.name}.decrypted")

        self.output_path_var.set(str(suggestion))

    def _register_drop_target(self, widget: tk.Widget, callback: object) -> None:
        if not HAS_DRAG_AND_DROP:
            return

        widget.drop_target_register(DND_FILES)
        widget.dnd_bind("<<Drop>>", callback)

    def _extract_drop_path(self, raw_data: str) -> str | None:
        try:
            dropped = self.tk.splitlist(raw_data)
        except tk.TclError:
            dropped = [raw_data]
        return dropped[0] if dropped else None

    def _handle_file_drop(self, event: tk.Event[tk.Widget]) -> str:
        path = self._extract_drop_path(event.data)
        if path:
            self.file_path_var.set(path)
            self._suggest_output_path()
        return "break"

    def _choose_hash_file(self) -> None:
        file_path = filedialog.askopenfilename(title="Choose a file to hash")
        if file_path:
            self.hash_file_path_var.set(file_path)

    def _handle_hash_drop(self, event: tk.Event[tk.Widget]) -> str:
        path = self._extract_drop_path(event.data)
        if path:
            self.hash_file_path_var.set(path)
        return "break"

    def _start_file_worker(self, target: object, verb: str) -> None:
        # run file work in the background so the window stays alive
        self.file_queue = Queue()
        self.file_progress_var.set(0)
        self.file_progress_text_var.set("0%")
        self.file_status_var.set(f"{verb} in progress...")
        self.file_run_button.configure(state="disabled")

        def progress(processed: int, total: int) -> None:
            assert self.file_queue is not None
            self.file_queue.put(("progress", processed, total))

        def worker() -> None:
            try:
                result = target(progress)
            except Exception as exc:  # pragma: no cover - shown by the UI
                assert self.file_queue is not None
                self.file_queue.put(("error", exc, verb))
            else:
                assert self.file_queue is not None
                self.file_queue.put(("done", result, verb))

        self.file_worker_thread = Thread(target=worker, daemon=True)
        self.file_worker_thread.start()
        self.after(80, self._poll_file_queue)

    def _poll_file_queue(self) -> None:
        if self.file_queue is None:
            return

        still_running = self.file_worker_thread is not None and self.file_worker_thread.is_alive()
        try:
            while True:
                kind, first, second = self.file_queue.get_nowait()
                if kind == "progress":
                    processed = int(first)
                    total = int(second)
                    percent = 100.0 if total == 0 else (processed / total) * 100
                    self.file_progress_var.set(percent)
                    self.file_progress_text_var.set(
                        f"{percent:0.1f}% - {self._format_bytes(processed)} / {self._format_bytes(total)}"
                    )
                elif kind == "error":
                    self.file_run_button.configure(state="normal")
                    self.file_status_var.set(f"Error: {first}")
                    self.file_progress_text_var.set("Failed")
                    messagebox.showerror("Operation failed", str(first))
                    self.file_queue = None
                    return
                elif kind == "done":
                    self.file_run_button.configure(state="normal")
                    self.file_progress_var.set(100)
                    self.file_progress_text_var.set("100%")
                    self.output_path_var.set(str(first))
                    self.file_status_var.set(f"{second} complete: {first}")
                    messagebox.showinfo("Done", f"{second} complete.\n\nSaved to:\n{first}")
                    self.file_queue = None
                    return
        except Empty:
            pass

        if still_running:
            self.after(80, self._poll_file_queue)
        else:
            self.file_run_button.configure(state="normal")

    def _run_file_operation(self) -> None:
        if self.file_worker_thread is not None and self.file_worker_thread.is_alive():
            return

        source = self.file_path_var.get().strip()
        output = self.output_path_var.get().strip() or None
        password = self.file_password_var.get()

        if not source:
            messagebox.showwarning("Missing file", "Choose an input file first.")
            return
        if not password:
            messagebox.showwarning("Missing password", "Enter a password first.")
            return
        if (
            self.file_mode_var.get() == "encrypt"
            and password != self.file_password_confirm_var.get()
        ):
            messagebox.showwarning(
                "Passwords do not match",
                "Confirm the password before encrypting so a typo does not lock you out.",
            )
            return

        if self.file_mode_var.get() == "encrypt":
            self._start_file_worker(
                lambda progress: encrypt_file(
                    source,
                    password,
                    destination=output,
                    overwrite=self.overwrite_var.get(),
                    progress_callback=progress,
                ),
                "Encryption",
            )
        else:
            self._start_file_worker(
                lambda progress: decrypt_file(
                    source,
                    password,
                    destination=output,
                    overwrite=self.overwrite_var.get(),
                    progress_callback=progress,
                ),
                "Decryption",
            )

    def _hash_text_action(self) -> None:
        text = self.hash_text_box.get("1.0", "end-1c")
        if not text:
            messagebox.showwarning("Missing text", "Enter some text first.")
            return

        digest = hash_text(text, self.hash_algorithm_var.get())
        label = format_hash_algorithm_label(self.hash_algorithm_var.get())
        self.hash_output_var.set(digest)
        self._set_hash_display(digest)
        self.hash_status_var.set(f"{label} digest created from text input.")

    def _start_hash_worker(self, target: object) -> None:
        # same background-worker idea for hashing
        self.hash_queue = Queue()
        self.hash_progress_var.set(0)
        self.hash_progress_text_var.set("0%")
        self.hash_status_var.set("Hashing file...")
        self.hash_file_button.configure(state="disabled")

        def progress(processed: int, total: int) -> None:
            assert self.hash_queue is not None
            self.hash_queue.put(("progress", processed, total))

        def worker() -> None:
            try:
                result = target(progress)
            except Exception as exc:  # pragma: no cover - shown by the UI
                assert self.hash_queue is not None
                self.hash_queue.put(("error", exc, None))
            else:
                assert self.hash_queue is not None
                self.hash_queue.put(("done", result, None))

        self.hash_worker_thread = Thread(target=worker, daemon=True)
        self.hash_worker_thread.start()
        self.after(80, self._poll_hash_queue)

    def _poll_hash_queue(self) -> None:
        if self.hash_queue is None:
            return

        still_running = self.hash_worker_thread is not None and self.hash_worker_thread.is_alive()
        try:
            while True:
                kind, first, second = self.hash_queue.get_nowait()
                if kind == "progress":
                    processed = int(first)
                    total = int(second)
                    percent = 100.0 if total == 0 else (processed / total) * 100
                    self.hash_progress_var.set(percent)
                    self.hash_progress_text_var.set(
                        f"{percent:0.1f}% - {self._format_bytes(processed)} / {self._format_bytes(total)}"
                    )
                elif kind == "error":
                    self.hash_file_button.configure(state="normal")
                    self.hash_status_var.set(f"Error: {first}")
                    self.hash_progress_text_var.set("Failed")
                    messagebox.showerror("Hash failed", str(first))
                    self.hash_queue = None
                    return
                elif kind == "done":
                    label = format_hash_algorithm_label(self.hash_algorithm_var.get())
                    self.hash_file_button.configure(state="normal")
                    self.hash_progress_var.set(100)
                    self.hash_progress_text_var.set("100%")
                    self.hash_output_var.set(str(first))
                    self._set_hash_display(str(first))
                    self.hash_status_var.set(f"{label} digest created from file input.")
                    self.hash_queue = None
                    return
        except Empty:
            pass

        if still_running:
            self.after(80, self._poll_hash_queue)
        else:
            self.hash_file_button.configure(state="normal")

    def _hash_file_action(self) -> None:
        if self.hash_worker_thread is not None and self.hash_worker_thread.is_alive():
            return

        source = self.hash_file_path_var.get().strip()
        if not source:
            messagebox.showwarning("Missing file", "Choose a file to hash first.")
            return

        self._start_hash_worker(
            lambda progress: hash_file(
                source,
                self.hash_algorithm_var.get(),
                progress_callback=progress,
            )
        )

    def _copy_hash_output(self) -> None:
        digest = self.hash_output_box.get("1.0", "end-1c").strip()
        if not digest:
            messagebox.showwarning("Nothing to copy", "Create a digest first.")
            return

        self.clipboard_clear()
        self.clipboard_append(digest)
        self.hash_status_var.set("Digest copied to clipboard.")

    def _format_bytes(self, size: int) -> str:
        if size < 1024:
            return f"{size} B"

        value = float(size)
        units = ["KB", "MB", "GB", "TB"]
        for unit in units:
            value /= 1024
            if value < 1024 or unit == units[-1]:
                return f"{value:.1f} {unit}"
        return f"{size} B"


def launch_gui() -> int:
    app = CryptoToolsApp()
    app.mainloop()
    return 0
