"""Graphical user interface for the symmetric encryption lab tool."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from crypto_utils import (
    InvalidParameterError,
    decrypt_bytes,
    encrypt_bytes,
    generate_key_and_iv,
)
from visualization import create_test_pattern, visualize_image_modes


ALGORITHM_OPTIONS = ("AES", "DES")
MODE_OPTIONS = ("ECB", "CBC", "CTR")


class EncryptionTool:
    """Tkinter-based editor for encrypting/decrypting data and running demos."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Encryption Lab Tool")
        self.root.geometry("620x520")

        self.algo_var = tk.StringVar(value=ALGORITHM_OPTIONS[0])
        self.mode_var = tk.StringVar(value=MODE_OPTIONS[1])  # default CBC
        self.key_entry: ttk.Entry
        self.iv_entry: ttk.Entry

        self.file_label: ttk.Label
        self.current_file: Optional[Path] = None
        self.status_var = tk.StringVar(value="Ready to encrypt/decrypt files")

        self._build_ui()
        self._configure_traces()
        self._refresh_random_material()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        main_frame = ttk.Frame(self.root, padding="12")
        main_frame.grid(row=0, column=0, sticky=tk.NSEW)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Algorithm selection
        ttk.Label(main_frame, text="Encryption Algorithm:").grid(row=0, column=0, sticky=tk.W, pady=4)
        algo_frame = ttk.Frame(main_frame)
        algo_frame.grid(row=0, column=1, columnspan=3, sticky=tk.W)
        for option in ALGORITHM_OPTIONS:
            ttk.Radiobutton(algo_frame, text=option, value=option, variable=self.algo_var).pack(side=tk.LEFT)

        # Mode selection
        ttk.Label(main_frame, text="Cipher Mode:").grid(row=1, column=0, sticky=tk.W, pady=4)
        mode_frame = ttk.Frame(main_frame)
        mode_frame.grid(row=1, column=1, columnspan=3, sticky=tk.W)
        for option in MODE_OPTIONS:
            ttk.Radiobutton(mode_frame, text=option, value=option, variable=self.mode_var).pack(side=tk.LEFT)

        # Key / IV inputs
        ttk.Label(main_frame, text="Encryption Key (hex):").grid(row=2, column=0, sticky=tk.W, pady=4)
        self.key_entry = ttk.Entry(main_frame, width=58)
        self.key_entry.grid(row=2, column=1, columnspan=3, sticky=tk.EW, pady=4)

        ttk.Label(main_frame, text="IV / Nonce (hex):").grid(row=3, column=0, sticky=tk.W, pady=4)
        self.iv_entry = ttk.Entry(main_frame, width=58)
        self.iv_entry.grid(row=3, column=1, columnspan=3, sticky=tk.EW, pady=4)

        # File selection
        ttk.Button(main_frame, text="Select File", command=self._select_file).grid(row=4, column=0, pady=10)
        self.file_label = ttk.Label(main_frame, text="No file selected", foreground="gray")
        self.file_label.grid(row=4, column=1, columnspan=3, sticky=tk.W, pady=10)

        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=4, pady=10)
        ttk.Button(button_frame, text="Generate Random Key/IV", command=self._refresh_random_material).pack(side=tk.LEFT, padx=4)
        ttk.Button(button_frame, text="Encrypt File", command=self._encrypt_file, style="Accent.TButton").pack(side=tk.LEFT, padx=4)
        ttk.Button(button_frame, text="Decrypt File", command=self._decrypt_file).pack(side=tk.LEFT, padx=4)

        # Visualization
        viz_frame = ttk.LabelFrame(main_frame, text="Pattern Visualization", padding="8")
        viz_frame.grid(row=6, column=0, columnspan=4, sticky=tk.EW, pady=10)
        ttk.Button(viz_frame, text="Create Test Image & Encrypt", command=self._create_and_visualize).pack(side=tk.LEFT, padx=4)
        ttk.Button(viz_frame, text="Encrypt Selected Image", command=self._visualize_selected_image).pack(side=tk.LEFT, padx=4)

        # Status bar
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, padding="6")
        status_bar.grid(row=7, column=0, columnspan=4, sticky=tk.EW, pady=(8, 0))

        main_frame.columnconfigure(1, weight=1)

    def _configure_traces(self) -> None:
        self.algo_var.trace_add("write", lambda *_: self._refresh_random_material())
        self.mode_var.trace_add("write", lambda *_: self._refresh_random_material())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _select_file(self) -> None:
        filename = filedialog.askopenfilename(title="Select file to encrypt/decrypt", filetypes=[("All files", "*.*")])
        if filename:
            self.current_file = Path(filename)
            self.file_label.configure(text=os.path.basename(filename), foreground="black")
            self.status_var.set(f"Selected: {os.path.basename(filename)}")

    def _refresh_random_material(self) -> None:
        algorithm = self.algo_var.get().lower()
        mode = self.mode_var.get().lower()
        key, iv = generate_key_and_iv(algorithm, mode)
        if iv is None:
            _, iv = generate_key_and_iv(algorithm, "cbc")
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key.hex())
        self.iv_entry.delete(0, tk.END)
        self.iv_entry.insert(0, iv.hex())
        self.status_var.set("Random key/IV generated")

    def _hex_to_bytes(self, value: str) -> Optional[bytes]:
        value = value.strip()
        if not value:
            return None
        try:
            return bytes.fromhex(value)
        except ValueError:
            messagebox.showerror("Error", "Invalid hex string in key or IV")
            return None

    def _gather_material(self, *, allow_generation: bool) -> Optional[Tuple[str, str, bytes, Optional[bytes]]]:
        algorithm = self.algo_var.get().lower()
        mode = self.mode_var.get().lower()
        key_hex = self.key_entry.get().strip()
        iv_hex = self.iv_entry.get().strip() if mode != "ecb" else ""

        if not key_hex and not allow_generation:
            messagebox.showwarning("Missing key", "Provide the key used during encryption.")
            return None

        try:
            key, iv = generate_key_and_iv(algorithm, mode, key_hex, iv_hex or None)
        except (ValueError, InvalidParameterError) as exc:
            messagebox.showerror("Invalid parameters", str(exc))
            return None

        if allow_generation:
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, key.hex())
            if iv:
                self.iv_entry.config(state=tk.NORMAL)
                self.iv_entry.delete(0, tk.END)
                self.iv_entry.insert(0, iv.hex())

        return algorithm, mode, key, iv

    # ------------------------------------------------------------------
    # Encryption / Decryption
    # ------------------------------------------------------------------
    def _encrypt_file(self) -> None:
        if not self.current_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return

        material = self._gather_material(allow_generation=True)
        if material is None:
            return
        algorithm, mode, key, iv = material

        try:
            plaintext = self.current_file.read_bytes()
            ciphertext = encrypt_bytes(plaintext, algorithm, mode, key, iv if mode != "ecb" else None)
        except InvalidParameterError as exc:
            messagebox.showerror("Encryption error", str(exc))
            return
        except Exception as exc:  # pragma: no cover - file/system errors
            messagebox.showerror("Encryption error", str(exc))
            return

        output_file = filedialog.asksaveasfilename(
            title="Save encrypted file as...",
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")],
        )
        if not output_file:
            return

        Path(output_file).write_bytes(ciphertext)
        self.status_var.set(f"Encrypted: {os.path.basename(output_file)}")
        messagebox.showinfo("Success", "File encrypted successfully!")

    def _decrypt_file(self) -> None:
        if not self.current_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return

        material = self._gather_material(allow_generation=False)
        if material is None:
            return
        algorithm, mode, key, iv = material

        try:
            ciphertext = self.current_file.read_bytes()
            plaintext = decrypt_bytes(ciphertext, algorithm, mode, key, iv if mode != "ecb" else None)
        except InvalidParameterError as exc:
            messagebox.showerror("Decryption error", str(exc))
            return
        except ValueError as exc:
            messagebox.showerror("Decryption error", f"Check your key/IV: {exc}")
            return
        except Exception as exc:  # pragma: no cover
            messagebox.showerror("Decryption error", str(exc))
            return

        output_file = filedialog.asksaveasfilename(
            title="Save decrypted file as...",
            defaultextension=".dec",
            filetypes=[("All files", "*.*")],
        )
        if not output_file:
            return

        Path(output_file).write_bytes(plaintext)
        self.status_var.set(f"Decrypted: {os.path.basename(output_file)}")
        messagebox.showinfo("Success", "File decrypted successfully!")

    # ------------------------------------------------------------------
    # Visualization
    # ------------------------------------------------------------------
    def _create_and_visualize(self) -> None:
        try:
            test_path = Path.cwd() / "test_pattern.png"
            create_test_pattern(test_path)
            self.current_file = test_path
            self.file_label.configure(text=test_path.name, foreground="black")
            self._visualize_image(test_path)
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to create visualization: {exc}")

    def _visualize_selected_image(self) -> None:
        if not self.current_file:
            messagebox.showwarning("Warning", "Please select an image file first")
            return
        self._visualize_image(self.current_file)

    def _visualize_image(self, image_path: Path) -> None:
        key = self._hex_to_bytes(self.key_entry.get())
        iv = self._hex_to_bytes(self.iv_entry.get())
        if not key or not iv:
            messagebox.showwarning("Missing key/IV", "Provide both key and IV for visualization.")
            return

        algorithm = self.algo_var.get().lower()
        try:
            visualize_image_modes(image_path, algorithm, key, iv)
            self.status_var.set("Visualization completed – observe ECB pattern leakage")
        except Exception as exc:
            messagebox.showerror("Visualization error", str(exc))


__all__ = ["EncryptionTool"]
