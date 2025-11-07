"""Application entry point for the encryption lab GUI."""

import tkinter as tk

from gui import EncryptionTool


def main() -> None:
    root = tk.Tk()
    EncryptionTool(root)
    root.mainloop()


if __name__ == "__main__":
    main()
