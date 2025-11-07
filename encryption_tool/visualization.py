"""Visualization helpers for encryption mode comparisons."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple

import matplotlib.pyplot as plt
import numpy as np
from PIL import Image

from crypto_utils import encrypt_bytes


def create_test_pattern(path: Path) -> Path:
    """Create a grayscale test image that exposes ECB leakage."""
    width, height = 300, 200
    img = Image.new("L", (width, height), color=128)
    pixels = img.load()

    for x in range(width):
        for y in range(height):
            pixels[x, y] = 200 if (x // 30) % 2 == 0 else 50

    for x in range(50, 150):
        for y in range(50, 100):
            pixels[x, y] = 255

    img.save(path)
    return path


def _load_image_grayscale(image_path: Path) -> Tuple[np.ndarray, bytes, Tuple[int, ...]]:
    img = Image.open(image_path).convert("L")
    array = np.array(img)
    return array, img.tobytes(), array.shape


def visualize_image_modes(
    image_path: Path,
    algorithm: str,
    key: bytes,
    iv: bytes,
    *,
    save_path: Optional[Path] = None,
    show: bool = True,
) -> None:
    """Encrypt an image in multiple modes using supplied material and display results.

    Parameters
    ----------
    image_path:
        Path to the source image.
    algorithm:
        "aes" or "des".
    key / iv:
        Binary key material used for encryption.
    save_path:
        Optional path to save the resulting matplotlib figure.
    show:
        When True (default), display the figure with ``plt.show()``. Set to False when
        running in headless scripts or tests.
    """
    if not image_path.exists():
        raise FileNotFoundError(f"Image not found: {image_path}")

    original_array, original_bytes, shape = _load_image_grayscale(image_path)

    modes = ["ecb", "cbc", "ctr"]
    figures: List[Tuple[str, np.ndarray]] = [("Original", original_array)]

    for mode in modes:
        mode_iv = iv if mode != "ecb" else None
        ciphertext = encrypt_bytes(original_bytes, algorithm, mode, key, mode_iv)
        trimmed = ciphertext[: len(original_bytes)]
        cipher_array = np.frombuffer(trimmed, dtype=np.uint8).reshape(shape)
        figures.append((mode.upper(), cipher_array))

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    titles = {
        "Original": "Original Image",
        "ECB": "ECB Mode - Patterns Visible",
        "CBC": "CBC Mode - Patterns Hidden",
        "CTR": "CTR Mode - Patterns Hidden",
    }

    for idx, (label, array) in enumerate(figures):
        ax = axes[idx // 2, idx % 2]
        ax.imshow(array, cmap="gray", aspect="auto")
        title = titles.get(label, label)
        ax.set_title(title, fontweight="bold")
        if label == "ECB":
            ax.title.set_color("red")
        ax.axis("off")

    plt.tight_layout()

    if save_path:
        save_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(save_path)

    if show:
        plt.show()
    else:
        plt.close(fig)
