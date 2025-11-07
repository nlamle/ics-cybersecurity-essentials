"""Automated experiments for Part 2 of the symmetric encryption lab.

This script demonstrates:
 1. ECB pattern leakage on an image file.
 2. Key/IV reuse vulnerability with identical keys across multiple plaintexts.

Outputs are written to the ``analysis_outputs`` directory for easy inclusion in
Deliverable 2.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Dict, Tuple

import numpy as np
import matplotlib.pyplot as plt

from crypto_utils import encrypt_bytes, generate_key_and_iv
from visualization import visualize_image_modes


ROOT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = ROOT_DIR / "analysis_outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Experiment 1: ECB Pattern Leakage
# ---------------------------------------------------------------------------

def run_ecb_leakage_demo() -> Dict[str, str]:
    """Generate the ECB visualization figure and return file references."""
    source_image = ROOT_DIR / "tux.png"
    if not source_image.exists():
        raise FileNotFoundError(
            "Expected tux.png at the project root. Place your image at "
            f"{source_image} and rerun the analysis."
        )

    image_path = OUTPUT_DIR / "tux.png"
    image_path.write_bytes(source_image.read_bytes())

    # Deterministic key/IV for reproducibility
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")

    figure_path = OUTPUT_DIR / "ecb_vs_modes.png"
    visualize_image_modes(
        image_path,
        "aes",
        key,
        iv,
        save_path=figure_path,
        show=False,
    )

    return {
        "test_image": str(image_path.relative_to(ROOT_DIR)),
        "visualization": str(figure_path.relative_to(ROOT_DIR)),
        "key_hex": key.hex(),
        "iv_hex": iv.hex(),
    }


# ---------------------------------------------------------------------------
# Experiment 2: Key reuse analysis
# ---------------------------------------------------------------------------

def _encrypt_with_reused_material(
    plaintext_a: bytes,
    plaintext_b: bytes,
    *,
    mode: str,
) -> Tuple[bytes, bytes]:
    key = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
    iv = bytes.fromhex("1112131415161718191a1b1c1d1e1f20")
    ciphertext_a = encrypt_bytes(plaintext_a, "aes", mode, key, iv if mode != "ecb" else None)
    ciphertext_b = encrypt_bytes(plaintext_b, "aes", mode, key, iv if mode != "ecb" else None)
    return ciphertext_a, ciphertext_b


def _similarity_metrics(cipher_a: bytes, cipher_b: bytes) -> Dict[str, float]:
    min_len = min(len(cipher_a), len(cipher_b))
    xor = np.frombuffer(bytes(a ^ b for a, b in zip(cipher_a[:min_len], cipher_b[:min_len])), dtype=np.uint8)
    identical_fraction = float((xor == 0).mean())

    hist_a, _ = np.histogram(np.frombuffer(cipher_a, dtype=np.uint8), bins=256, range=(0, 255), density=True)
    hist_b, _ = np.histogram(np.frombuffer(cipher_b, dtype=np.uint8), bins=256, range=(0, 255), density=True)
    histogram_distance = float(np.linalg.norm(hist_a - hist_b))
    return {
        "min_length": float(min_len),
        "identical_fraction": identical_fraction,
        "histogram_distance": histogram_distance,
    }


def _save_histogram_plot(
    cipher_a: bytes,
    cipher_b: bytes,
    save_path: Path,
    *,
    title: str,
    labels: Tuple[str, str],
) -> None:
    """Persist side-by-side ciphertext histograms for reporting."""
    data_a = np.frombuffer(cipher_a, dtype=np.uint8)
    data_b = np.frombuffer(cipher_b, dtype=np.uint8)

    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    axes[0].hist(data_a, bins=256, range=(0, 255), color="steelblue")
    axes[0].set_title(f"{labels[0]}\nlen={len(data_a)}")
    axes[1].hist(data_b, bins=256, range=(0, 255), color="tomato")
    axes[1].set_title(f"{labels[1]}\nlen={len(data_b)}")

    for ax in axes:
        ax.set_xlabel("Byte value")
        ax.set_ylabel("Frequency")

    fig.suptitle(title)
    plt.tight_layout()
    save_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(save_path)
    plt.close(fig)


def run_key_reuse_demo() -> Dict[str, Dict[str, float]]:
    """Encrypt two plaintexts with the same key/IV in CBC and CTR modes."""
    plaintext_a = (
        b"AES and DES are symmetric ciphers. Reusing IVs is dangerous because it leaks patterns.\n"
    )
    plaintext_b = (
        b"This second message shares the same encryption key and IV. Attackers can correlate ciphertexts.\n"
    )

    results: Dict[str, Dict[str, float]] = {}

    for mode in ("cbc", "ctr"):
        cipher_a, cipher_b = _encrypt_with_reused_material(plaintext_a, plaintext_b, mode=mode)

        cipher1_path = OUTPUT_DIR / f"reuse_{mode}_cipher1.bin"
        cipher2_path = OUTPUT_DIR / f"reuse_{mode}_cipher2.bin"
        cipher1_path.write_bytes(cipher_a)
        cipher2_path.write_bytes(cipher_b)

        # Save histograms for visual evidence
        hist_path = OUTPUT_DIR / f"hist_{mode}_comparison.png"

        _save_histogram_plot(
            cipher_a,
            cipher_b,
            hist_path,
            title=f"{mode.upper()} ciphertext histograms",
            labels=(cipher1_path.name, cipher2_path.name),
        )

        metrics = _similarity_metrics(cipher_a, cipher_b)
        results[mode.upper()] = {**metrics, "histogram_plot": str(hist_path.relative_to(ROOT_DIR))}

    return results


# ---------------------------------------------------------------------------
# Experiment 3: Structured data (CSV) under ECB vs CBC
# ---------------------------------------------------------------------------


def _block_analysis(ciphertext: bytes, block_size: int = 16) -> Dict[str, float]:
    blocks = [ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)]
    counter = Counter(blocks)
    total_blocks = len(blocks)
    unique_blocks = len(counter)
    duplicate_blocks = sum(1 for count in counter.values() if count > 1)
    most_common = counter.most_common(1)[0][1] if counter else 0

    return {
        "total_blocks": float(total_blocks),
        "unique_blocks": float(unique_blocks),
        "duplicate_blocks": float(duplicate_blocks),
        "most_common_frequency": float(most_common),
        "duplicate_ratio": float(duplicate_blocks / total_blocks) if total_blocks else 0.0,
    }


def run_structured_data_demo() -> Dict[str, Dict[str, float]]:
    csv_path = ROOT_DIR / "studentdata.csv"
    if not csv_path.exists():
        raise FileNotFoundError(
            "Expected studentdata.csv at the project root. Place the CSV at "
            f"{csv_path} and rerun the analysis."
        )

    base_plaintext = csv_path.read_bytes()
    # Repeat the CSV content to intentionally introduce repeated blocks so ECB leakage is visible.
    plaintext = base_plaintext * 32
    key = bytes.fromhex("00102030405060708090a0b0c0d0e0f0")
    iv = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")

    ecb_cipher = encrypt_bytes(plaintext, "aes", "ecb", key, None)
    cbc_cipher = encrypt_bytes(plaintext, "aes", "cbc", key, iv)

    (OUTPUT_DIR / "student_ecb.bin").write_bytes(ecb_cipher)
    (OUTPUT_DIR / "student_cbc.bin").write_bytes(cbc_cipher)

    return {
        "ECB": _block_analysis(ecb_cipher),
        "CBC": _block_analysis(cbc_cipher),
        "plaintext_preview": base_plaintext.decode("utf-8", errors="replace"),
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> None:
    report: Dict[str, object] = {}
    report["ecb_demo"] = run_ecb_leakage_demo()
    report["key_reuse"] = run_key_reuse_demo()
    report["structured_data"] = run_structured_data_demo()

    summary_path = OUTPUT_DIR / "part2_summary.json"
    summary_path.write_text(json.dumps(report, indent=2))

    print("Part 2 analysis complete. Summary written to:", summary_path)
    print("Key points:")
    print("  - ECB visualization saved as ecb_vs_modes.png")
    print("  - Ciphertexts for key reuse experiments saved as reuse_cbc_*.bin and reuse_ctr_*.bin")
    for mode, metrics in report["key_reuse"].items():
        print(f"    {mode}: identical bytes = {metrics['identical_fraction']:.2%}, histogram distance = {metrics['histogram_distance']:.4f}")
        print(f"       histogram figure: {metrics['histogram_plot']}")

    ecb_stats = report["structured_data"]["ECB"]
    cbc_stats = report["structured_data"]["CBC"]
    print("  - Structured data encrypted under ECB (student_ecb.bin) vs CBC (student_cbc.bin)")
    print(
        "    ECB duplicate blocks:",
        f"{int(ecb_stats['duplicate_blocks'])}/{int(ecb_stats['total_blocks'])}"
        f" (ratio {ecb_stats['duplicate_ratio']:.2%})",
    )
    print(
        "    CBC duplicate blocks:",
        f"{int(cbc_stats['duplicate_blocks'])}/{int(cbc_stats['total_blocks'])}"
        f" (ratio {cbc_stats['duplicate_ratio']:.2%})",
    )


if __name__ == "__main__":
    main()
