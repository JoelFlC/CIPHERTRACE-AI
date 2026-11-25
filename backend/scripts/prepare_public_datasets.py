"""Inspect public CSV/Parquet datasets in backend/data/raw/ and optionally run training."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
BACKEND_DIR = SCRIPT_PATH.parent.parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import RAW_DATA_DIR, ensure_directories  # noqa: E402
from app.ml.dataset_builder import (  # noqa: E402
    _list_raw_dataset_files,
    build_or_load_dataset_with_metadata,
)
from app.ml.train_pipeline import run_training_pipeline  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect CIC-IDS2017 / CTU-13 / DoHBrw-2020 files in backend/data/raw/."
    )
    parser.add_argument(
        "--train",
        action="store_true",
        help="Run full training pipeline after inspecting datasets.",
    )
    args = parser.parse_args()

    ensure_directories()
    raw_files = _list_raw_dataset_files(RAW_DATA_DIR)
    print(f"[CIPHERTRACE DATASETS] Carpeta inspeccionada: {RAW_DATA_DIR}")

    if not raw_files:
        print(
            "[CIPHERTRACE DATASETS] No se encontraron archivos .csv/.parquet en backend/data/raw/.\n"
            "  Para usar datasets reales, coloca archivos de CIC-IDS2017, CTU-13 o\n"
            "  BCCC-CIRA-CIC-DoHBrw-2020 en backend/data/raw/ y vuelve a ejecutar con --train.\n"
            "  Mientras tanto, se mantiene activo el respaldo estadístico automático."
        )
    else:
        print(f"[CIPHERTRACE DATASETS] Detectados {len(raw_files)} archivo(s):")
        for fpath in raw_files:
            print(f"  - {fpath.name} ({fpath.stat().st_size:,} bytes)")

    df, breakdown = build_or_load_dataset_with_metadata(force_rebuild=True)
    print(f"[CIPHERTRACE DATASETS] Modo de procedencia: {breakdown['mode']}")
    print(
        f"[CIPHERTRACE DATASETS] Total flujos preparados: {len(df)} "
        f"(públicos reales={breakdown['public_raw_flows']}, "
        f"laboratorio/respaldo={breakdown['fallback_or_lab_flows']})"
    )

    if breakdown.get("by_file"):
        print("[CIPHERTRACE DATASETS] Desglose por archivo real cargado:")
        for fname, info in breakdown["by_file"].items():
            print(f"  * {fname}: {info['total_loaded']} filas -> {info['by_class']}")

    print("[CIPHERTRACE DATASETS] Desglose por clase:")
    for label, counts in breakdown["by_class"].items():
        print(
            f"  {label:<15} -> public_raw={counts['public_raw']}, "
            f"fallback_or_lab={counts['fallback_or_lab']}"
        )

    if args.train:
        print("\n[CIPHERTRACE DATASETS] Iniciando reentrenamiento completo...")
        run_training_pipeline()


if __name__ == "__main__":
    main()
