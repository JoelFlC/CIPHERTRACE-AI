#!/usr/bin/env bash
set -euo pipefail

ARTIFACTS_DIR="/app/artifacts"
REQUIRED_FILES=(
  "scaler.joblib"
  "mlp_model.joblib"
  "autoencoder.pt"
  "rf_model.joblib"
  "iforest_model.joblib"
  "ga_config.json"
  "model_metrics.json"
)

MISSING=0
for f in "${REQUIRED_FILES[@]}"; do
  if [ ! -f "${ARTIFACTS_DIR}/${f}" ]; then
    MISSING=1
    break
  fi
done

if [ "${MISSING}" -eq 1 ]; then
  echo "[CIPHERTRACE] Artefactos ML/DL incompletos en ${ARTIFACTS_DIR}. Ejecutando entrenamiento inicial..."
  python -m app.ml.train_pipeline
else
  echo "[CIPHERTRACE] Artefactos ML/DL verificados en ${ARTIFACTS_DIR}."
fi

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
