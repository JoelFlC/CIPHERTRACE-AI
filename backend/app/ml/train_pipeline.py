"""Master training, 5-fold StratifiedKFold CV, GA optimization, and artifact export pipeline."""

from __future__ import annotations

import json
import time
import warnings
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

from app.core.config import (
    AUTOENCODER_PATH,
    FEATURE_COLUMNS,
    GA_CONFIG_PATH,
    IFOREST_MODEL_PATH,
    LABEL_CLASSES,
    LABEL_TO_ID,
    MLP_MODEL_PATH,
    MODEL_METRICS_PATH,
    PROCESSED_DATASET_PATH,
    RANDOM_SEED,
    RF_MODEL_PATH,
    SCALER_PATH,
    TARGET_BINARY_COL,
    TARGET_CLASS_COL,
    ensure_directories,
)
from app.ml.autoencoder import TabularAutoencoderDetector
from app.ml.dataset_builder import build_or_load_dataset_with_metadata
from app.ml.genetic_optimizer import GeneticOptimizer

warnings.filterwarnings("ignore", category=UserWarning)


def _compute_binary_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    latencies_ms: list[float],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metrics: dict[str, Any] = {
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "avg_latency_ms": round(float(np.mean(latencies_ms)), 6),
    }
    if extra:
        metrics.update(extra)
    return metrics


def run_training_pipeline() -> dict[str, Any]:
    """Execute dataset build, GA optimization, 5-fold CV across 4 models, and export."""
    ensure_directories()

    print("[1/5] Building/loading standardized passive metadata dataset...")
    df, source_breakdown = build_or_load_dataset_with_metadata(force_rebuild=True)
    X_raw = df[FEATURE_COLUMNS].to_numpy(dtype=np.float64)
    y_class = df[TARGET_CLASS_COL].map(LABEL_TO_ID).to_numpy(dtype=int)
    y_binary = df[TARGET_BINARY_COL].to_numpy(dtype=int)
    benign_id = LABEL_TO_ID["BENIGN"]

    print(
        f"      Dataset ready: {len(df)} flows, {len(FEATURE_COLUMNS)} features, "
        f"classes={df[TARGET_CLASS_COL].value_counts().to_dict()}"
    )

    print("[2/5] Running Genetic Algorithm (Phase 1: Feature Selection)...")
    X_tr_raw, X_val_raw, y_tr_bin, y_val_bin = train_test_split(
        X_raw,
        y_binary,
        test_size=0.20,
        stratify=y_class,
        random_state=RANDOM_SEED,
    )
    ga_scaler = StandardScaler()
    X_tr_scaled = ga_scaler.fit_transform(X_tr_raw)
    X_val_scaled = ga_scaler.transform(X_val_raw)

    ga = GeneticOptimizer(seed=RANDOM_SEED)
    ga_phase1 = ga.optimize_features(
        X_train=X_tr_scaled,
        y_train_binary=y_tr_bin,
        X_val=X_val_scaled,
        y_val_binary=y_val_bin,
        feature_names=FEATURE_COLUMNS,
        n_pop=16,
        n_gen=15,
    )
    ga_mask = np.array(ga_phase1["mask"], dtype=bool)
    print(
        f"      Selected {int(ga_mask.sum())}/{len(FEATURE_COLUMNS)} features: "
        f"{ga_phase1['selected_features']}"
    )

    print("[3/5] Running 5-fold StratifiedKFold Cross-Validation across 4 models...")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)

    n_total = len(df)
    oof_rf_pred = np.zeros(n_total, dtype=int)
    oof_rf_class = np.zeros(n_total, dtype=int)
    oof_mlp_pred = np.zeros(n_total, dtype=int)
    oof_mlp_class = np.zeros(n_total, dtype=int)
    oof_mlp_prob = np.zeros(n_total, dtype=float)
    oof_ae_pred = np.zeros(n_total, dtype=int)
    oof_ae_score = np.zeros(n_total, dtype=float)
    oof_if_pred = np.zeros(n_total, dtype=int)

    latencies: dict[str, list[float]] = {
        "random_forest": [],
        "mlp": [],
        "autoencoder": [],
        "isolation_forest": [],
    }

    for fold_idx, (train_idx, test_idx) in enumerate(skf.split(X_raw, y_class), start=1):
        fold_scaler = StandardScaler()
        X_train_fold = fold_scaler.fit_transform(X_raw[train_idx])[:, ga_mask]
        X_test_fold = fold_scaler.transform(X_raw[test_idx])[:, ga_mask]

        y_train_cls = y_class[train_idx]
        y_train_bin = y_binary[train_idx]
        benign_mask_train = y_train_bin == 0
        X_train_benign = X_train_fold[benign_mask_train]
        n_test = len(test_idx)

        # 1) Random Forest (multiclass)
        rf = RandomForestClassifier(
            n_estimators=150,
            max_depth=16,
            random_state=RANDOM_SEED,
            n_jobs=-1,
        )
        rf.fit(X_train_fold, y_train_cls)
        t0 = time.perf_counter()
        rf_probs = rf.predict_proba(X_test_fold)
        rf_cls_pred = np.argmax(rf_probs, axis=1)
        t1 = time.perf_counter()
        latencies["random_forest"].append(((t1 - t0) * 1000.0) / n_test)
        oof_rf_class[test_idx] = rf_cls_pred
        oof_rf_pred[test_idx] = (rf_cls_pred != benign_id).astype(int)

        # 2) Neural Network MLP (multiclass)
        mlp = MLPClassifier(
            hidden_layer_sizes=(64, 32),
            activation="relu",
            max_iter=200,
            early_stopping=True,
            random_state=RANDOM_SEED,
        )
        mlp.fit(X_train_fold, y_train_cls)
        t0 = time.perf_counter()
        mlp_probs = mlp.predict_proba(X_test_fold)
        mlp_cls_pred = np.argmax(mlp_probs, axis=1)
        t1 = time.perf_counter()
        latencies["mlp"].append(((t1 - t0) * 1000.0) / n_test)
        oof_mlp_class[test_idx] = mlp_cls_pred
        oof_mlp_prob[test_idx] = 1.0 - mlp_probs[:, benign_id]
        oof_mlp_pred[test_idx] = (mlp_cls_pred != benign_id).astype(int)

        # 3) PyTorch Autoencoder (trained strictly on BENIGN traffic)
        ae = TabularAutoencoderDetector(
            input_dim=X_train_fold.shape[1], seed=RANDOM_SEED
        )
        ae.fit(X_train_benign, epochs=45, batch_size=64, lr=1e-3)
        t0 = time.perf_counter()
        ae_scores = ae.predict_scores(X_test_fold)
        ae_preds = (ae_scores >= 0.5).astype(int)
        t1 = time.perf_counter()
        latencies["autoencoder"].append(((t1 - t0) * 1000.0) / n_test)
        oof_ae_score[test_idx] = ae_scores
        oof_ae_pred[test_idx] = ae_preds

        # 4) Isolation Forest (trained strictly on BENIGN traffic)
        iforest = IsolationForest(
            n_estimators=150,
            contamination=0.05,
            random_state=RANDOM_SEED,
            n_jobs=-1,
        )
        iforest.fit(X_train_benign)
        t0 = time.perf_counter()
        if_raw = iforest.predict(X_test_fold)
        if_preds = (if_raw == -1).astype(int)
        t1 = time.perf_counter()
        latencies["isolation_forest"].append(((t1 - t0) * 1000.0) / n_test)
        oof_if_pred[test_idx] = if_preds

        print(f"      Fold {fold_idx}/5 complete.")

    print("[4/5] Running Genetic Algorithm (Phase 2: Hybrid Ensemble Weights)...")
    ga_phase2 = ga.optimize_ensemble_weights(
        mlp_probs=oof_mlp_prob,
        ae_scores=oof_ae_score,
        y_binary=y_binary,
        n_pop=24,
        n_gen=20,
    )
    w_mlp = float(ga_phase2["w_mlp"])
    w_ae = float(ga_phase2["w_ae"])
    thr = float(ga_phase2["threshold"])

    hybrid_score = w_mlp * oof_mlp_prob + w_ae * oof_ae_score
    hybrid_pred = (hybrid_score >= thr).astype(int)
    cm = confusion_matrix(y_binary, hybrid_pred, labels=[0, 1])
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    model_metrics = {
        "dataset": {
            "path": str(PROCESSED_DATASET_PATH),
            "total_flows": int(n_total),
            "total_features": len(FEATURE_COLUMNS),
            "selected_features_count": int(ga_mask.sum()),
            "classes": LABEL_CLASSES,
            "cv_folds": 5,
            "source_breakdown": source_breakdown,
        },
        "models": {
            "random_forest": _compute_binary_metrics(
                y_binary,
                oof_rf_pred,
                latencies["random_forest"],
                extra={
                    "display_name": "Random Forest",
                    "paradigm": "Supervised Multiclass",
                    "multiclass_f1_macro": round(
                        float(f1_score(y_class, oof_rf_class, average="macro")), 4
                    ),
                },
            ),
            "mlp": _compute_binary_metrics(
                y_binary,
                oof_mlp_pred,
                latencies["mlp"],
                extra={
                    "display_name": "MLP Neural Network",
                    "paradigm": "Supervised Deep Learning",
                    "multiclass_f1_macro": round(
                        float(f1_score(y_class, oof_mlp_class, average="macro")), 4
                    ),
                },
            ),
            "autoencoder": _compute_binary_metrics(
                y_binary,
                oof_ae_pred,
                latencies["autoencoder"],
                extra={
                    "display_name": "PyTorch Autoencoder",
                    "paradigm": "Unsupervised Zero-Day (Benign-Only)",
                },
            ),
            "isolation_forest": _compute_binary_metrics(
                y_binary,
                oof_if_pred,
                latencies["isolation_forest"],
                extra={
                    "display_name": "Isolation Forest",
                    "paradigm": "Unsupervised Anomaly (Benign-Only)",
                },
            ),
        },
        "hybrid_ensemble": {
            **_compute_binary_metrics(
                y_binary,
                hybrid_pred,
                [
                    mlp_lat + ae_lat
                    for mlp_lat, ae_lat in zip(
                        latencies["mlp"], latencies["autoencoder"]
                    )
                ],
                extra={
                    "display_name": "GA-Optimized Hybrid (MLP + Autoencoder)",
                    "w_mlp": w_mlp,
                    "w_ae": w_ae,
                    "threshold": thr,
                },
            ),
            "confusion_matrix": {
                "labels": ["BENIGN (0)", "MALICIOUS (1)"],
                "matrix": [[tn, fp], [fn, tp]],
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "tp": tp,
            },
        },
    }

    print("[5/5] Training final production models on full dataset & exporting artifacts...")
    final_scaler = StandardScaler()
    X_all_scaled = final_scaler.fit_transform(X_raw)
    X_all_selected = X_all_scaled[:, ga_mask]
    X_all_benign = X_all_selected[y_binary == 0]

    final_rf = RandomForestClassifier(
        n_estimators=150, max_depth=16, random_state=RANDOM_SEED, n_jobs=-1
    ).fit(X_all_selected, y_class)

    final_mlp = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        activation="relu",
        max_iter=200,
        early_stopping=True,
        random_state=RANDOM_SEED,
    ).fit(X_all_selected, y_class)

    final_iforest = IsolationForest(
        n_estimators=150, contamination=0.05, random_state=RANDOM_SEED, n_jobs=-1
    ).fit(X_all_benign)

    final_ae = TabularAutoencoderDetector(
        input_dim=X_all_selected.shape[1], seed=RANDOM_SEED
    ).fit(X_all_benign, epochs=45, batch_size=64, lr=1e-3)

    joblib.dump(final_scaler, SCALER_PATH)
    joblib.dump(final_rf, RF_MODEL_PATH)
    joblib.dump(final_mlp, MLP_MODEL_PATH)
    joblib.dump(final_iforest, IFOREST_MODEL_PATH)
    final_ae.save(AUTOENCODER_PATH)

    ga_config = {
        "feature_columns": FEATURE_COLUMNS,
        "ga_mask": ga_phase1["mask"],
        "selected_features": ga_phase1["selected_features"],
        "discarded_features": ga_phase1["discarded_features"],
        "weights": {"w_mlp": w_mlp, "w_ae": w_ae},
        "threshold": thr,
        "phase1_feature_selection": {
            "best_fitness": ga_phase1["best_fitness"],
            "best_f1": ga_phase1["best_f1"],
            "history": ga_phase1["history"],
        },
        "phase2_weight_optimization": {
            "best_f1": ga_phase2["best_f1"],
            "history": ga_phase2["history"],
        },
    }

    with open(GA_CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(ga_config, fh, indent=2)
    with open(MODEL_METRICS_PATH, "w", encoding="utf-8") as fh:
        json.dump(model_metrics, fh, indent=2)

    print("\n=== CIPHERTRACE AI — 5-Fold Cross-Validation Summary ===")
    print(f"{'Model':<38} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'Latency(ms)':>13}")
    print("-" * 85)
    for key in ("random_forest", "mlp", "autoencoder", "isolation_forest"):
        m = model_metrics["models"][key]
        print(
            f"{m['display_name']:<38} {m['precision']:>10.4f} {m['recall']:>10.4f} "
            f"{m['f1_score']:>10.4f} {m['avg_latency_ms']:>13.6f}"
        )
    hyb = model_metrics["hybrid_ensemble"]
    print("-" * 85)
    print(
        f"{hyb['display_name']:<38} {hyb['precision']:>10.4f} {hyb['recall']:>10.4f} "
        f"{hyb['f1_score']:>10.4f} {hyb['avg_latency_ms']:>13.6f}"
    )
    print(
        f"\nHybrid GA Weights: w_mlp={w_mlp:.4f}, w_ae={w_ae:.4f}, threshold={thr:.4f}"
    )
    print(f"Hybrid Confusion Matrix [[TN, FP], [FN, TP]]: {cm.tolist()}")
    print(f"Artifacts saved to: {SCALER_PATH.parent}")
    return model_metrics


if __name__ == "__main__":
    run_training_pipeline()
