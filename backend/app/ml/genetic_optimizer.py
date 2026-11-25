"""Pure NumPy Genetic Algorithm for passive feature selection and ensemble weight optimization."""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score

from app.core.config import RANDOM_SEED


class GeneticOptimizer:
    """Two-phase Genetic Algorithm optimizer implemented in pure NumPy."""

    def __init__(self, seed: int = RANDOM_SEED) -> None:
        self.seed = int(seed)
        self.rng = np.random.default_rng(self.seed)

    def _ensure_min_features(self, mask: np.ndarray, min_features: int) -> np.ndarray:
        fixed = mask.copy()
        if int(fixed.sum()) < min_features:
            zero_indices = np.where(~fixed)[0]
            needed = min(min_features - int(fixed.sum()), len(zero_indices))
            chosen = self.rng.choice(zero_indices, size=needed, replace=False)
            fixed[chosen] = True
        return fixed

    def optimize_features(
        self,
        X_train: np.ndarray,
        y_train_binary: np.ndarray,
        X_val: np.ndarray,
        y_val_binary: np.ndarray,
        feature_names: list[str],
        n_pop: int = 16,
        n_gen: int = 15,
        elitism: int = 2,
        mutation_rate: float = 0.08,
        min_features: int = 4,
    ) -> dict[str, Any]:
        """Phase 1: Evolve binary feature masks maximizing F1 - 0.01 * (k / total_features)."""
        n_features = X_train.shape[1]
        cache: dict[tuple[bool, ...], tuple[float, float]] = {}

        def evaluate_mask(mask: np.ndarray) -> tuple[float, float]:
            key = tuple(bool(v) for v in mask)
            if key in cache:
                return cache[key]
            clf = RandomForestClassifier(
                n_estimators=20,
                max_depth=8,
                random_state=self.seed,
                n_jobs=-1,
            )
            clf.fit(X_train[:, mask], y_train_binary)
            preds = clf.predict(X_val[:, mask])
            f1 = float(f1_score(y_val_binary, preds, zero_division=0))
            penalty = 0.01 * (int(mask.sum()) / float(n_features))
            fitness = f1 - penalty
            cache[key] = (fitness, f1)
            return fitness, f1

        population = [
            self._ensure_min_features(
                self.rng.random(n_features) < 0.65, min_features
            )
            for _ in range(n_pop)
        ]

        history: list[dict[str, Any]] = []
        best_overall_mask = population[0].copy()
        best_overall_fitness = -1.0
        best_overall_f1 = 0.0

        for gen in range(1, n_gen + 1):
            results = [evaluate_mask(ind) for ind in population]
            fitness_vals = np.array([res[0] for res in results], dtype=float)
            f1_vals = np.array([res[1] for res in results], dtype=float)

            order = np.argsort(-fitness_vals)
            gen_best_idx = int(order[0])
            gen_best_mask = population[gen_best_idx].copy()
            gen_best_fitness = float(fitness_vals[gen_best_idx])
            gen_best_f1 = float(f1_vals[gen_best_idx])

            if gen_best_fitness > best_overall_fitness:
                best_overall_fitness = gen_best_fitness
                best_overall_f1 = gen_best_f1
                best_overall_mask = gen_best_mask.copy()

            history.append(
                {
                    "generation": gen,
                    "best_fitness": round(gen_best_fitness, 6),
                    "avg_fitness": round(float(np.mean(fitness_vals)), 6),
                    "best_f1": round(gen_best_f1, 6),
                    "avg_f1": round(float(np.mean(f1_vals)), 6),
                    "num_selected_features": int(gen_best_mask.sum()),
                    "selected_features": [
                        name for name, keep in zip(feature_names, gen_best_mask) if keep
                    ],
                }
            )

            if gen == n_gen:
                break

            next_population = [population[int(idx)].copy() for idx in order[:elitism]]
            while len(next_population) < n_pop:
                # Tournament selection (k=3)
                cand_a = self.rng.choice(n_pop, size=3, replace=False)
                cand_b = self.rng.choice(n_pop, size=3, replace=False)
                parent_a = population[int(cand_a[np.argmax(fitness_vals[cand_a])])]
                parent_b = population[int(cand_b[np.argmax(fitness_vals[cand_b])])]

                # Single-point crossover
                cut = int(self.rng.integers(1, n_features))
                child = np.concatenate([parent_a[:cut], parent_b[cut:]]).copy()

                # Bit-flip mutation
                flips = self.rng.random(n_features) < mutation_rate
                child[flips] = ~child[flips]
                child = self._ensure_min_features(child, min_features)
                next_population.append(child)

            population = next_population

        selected_features = [
            name for name, keep in zip(feature_names, best_overall_mask) if keep
        ]
        discarded_features = [
            name for name, keep in zip(feature_names, best_overall_mask) if not keep
        ]

        return {
            "mask": [bool(v) for v in best_overall_mask],
            "selected_features": selected_features,
            "discarded_features": discarded_features,
            "best_fitness": round(best_overall_fitness, 6),
            "best_f1": round(best_overall_f1, 6),
            "history": history,
        }

    def optimize_ensemble_weights(
        self,
        mlp_probs: np.ndarray,
        ae_scores: np.ndarray,
        y_binary: np.ndarray,
        n_pop: int = 24,
        n_gen: int = 20,
        elitism: int = 3,
    ) -> dict[str, Any]:
        """Phase 2: Optimize (w_mlp, w_ae, threshold) to maximize hybrid F1-score."""

        def evaluate_gene(w_mlp: float, thr: float) -> float:
            w_ae = 1.0 - w_mlp
            combined = w_mlp * mlp_probs + w_ae * ae_scores
            preds = (combined >= thr).astype(int)
            return float(f1_score(y_binary, preds, zero_division=0))

        # Genes: [w_mlp in [0.10, 0.95], threshold in [0.15, 0.85]]
        population = np.column_stack(
            [
                self.rng.uniform(0.10, 0.95, size=n_pop),
                self.rng.uniform(0.15, 0.85, size=n_pop),
            ]
        )

        history: list[dict[str, Any]] = []
        best_gene = population[0].copy()
        best_f1 = -1.0

        for gen in range(1, n_gen + 1):
            scores = np.array(
                [evaluate_gene(float(g[0]), float(g[1])) for g in population],
                dtype=float,
            )
            order = np.argsort(-scores)
            gen_best_idx = int(order[0])
            gen_best_f1 = float(scores[gen_best_idx])

            if gen_best_f1 > best_f1:
                best_f1 = gen_best_f1
                best_gene = population[gen_best_idx].copy()

            history.append(
                {
                    "generation": gen,
                    "best_f1": round(gen_best_f1, 6),
                    "avg_f1": round(float(np.mean(scores)), 6),
                    "best_w_mlp": round(float(population[gen_best_idx, 0]), 4),
                    "best_w_ae": round(float(1.0 - population[gen_best_idx, 0]), 4),
                    "best_threshold": round(float(population[gen_best_idx, 1]), 4),
                }
            )

            if gen == n_gen:
                break

            next_pop = [population[int(idx)].copy() for idx in order[:elitism]]
            while len(next_pop) < n_pop:
                cand_a = self.rng.choice(n_pop, size=3, replace=False)
                cand_b = self.rng.choice(n_pop, size=3, replace=False)
                p1 = population[int(cand_a[np.argmax(scores[cand_a])])]
                p2 = population[int(cand_b[np.argmax(scores[cand_b])])]

                alpha = float(self.rng.random())
                child = alpha * p1 + (1.0 - alpha) * p2
                if self.rng.random() < 0.35:
                    child += self.rng.normal(0.0, 0.06, size=2)
                child[0] = float(np.clip(child[0], 0.10, 0.95))
                child[1] = float(np.clip(child[1], 0.15, 0.85))
                next_pop.append(child)

            population = np.vstack(next_pop)

        w_mlp = round(float(best_gene[0]), 4)
        w_ae = round(1.0 - w_mlp, 4)
        threshold = round(float(best_gene[1]), 4)

        return {
            "w_mlp": w_mlp,
            "w_ae": w_ae,
            "threshold": threshold,
            "best_f1": round(best_f1, 6),
            "history": history,
        }
