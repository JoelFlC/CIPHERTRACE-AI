"""Compact CPU-based PyTorch Autoencoder trained exclusively on BENIGN traffic."""

from __future__ import annotations

import math
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from app.core.config import RANDOM_SEED


class AutoencoderNet(nn.Module):
    """Symmetric bottleneck MLP autoencoder: Input -> 16 -> 8 -> 4 -> 8 -> 16 -> Output."""

    def __init__(self, input_dim: int) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 4),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(4, 8),
            nn.ReLU(),
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


class TabularAutoencoderDetector:
    """Anomaly detector mapping reconstruction MSE of benign-trained Autoencoder into [0, 1]."""

    def __init__(self, input_dim: int, seed: int = RANDOM_SEED) -> None:
        self.input_dim = int(input_dim)
        self.seed = int(seed)
        self.device = torch.device("cpu")
        torch.manual_seed(self.seed)
        self.model = AutoencoderNet(self.input_dim).to(self.device)
        self.scale: float = 1.0
        self.benign_mse_p95: float = 1.0

    def fit(
        self,
        X_benign: np.ndarray,
        epochs: int = 45,
        batch_size: int = 64,
        lr: float = 1e-3,
    ) -> "TabularAutoencoderDetector":
        """Train the autoencoder strictly on BENIGN traffic samples."""
        torch.manual_seed(self.seed)
        self.model = AutoencoderNet(self.input_dim).to(self.device)
        self.model.train()

        tensor_x = torch.tensor(X_benign, dtype=torch.float32)
        dataset = TensorDataset(tensor_x)
        generator = torch.Generator().manual_seed(self.seed)
        loader = DataLoader(
            dataset, batch_size=batch_size, shuffle=True, generator=generator
        )

        optimizer = torch.optim.Adam(self.model.parameters(), lr=lr)
        criterion = nn.MSELoss()

        for _ in range(epochs):
            for (batch_x,) in loader:
                optimizer.zero_grad()
                recon = self.model(batch_x)
                loss = criterion(recon, batch_x)
                loss.backward()
                optimizer.step()

        benign_mse = self.reconstruction_error(X_benign)
        self.benign_mse_p95 = max(float(np.percentile(benign_mse, 95)), 1e-6)
        # Map benign 95th percentile MSE to anomaly score 0.50 via 1 - exp(-mse / scale)
        self.scale = self.benign_mse_p95 / math.log(2.0)
        return self

    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """Compute per-sample MSE reconstruction error."""
        self.model.eval()
        with torch.no_grad():
            tensor_x = torch.tensor(X, dtype=torch.float32, device=self.device)
            recon = self.model(tensor_x)
            mse = torch.mean((recon - tensor_x) ** 2, dim=1)
        return mse.cpu().numpy()

    def predict_scores(self, X: np.ndarray) -> np.ndarray:
        """Return normalized anomaly scores in [0.0, 1.0]."""
        mse = self.reconstruction_error(X)
        scores = 1.0 - np.exp(-mse / max(self.scale, 1e-6))
        return np.clip(scores, 0.0, 1.0)

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """Return binary predictions (1 = malicious anomaly, 0 = benign)."""
        return (self.predict_scores(X) >= threshold).astype(int)

    def save(self, path: str | Path) -> None:
        """Persist model weights and calibration metadata to disk."""
        torch.save(
            {
                "input_dim": self.input_dim,
                "seed": self.seed,
                "scale": self.scale,
                "benign_mse_p95": self.benign_mse_p95,
                "state_dict": self.model.state_dict(),
            },
            str(path),
        )

    @classmethod
    def load(cls, path: str | Path) -> "TabularAutoencoderDetector":
        """Load serialized Autoencoder detector from disk on CPU."""
        checkpoint = torch.load(str(path), map_location="cpu", weights_only=True)
        detector = cls(
            input_dim=int(checkpoint["input_dim"]),
            seed=int(checkpoint.get("seed", RANDOM_SEED)),
        )
        detector.scale = float(checkpoint["scale"])
        detector.benign_mse_p95 = float(checkpoint["benign_mse_p95"])
        detector.model.load_state_dict(checkpoint["state_dict"])
        detector.model.eval()
        return detector
