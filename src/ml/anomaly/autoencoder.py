import pickle
from pathlib import Path
from typing import Optional
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from src.utils.config import settings
from src.utils.logger import logger


class AutoencoderNet(nn.Module):
    """Deep Compression Autoencoder for Network Flow Anomaly Detection."""

    def __init__(self, input_dim: int = 68, latent_dim: int = 12):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 48),
            nn.BatchNorm1d(48),
            nn.LeakyReLU(0.1),
            nn.Dropout(0.05),
            nn.Linear(48, 24),
            nn.BatchNorm1d(24),
            nn.LeakyReLU(0.1),
            nn.Linear(24, latent_dim),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 24),
            nn.BatchNorm1d(24),
            nn.LeakyReLU(0.1),
            nn.Dropout(0.05),
            nn.Linear(24, 48),
            nn.BatchNorm1d(48),
            nn.LeakyReLU(0.1),
            nn.Linear(48, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        latent = self.encoder(x)
        reconstruction = self.decoder(latent)
        return reconstruction


class FlowAutoencoder:
    """Wrapper for training, evaluating, and persisting the PyTorch Autoencoder."""

    def __init__(self, input_dim: int = 68, latent_dim: int = 12, device: Optional[str] = None):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model = AutoencoderNet(input_dim, latent_dim).to(self.device)
        self.is_fitted = False

    def train(
        self,
        X_train: np.ndarray,
        epochs: int = 20,
        batch_size: int = 512,
        lr: float = 0.001,
        weight_decay: float = 1e-5,
    ):
        """Train Autoencoder strictly on normal (Benign) flows to minimize reconstruction MSE."""
        logger.info(
            f"Training Autoencoder ({self.input_dim} -> {self.latent_dim} -> {self.input_dim}) "
            f"on {len(X_train):,} Benign flows using {self.device.upper()}..."
        )

        tensor_x = torch.tensor(X_train, dtype=torch.float32)
        dataset = TensorDataset(tensor_x)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, drop_last=True)

        criterion = nn.MSELoss()
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=lr, weight_decay=weight_decay)
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode="min", factor=0.5, patience=3)

        self.model.train()
        for epoch in range(1, epochs + 1):
            total_loss = 0.0
            for (batch_x,) in loader:
                batch_x = batch_x.to(self.device)
                optimizer.zero_grad()
                recon = self.model(batch_x)
                loss = criterion(recon, batch_x)
                loss.backward()
                optimizer.step()
                total_loss += loss.item() * len(batch_x)

            epoch_loss = total_loss / len(X_train)
            scheduler.step(epoch_loss)
            if epoch % 5 == 0 or epoch == epochs or epoch == 1:
                logger.info(f"  Epoch [{epoch:02d}/{epochs:02d}] — Reconstruction Loss (MSE): {epoch_loss:.6f}")

        self.is_fitted = True
        logger.success("Autoencoder training complete.")
        return self

    def reconstruction_error(
        self,
        X: np.ndarray,
        batch_size: int = 1024,
        top_k: int = 10,
        alpha: float = 0.5,
    ) -> np.ndarray:
        """
        Compute multi-scale reconstruction error:
        Combines global MSE with top-K feature error to avoid diluting localized attack deviations
        across sparse/zero-variance features:
            error = (1 - alpha) * global_mse + alpha * mean(top_k(squared_error))
        """
        self.model.eval()
        tensor_x = torch.tensor(X, dtype=torch.float32)
        dataset = TensorDataset(tensor_x)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=False)

        errors = []
        with torch.no_grad():
            for (batch_x,) in loader:
                batch_x = batch_x.to(self.device)
                recon = self.model(batch_x)
                diff = (recon - batch_x) ** 2
                global_mse = torch.mean(diff, dim=1)
                k = min(top_k, diff.shape[1])
                topk_err = torch.topk(diff, k=k, dim=1).values.mean(dim=1)
                sample_error = ((1.0 - alpha) * global_mse + alpha * topk_err).cpu().numpy()
                errors.append(sample_error)

        return np.concatenate(errors)

    def save(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "state_dict": self.model.state_dict(),
                "input_dim": self.input_dim,
                "latent_dim": self.latent_dim,
            },
            path,
        )
        logger.success(f"Autoencoder weights saved → {path}")

    @classmethod
    def load(cls, path: Path, device: Optional[str] = None):
        checkpoint = torch.load(path, map_location="cpu")
        obj = cls(
            input_dim=checkpoint.get("input_dim", 68),
            latent_dim=checkpoint.get("latent_dim", 12),
            device=device,
        )
        obj.model.load_state_dict(checkpoint["state_dict"])
        obj.model.eval()
        obj.is_fitted = True
        logger.info(f"Autoencoder loaded from {path}")
        return obj
