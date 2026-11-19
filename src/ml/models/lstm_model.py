import numpy as np
import torch
import torch.nn as nn
from pathlib import Path
from torch.utils.data import DataLoader, Dataset
from src.utils.config import settings
from src.utils.logger import logger

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


class FlowSequenceDataset(Dataset):
    """
    Memory-efficient sliding window dataset for sequential flow detection.
    Avoids copying large sequence arrays into RAM.
    """
    def __init__(self, X: np.ndarray, y: np.ndarray, seq_len: int = 20, max_samples: int = None):
        self.seq_len = seq_len
        total_len = len(X) - seq_len
        if max_samples and max_samples < total_len:
            step = max(1, total_len // max_samples)
            self.indices = np.arange(0, total_len, step)[:max_samples]
        else:
            self.indices = np.arange(0, total_len)

        self.X = X
        self.y = y

    def __len__(self):
        return len(self.indices)

    def __getitem__(self, idx):
        real_idx = self.indices[idx]
        seq = torch.from_numpy(self.X[real_idx : real_idx + self.seq_len]).float()
        target = torch.tensor(self.y[real_idx + self.seq_len - 1], dtype=torch.long)
        return seq, target


class LSTMNet(nn.Module):

    def __init__(self, input_size: int, hidden_size: int = 128,
                 num_layers: int = 2, num_classes: int = 2, dropout: float = 0.3):
        super().__init__()
        self.hidden_size = hidden_size
        self.num_layers  = num_layers

        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(x.device)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(x.device)
        out, _ = self.lstm(x, (h0, c0))
        return self.classifier(out[:, -1, :])


class LSTMModel:

    SEQ_LEN    = 20
    BATCH_SIZE = 1024
    EPOCHS     = 6
    LR         = 1e-3

    def __init__(self, input_size: int = 69):
        self.input_size = input_size
        self.net        = None

    def train(self, X_train: np.ndarray, y_train: np.ndarray, max_train_samples: int = 80000):
        logger.info(f"Building memory-efficient sequence loader (seq_len={self.SEQ_LEN})...")
        train_dataset = FlowSequenceDataset(
            X_train, y_train, seq_len=self.SEQ_LEN, max_samples=max_train_samples
        )
        loader = DataLoader(train_dataset, batch_size=self.BATCH_SIZE, shuffle=True)
        logger.info(f"Training Fast Deep LSTM on {len(train_dataset):,} sequences | device={DEVICE}")

        self.net = LSTMNet(input_size=self.input_size).to(DEVICE)
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.Adam(self.net.parameters(), lr=self.LR)
        scheduler = torch.optim.lr_scheduler.StepLR(optimizer, step_size=2, gamma=0.5)

        self.net.train()
        for epoch in range(1, self.EPOCHS + 1):
            total_loss, correct, total = 0.0, 0, 0

            for Xb, yb in loader:
                Xb, yb = Xb.to(DEVICE), yb.to(DEVICE)
                optimizer.zero_grad()
                out  = self.net(Xb)
                loss = criterion(out, yb)
                loss.backward()
                nn.utils.clip_grad_norm_(self.net.parameters(), max_norm=1.0)
                optimizer.step()

                total_loss += loss.item() * len(yb)
                correct    += (out.argmax(1) == yb).sum().item()
                total      += len(yb)

            scheduler.step()
            acc = correct / total if total > 0 else 0
            avg = total_loss / total if total > 0 else 0
            logger.info(f"  Epoch {epoch:>2}/{self.EPOCHS} | loss={avg:.4f} | acc={acc * 100:.2f}%")

        logger.success("LSTM training complete")
        return self

    def predict_single(self, features: np.ndarray) -> dict:
        if self.net is None:
            return {"is_attack": False, "label": "BENIGN", "confidence": 0.0}

        self.net.eval()
        seq = np.tile(features, (self.SEQ_LEN, 1)).reshape(1, self.SEQ_LEN, -1)
        tensor = torch.tensor(seq, dtype=torch.float32).to(DEVICE)
        with torch.no_grad():
            logits = self.net(tensor)
            proba  = torch.softmax(logits, dim=-1).cpu().numpy()[0]
        pred = int(np.argmax(proba))
        return {
            "prediction":   pred,
            "label":        "ATTACK" if pred == 1 else "BENIGN",
            "confidence":   float(proba[pred]),
            "proba_benign": float(proba[0]),
            "proba_attack": float(proba[1]),
            "is_attack":    pred == 1,
            "model":        "LSTM",
        }

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray, max_eval_samples: int = 25000) -> dict:
        from sklearn.metrics import classification_report, f1_score, confusion_matrix
        self.net.eval()
        eval_dataset = FlowSequenceDataset(
            X_test, y_test, seq_len=self.SEQ_LEN, max_samples=max_eval_samples
        )
        loader = DataLoader(eval_dataset, batch_size=self.BATCH_SIZE * 2, shuffle=False)
        preds, truths = [], []
        with torch.no_grad():
            for Xb, yb in loader:
                out = self.net(Xb.to(DEVICE))
                preds.extend(out.argmax(1).cpu().numpy().tolist())
                truths.extend(yb.numpy().tolist())

        f1 = f1_score(truths, preds, average="binary", zero_division=0)
        report = classification_report(
            truths, preds, target_names=["BENIGN", "ATTACK"],
            zero_division=0, output_dict=True,
        )
        cm = confusion_matrix(truths, preds)

        logger.info("\n" + classification_report(
            truths, preds, target_names=["BENIGN", "ATTACK"], zero_division=0
        ))
        logger.info(f"Confusion Matrix:\n{cm}")

        return {
            "f1": float(f1),
            "report": report,
            "confusion_matrix": cm.tolist(),
            "labels": ["BENIGN", "ATTACK"],
        }

    def save(self, path: Path = None) -> Path:
        if path is None:
            path = settings.models_dir / "lstm.pt"
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save({
            "net_state":  self.net.state_dict(),
            "input_size": self.input_size,
            "seq_len":    self.SEQ_LEN,
        }, path)
        logger.success(f"LSTM saved → {path}")
        return path

    @classmethod
    def load(cls, path: Path = None):
        if path is None:
            path = settings.models_dir / "lstm.pt"
        ckpt = torch.load(path, map_location=DEVICE, weights_only=False)
        obj  = cls(input_size=ckpt["input_size"])
        obj.SEQ_LEN = ckpt["seq_len"]
        obj.net     = LSTMNet(input_size=obj.input_size).to(DEVICE)
        obj.net.load_state_dict(ckpt["net_state"])
        obj.net.eval()
        logger.info(f"LSTM loaded from {path}")
        return obj