from typing import Dict, Any, List, Iterator, Optional, Tuple
import numpy as np
import yaml
import os
import pickle


def load_lstm_model(model_path: str):
    try:
        # Lazy import to avoid TF dependency unless needed
        from tensorflow.keras.models import load_model  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "TensorFlow/Keras is required for ML detection. Install tensorflow-cpu or tensorflow."
        ) from e
    return load_model(model_path)


class FeatureScaler:
    def __init__(self, cfg: Dict[str, Any], feature_names: List[str]):
        self.type = (cfg or {}).get("type")
        self.feature_names = feature_names
        self.mean =None
        self.std = None
        self.min = None
        self.max = None
        if self.type == "zscore":
            self.mean = np.array([float(cfg["mean"].get(k, 0.0)) for k in feature_names], dtype=float)
            self.std = np.array([float(cfg["std"].get(k, 1.0)) for k in feature_names], dtype=float)
        elif self.type == "minmax":
            self.min = np.array([float(cfg["min"].get(k, 0.0)) for k in feature_names], dtype=float)
            self.max = np.array([float(cfg["max"].get(k, 1.0)) for k in feature_names], dtype=float)

    def transform(self, X: np.ndarray) -> np.ndarray:
        if self.type == "zscore" and self.mean is not None and self.std is not None:
            denom = np.where(self.std == 0, 1.0, self.std)
            return (X - self.mean) / denom
        if self.type == "minmax" and self.min is not None and self.max is not None:
            rng = np.where((self.max - self.min) == 0, 1.0, (self.max - self.min))
            return (X - self.min) / rng
        return X


def load_feature_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


class LSTMDetector:
    def __init__(
        self,
        model,
        feature_names: List[str],
        sequence_length: int,
        threshold: float = 0.5,
        scaler_cfg: Optional[Dict[str, Any]] = None,
        external_scaler: Optional[Any] = None,
    ) -> None:
        self.model = model
        self.feature_names = feature_names
        self.L = int(sequence_length)
        self.threshold = float(threshold)
        self.scaler = FeatureScaler(scaler_cfg or {}, feature_names)
        self.external_scaler = external_scaler

    def _build_sequence_windows(self, feature_rows: List[List[float]]) -> np.ndarray:
        X = np.array(feature_rows, dtype=float)
        # Apply external scaler (e.g., sklearn) if provided, else internal
        if self.external_scaler is not None:
            try:
                X = self.external_scaler.transform(X)
            except Exception:
                # Fallback to identity if transform fails
                pass
        else:
            X = self.scaler.transform(X)
        if len(X) < self.L:
            return np.empty((0, self.L, X.shape[1]))
        windows = []
        for i in range(self.L - 1, len(X)):
            win = X[i - self.L + 1 : i + 1]
            windows.append(win)
        return np.stack(windows, axis=0)

    def predict_scores(self, feature_rows: List[List[float]]) -> List[Optional[float]]:
        windows = self._build_sequence_windows(feature_rows)
        if windows.shape[0] == 0:
            return [None] * len(feature_rows)
        preds = self.model.predict(windows, verbose=0)
        preds = np.array(preds).reshape((-1,))
        # Align scores to last element of each window
        scores: List[Optional[float]] = [None] * (self.L - 1) + [float(x) for x in preds]
        return scores

    def predict_flags(self, feature_rows: List[List[float]]) -> List[Optional[bool]]:
        scores = self.predict_scores(feature_rows)
        return [None if s is None else (s >= self.threshold) for s in scores]


def extract_features_from_event(event: Dict[str, Any], feature_names: List[str]) -> Optional[List[float]]:
    """Extract feature values from event dict in EXACT order matching feature_names.
    This ensures the feature vector matches the model's expected input order exactly.
    Missing features are filled with 0.0.
    """
    row: List[float] = []
    try:
        missing_count = 0
        for k in feature_names:
            # Try exact match first
            v = event.get(k)
            if v is None:
                # Try case-insensitive match
                v = None
                for key, val in event.items():
                    if key.lower() == k.lower():
                        v = val
                        break
                if v is None:
                    row.append(0.0)
                    missing_count += 1
                    continue
            
            try:
                row.append(float(v))
            except (ValueError, TypeError):
                row.append(0.0)
                missing_count += 1
        
        # Only return None if ALL features are missing (shouldn't happen)
        if missing_count == len(feature_names):
            return None
        return row
    except Exception:
        return None


def group_events(events: Iterator[Dict[str, Any]], group_field: Optional[str]) -> Dict[Any, List[Dict[str, Any]]]:
    buckets: Dict[Any, List[Dict[str, Any]]] = {}
    if group_field is None:
        buckets["__all__"] = list(events)
        return buckets
    for ev in events:
        key = ev.get(group_field, "__nogroup__")
        buckets.setdefault(key, []).append(ev)
    return buckets


def load_feature_list_pkl(path: str) -> List[str]:
    with open(path, "rb") as f:
        obj = pickle.load(f)
    if isinstance(obj, (list, tuple)):
        return [str(x) for x in obj]
    raise ValueError("feature.pkl must contain a list/tuple of feature names")


def load_external_scaler_pkl(path: str) -> Any:
    with open(path, "rb") as f:
        obj = pickle.load(f)
    # Expect sklearn-like object with transform()
    if not hasattr(obj, "transform"):
        raise ValueError("scaler.pkl must provide an object with a transform(X) method")
    return obj


def resolve_model_artifacts(
    model_path: Optional[str] = None,
    model_dir: Optional[str] = None,
    feature_pkl: Optional[str] = None,
    scaler_pkl: Optional[str] = None,
) -> Tuple[str, Optional[str], Optional[str]]:
    """Resolve paths for model.h5, feature.pkl, scaler.pkl.
    Returns (model_path, feature_pkl_path or None, scaler_pkl_path or None).
    """
    m_path = model_path
    f_path = feature_pkl
    s_path = scaler_pkl
    if model_dir:
        # Prefer explicit files if given, else derive from dir
        if not m_path:
            cand = os.path.join(model_dir, "model.h5")
            if os.path.exists(cand):
                m_path = cand
        if not f_path:
            # Support both 'feature.pkl' and legacy/plural 'features.pkl'
            cand1 = os.path.join(model_dir, "feature.pkl")
            cand2 = os.path.join(model_dir, "features.pkl")
            if os.path.exists(cand1):
                f_path = cand1
            elif os.path.exists(cand2):
                f_path = cand2
        if not s_path:
            cand = os.path.join(model_dir, "scaler.pkl")
            if os.path.exists(cand):
                s_path = cand
    if not m_path:
        raise ValueError("Model path not provided. Use --model-path or --model-dir")
    return m_path, f_path, s_path

