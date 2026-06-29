"""
ml_detector.py — LSTM Autoencoder inference engine for Project Aegis
Maintains a rolling window of system telemetry.
Exposes: load_model(), add_sample(), check_for_anomaly(), get_status()
"""

import json
import os
import numpy as np
import joblib
import tensorflow as tf
from collections import deque
from datetime import datetime
import csv as _csv
import runtime_paths

# ── Suppress TensorFlow / oneDNN noise ──────────────────────────────────────
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

# ── Paths ────────────────────────────────────────────────────────────────────
MODEL_DIR   = runtime_paths.as_str(runtime_paths.MODEL_DIR)
MODEL_PATH  = runtime_paths.as_str(runtime_paths.MODEL_PATH)
SCALER_PATH = runtime_paths.as_str(runtime_paths.SCALER_PATH)
META_PATH   = runtime_paths.as_str(runtime_paths.METADATA_PATH)
SCORES_CSV  = runtime_paths.as_str(runtime_paths.ANOMALY_SCORES_CSV)

# ── Module state ─────────────────────────────────────────────────────────────
_model      = None
_scaler     = None
_threshold  = 0.072743
_timesteps  = 20
_n_features = 6
_window     = deque(maxlen=20)
_ready      = False
_version    = 0          # increments every time model is reloaded from disk
_phase      = "WARMING UP"
_last_sample = {}


# ─────────────────────────────────────────────────────────────────────────────
def _log_score(score, is_anomaly):
    """Append one anomaly score reading to CSV for dashboard consumption."""
    try:
        os.makedirs(os.path.dirname(SCORES_CSV), exist_ok=True)
        write_header = not os.path.exists(SCORES_CSV)
        with open(SCORES_CSV, "a", newline="") as f:
            writer = _csv.writer(f)
            if write_header:
                writer.writerow(["timestamp", "score", "is_anomaly", "threshold"])
            writer.writerow([
                datetime.now().isoformat(),
                round(score, 8),
                is_anomaly,
                round(_threshold, 8),
            ])
    except Exception:
        pass   # never let logging break inference


# ─────────────────────────────────────────────────────────────────────────────
def load_model(path_override=None):
    """
    Load (or reload) the model, scaler, and metadata from disk.
    Safe to call multiple times — used by hot-reload after retraining.
    Returns True on success, False on failure.
    """
    global _model, _scaler, _threshold, _timesteps, _n_features
    global _window, _ready, _version, _phase

    model_path = path_override or MODEL_PATH

    print("[ML] Loading LSTM Autoencoder ...", flush=True)

    if not os.path.exists(model_path):
        print(f"[ML] No model found at {model_path} — entering WARMING UP phase", flush=True)
        _phase = "WARMING UP"
        return False

    if not os.path.exists(SCALER_PATH):
        print(f"[ML] ERROR — scaler not found at {SCALER_PATH}", flush=True)
        return False

    try:
        _model  = tf.keras.models.load_model(model_path)
        _scaler = joblib.load(SCALER_PATH)

        if os.path.exists(META_PATH):
            with open(META_PATH, "r") as f:
                meta = json.load(f)
            _threshold  = meta.get("threshold",  _threshold)
            _timesteps  = meta.get("timesteps", meta.get("sequence_length", _timesteps))
            _n_features = meta.get("n_features", _n_features)

        # Resize window if timesteps changed
        if _window.maxlen != _timesteps:
            old = list(_window)
            _window = deque(old[-_timesteps:], maxlen=_timesteps)

        _ready   = True
        _version += 1
        _phase   = "DEFENDING"

        print(f"[ML] Model v{_version} loaded — "
              f"threshold={_threshold:.6f}, "
              f"timesteps={_timesteps}, "
              f"features={_n_features}", flush=True)
        return True

    except Exception as e:
        print(f"[ML] ERROR loading model: {e}", flush=True)
        _ready = False
        _phase = "WARMING UP"
        return False


# ─────────────────────────────────────────────────────────────────────────────
def add_sample(cpu_percent, ram_percent, failed_logins,
               active_users, open_ports, hour_of_day):
    """
    Push one telemetry snapshot into the rolling window.
    Called every 10 seconds by the data collector thread.
    """
    global _last_sample
    sample = [
        float(cpu_percent),
        float(ram_percent),
        float(failed_logins),
        float(active_users),
        float(open_ports),
        float(hour_of_day),
    ]
    _window.append(sample)
    _last_sample = {
        "cpu_percent": sample[0],
        "ram_percent": sample[1],
        "failed_logins": sample[2],
        "active_users": sample[3],
        "open_ports": sample[4],
        "hour_of_day": sample[5],
    }


# ─────────────────────────────────────────────────────────────────────────────
def check_for_anomaly():
    """
    Run inference on the current rolling window.

    Returns:
        score       (float) — mean absolute reconstruction error
        is_anomaly  (bool)  — True if score > threshold and window is full

    Returns (0.0, False) if model not ready or window not full yet.
    """
    if not _ready:
        return 0.0, False

    if len(_window) < _timesteps:
        print(f"[ML] Window filling ... ({len(_window)}/{_timesteps})", flush=True)
        return 0.0, False

    try:
        raw    = np.array(list(_window), dtype=np.float32)        # (T, F)
        scaled = _scaler.transform(raw)                            # (T, F)
        X      = scaled.reshape(1, _timesteps, _n_features)       # (1, T, F)
        X_pred = _model.predict(X, verbose=0)                     # (1, T, F)
        score  = float(np.mean(np.abs(X_pred - X)))

        is_anomaly = score > _threshold
        _log_score(score, is_anomaly)

        if is_anomaly:
            print(f"[ML] ⚠  ANOMALY — score={score:.6f} > threshold={_threshold:.6f}", flush=True)
        else:
            print(f"[ML] ✓  Normal  — score={score:.6f}", flush=True)

        return score, is_anomaly

    except Exception as e:
        print(f"[ML] ERROR during inference: {e}", flush=True)
        return 0.0, False


# ─────────────────────────────────────────────────────────────────────────────
def set_phase(phase):
    """Called by trainer.py to update the displayed phase."""
    global _phase
    _phase = phase
    print(f"[ML] Phase → {_phase}", flush=True)


def get_status():
    """Returns a dict for dashboard and logging consumption."""
    return {
        "phase":       _phase,
        "ready":       _ready,
        "version":     _version,
        "threshold":   _threshold,
        "window_size": len(_window),
        "window_full": len(_window) >= _timesteps,
        "timesteps":   _timesteps,
        "last_sample": dict(_last_sample),
    }

