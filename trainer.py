"""
trainer.py — Background retraining engine for Project Aegis

Runs in a daemon thread. Every 60 minutes OR every 200 new rows,
it applies the three-layer data guard and retrains the LSTM Autoencoder
on clean data only. Hot-reloads ml_detector when done.

Three-layer data guard:
  Filter 1 — Score each row with current model, exclude score > threshold
  Filter 2 — Exclude rows inside incident blackout windows (±5 min)
  Filter 3 — Abort if < MIN_CLEAN_ROWS survive after filtering
"""

import os
import time
import threading
import json
import numpy as np
import pandas as pd
import joblib
import tensorflow as tf
from datetime import datetime, timedelta

import ml_detector
import runtime_paths

# ── Suppress TF noise ────────────────────────────────────────────────────────
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR      = runtime_paths.as_str(runtime_paths.BASE_DIR)
CSV_PATH      = runtime_paths.as_str(runtime_paths.SYSTEM_METRICS_CSV)
MODEL_DIR     = runtime_paths.as_str(runtime_paths.MODEL_DIR)
MODEL_PATH    = runtime_paths.as_str(runtime_paths.MODEL_PATH)
SCALER_PATH   = runtime_paths.as_str(runtime_paths.SCALER_PATH)
META_PATH     = runtime_paths.as_str(runtime_paths.METADATA_PATH)
INCIDENTS_CSV = runtime_paths.as_str(runtime_paths.INCIDENTS_CSV)

# Temp paths for atomic swap
# NOTE: MODEL_TMP must still end in .keras — Keras' model.save() validates
# the literal save path's extension, so "aegis_model.keras.tmp" is rejected.
# Inserting .tmp before the extension keeps it a valid Keras path while
# still being a distinct file for the atomic rename below.
MODEL_TMP  = os.path.join(MODEL_DIR, "aegis_model.tmp.keras")
SCALER_TMP = SCALER_PATH + ".tmp"
META_TMP   = META_PATH   + ".tmp"

# ── Config ───────────────────────────────────────────────────────────────────
RETRAIN_INTERVAL_SEC = 60 * 60        # retrain every 60 minutes
RETRAIN_EVERY_N_ROWS = 200            # OR every 200 new rows
MIN_CLEAN_ROWS       = 100            # abort if fewer clean rows survive
BLACKOUT_MINUTES     = 5              # exclude ±5 min around each incident
EPOCHS               = 50
BATCH_SIZE           = 32
TIMESTEPS            = 20
N_FEATURES           = 6
FEATURES             = [
    "cpu_percent", "ram_percent", "failed_logins",
    "active_users", "open_ports", "hour_of_day"
]

# ── State ────────────────────────────────────────────────────────────────────
_lock              = threading.Lock()   # protects CSV writes from collector
_incident_times    = []                 # list of datetime objects, fed by daemon
_last_row_count    = 0
_last_retrain_time = 0
_retrain_count     = 0
_running           = False


# ─────────────────────────────────────────────────────────────────────────────
def register_incident(dt=None):
    """
    Called by daemon whenever an incident fires.
    Records the timestamp for blackout filtering.
    """
    global _incident_times
    t = dt or datetime.now()
    _incident_times.append(t)
    # Keep only last 24 hours of incidents
    cutoff = datetime.now() - timedelta(hours=24)
    _incident_times = [x for x in _incident_times if x > cutoff]
    print(f"[TRAINER] Incident registered at {t.strftime('%H:%M:%S')} "
          f"— blackout window ±{BLACKOUT_MINUTES} min", flush=True)


# ─────────────────────────────────────────────────────────────────────────────
def _is_in_blackout(ts):
    """Return True if timestamp ts falls within any incident blackout window."""
    window = timedelta(minutes=BLACKOUT_MINUTES)
    for inc_time in _incident_times:
        if abs(ts - inc_time) <= window:
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
def _load_csv():
    """Load the training CSV. Returns DataFrame or None."""
    if not os.path.exists(CSV_PATH):
        print("[TRAINER] CSV not found — skipping", flush=True)
        return None
    try:
        df = pd.read_csv(CSV_PATH)
        if df.empty or len(df) < MIN_CLEAN_ROWS:
            return None
        return df
    except Exception as e:
        print(f"[TRAINER] CSV read error: {e}", flush=True)
        return None


# ─────────────────────────────────────────────────────────────────────────────
def _apply_data_guard(df):
    """
    Apply three-layer data guard. Returns clean numpy array or None.
    """
    print(f"[TRAINER] Data guard — starting with {len(df)} rows", flush=True)

    # ── Filter 2: Blackout windows ───────────────────────────────────────────
    if "timestamp" in df.columns and _incident_times:
        try:
            df["_ts"] = pd.to_datetime(df["timestamp"])
            before    = len(df)
            df        = df[~df["_ts"].apply(_is_in_blackout)]
            df        = df.drop(columns=["_ts"])
            removed   = before - len(df)
            if removed:
                print(f"[TRAINER] Filter 2 (blackout): removed {removed} rows", flush=True)
        except Exception as e:
            print(f"[TRAINER] Filter 2 warning: {e}", flush=True)

    # ── Extract feature matrix ───────────────────────────────────────────────
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        print(f"[TRAINER] Missing columns: {missing}", flush=True)
        return None

    raw = df[FEATURES].values.astype(np.float32)

    # ── Filter 1: Score with current model ───────────────────────────────────
    if ml_detector._ready and ml_detector._scaler is not None:
        try:
            scaler    = ml_detector._scaler
            model     = ml_detector._model
            threshold = ml_detector._threshold
            scaled    = scaler.transform(raw)

            # Score each row: build sliding windows and score the center row
            scores = np.zeros(len(raw))
            for i in range(TIMESTEPS, len(raw)):
                window = scaled[i - TIMESTEPS:i].reshape(1, TIMESTEPS, N_FEATURES)
                pred   = model.predict(window, verbose=0)
                scores[i] = float(np.mean(np.abs(pred - window)))

            suspicious = scores > threshold
            removed    = suspicious.sum()
            raw        = raw[~suspicious]
            if removed:
                print(f"[TRAINER] Filter 1 (model score): removed {int(removed)} suspicious rows",
                      flush=True)
        except Exception as e:
            print(f"[TRAINER] Filter 1 warning (skipping): {e}", flush=True)

    # ── Filter 3: Minimum clean rows ─────────────────────────────────────────
    print(f"[TRAINER] Data guard — {len(raw)} clean rows surviving", flush=True)
    if len(raw) < MIN_CLEAN_ROWS:
        print(f"[TRAINER] Filter 3: insufficient clean data "
              f"({len(raw)} < {MIN_CLEAN_ROWS}) — aborting retrain", flush=True)
        return None

    return raw


# ─────────────────────────────────────────────────────────────────────────────
def _build_sequences(scaled, timesteps):
    """Build (X,) sequence array for autoencoder training."""
    sequences = []
    for i in range(len(scaled) - timesteps):
        sequences.append(scaled[i:i + timesteps])
    return np.array(sequences, dtype=np.float32)


# ─────────────────────────────────────────────────────────────────────────────
def _build_model(timesteps, n_features):
    """Build fresh LSTM Autoencoder (same architecture as train_model.py)."""
    inputs  = tf.keras.Input(shape=(timesteps, n_features))
    encoded = tf.keras.layers.LSTM(32, activation="relu",
                                   return_sequences=False)(inputs)
    repeated = tf.keras.layers.RepeatVector(timesteps)(encoded)
    decoded  = tf.keras.layers.LSTM(32, activation="relu",
                                    return_sequences=True)(repeated)
    outputs  = tf.keras.layers.TimeDistributed(
                   tf.keras.layers.Dense(n_features))(decoded)

    model = tf.keras.Model(inputs, outputs)
    model.compile(optimizer="adam", loss="mae")
    return model


# ─────────────────────────────────────────────────────────────────────────────
def run_retrain():
    """
    Full retrain cycle. Called by the background thread.
    Trains on clean data only, then atomically swaps model files.
    """
    global _last_retrain_time, _retrain_count

    print("\n[TRAINER] ═══ Retrain cycle starting ═══", flush=True)
    ml_detector.set_phase("RETRAINING")

    # ── Load CSV ─────────────────────────────────────────────────────────────
    with _lock:
        df = _load_csv()
    if df is None:
        ml_detector.set_phase("DEFENDING" if ml_detector._ready else "WARMING UP")
        return

    # ── Data guard ───────────────────────────────────────────────────────────
    clean_raw = _apply_data_guard(df)
    if clean_raw is None:
        ml_detector.set_phase("DEFENDING" if ml_detector._ready else "WARMING UP")
        return

    # ── Scale ─────────────────────────────────────────────────────────────────
    from sklearn.preprocessing import MinMaxScaler
    scaler = MinMaxScaler()
    scaled = scaler.fit_transform(clean_raw)

    # ── Build sequences ───────────────────────────────────────────────────────
    X = _build_sequences(scaled, TIMESTEPS)
    if len(X) < 10:
        print("[TRAINER] Not enough sequences after windowing — aborting", flush=True)
        ml_detector.set_phase("DEFENDING" if ml_detector._ready else "WARMING UP")
        return

    print(f"[TRAINER] Training on {len(X)} sequences ...", flush=True)

    # ── Train ─────────────────────────────────────────────────────────────────
    model = _build_model(TIMESTEPS, N_FEATURES)
    cb    = tf.keras.callbacks.EarlyStopping(
                monitor="val_loss", patience=5,
                restore_best_weights=True)
    model.fit(
        X, X,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_split=0.1,
        callbacks=[cb],
        verbose=0
    )

    # ── Calculate new threshold (99.5th percentile) ───────────────────────────
    preds  = model.predict(X, verbose=0)
    errors = np.mean(np.abs(preds - X), axis=(1, 2))
    new_threshold = float(np.percentile(errors, 99.5))
    print(f"[TRAINER] New threshold: {new_threshold:.6f}", flush=True)

    # ── Atomic swap ───────────────────────────────────────────────────────────
    try:
        os.makedirs(MODEL_DIR, exist_ok=True)

        model.save(MODEL_TMP)
        joblib.dump(scaler, SCALER_TMP)

        meta = {
            "threshold":    new_threshold,
            "timesteps":    TIMESTEPS,
            "n_features":   N_FEATURES,
            "trained_at":   datetime.now().isoformat(),
            "clean_rows":   int(len(clean_raw)),
            "retrain_count": _retrain_count + 1,
        }
        with open(META_TMP, "w") as f:
            json.dump(meta, f, indent=2)

        # Rename temp → live (atomic on Linux)
        os.replace(MODEL_TMP,  MODEL_PATH)
        os.replace(SCALER_TMP, SCALER_PATH)
        os.replace(META_TMP,   META_PATH)

        _retrain_count    += 1
        _last_retrain_time = time.time()

        print(f"[TRAINER] ✓ Model v{_retrain_count} saved — "
              f"threshold={new_threshold:.6f}, "
              f"clean_rows={len(clean_raw)}", flush=True)

        # Hot-reload ml_detector
        ml_detector.load_model()

    except Exception as e:
        print(f"[TRAINER] ERROR during atomic swap: {e}", flush=True)
        ml_detector.set_phase("DEFENDING" if ml_detector._ready else "WARMING UP")


# ─────────────────────────────────────────────────────────────────────────────
def _should_retrain(current_row_count):
    """Return True if either retrain condition is met."""
    global _last_row_count

    time_due = (time.time() - _last_retrain_time) >= RETRAIN_INTERVAL_SEC
    rows_due = (current_row_count - _last_row_count) >= RETRAIN_EVERY_N_ROWS

    if time_due:
        print("[TRAINER] Time-based retrain trigger", flush=True)
    if rows_due:
        print(f"[TRAINER] Row-based retrain trigger "
              f"({current_row_count - _last_row_count} new rows)", flush=True)

    if time_due or rows_due:
        _last_row_count = current_row_count
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
def _trainer_loop():
    """Background thread main loop. Checks every 60 seconds."""
    global _running
    print("[TRAINER] Background trainer started", flush=True)

    while _running:
        try:
            if os.path.exists(CSV_PATH):
                with _lock:
                    try:
                        row_count = sum(1 for _ in open(CSV_PATH)) - 1  # minus header
                    except Exception:
                        row_count = 0

                if row_count >= MIN_CLEAN_ROWS and _should_retrain(row_count):
                    run_retrain()

        except Exception as e:
            print(f"[TRAINER] Loop error: {e}", flush=True)

        time.sleep(60)   # check every 60 seconds


# ─────────────────────────────────────────────────────────────────────────────
def start():
    """Start the background trainer thread. Call once from daemon.py."""
    global _running, _last_retrain_time
    _running           = True
    _last_retrain_time = time.time()
    t = threading.Thread(target=_trainer_loop, name="trainer", daemon=True)
    t.start()
    print("[TRAINER] Thread launched", flush=True)


def stop():
    """Signal the trainer loop to exit cleanly."""
    global _running
    _running = False


