#!/usr/bin/env python3
"""
Project Aegis - LSTM Autoencoder Training
Trains an anomaly detection model on collected normal behavior data.
"""

import numpy as np
import pandas as pd
import os
import json
from datetime import datetime

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # Suppress TF warnings
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, LSTM, Dense, RepeatVector, TimeDistributed
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from sklearn.preprocessing import MinMaxScaler
import joblib
import runtime_paths

# ─── Config ────────────────────────────────────────────────────────────────────

DATA_FILE = runtime_paths.as_str(runtime_paths.NORMAL_BEHAVIOR_CSV)
MODEL_DIR = runtime_paths.as_str(runtime_paths.MODEL_DIR)
SEQUENCE_LENGTH = 20      # 20 timesteps = 200 seconds of history
FEATURES = [
    "cpu_percent", "ram_percent", "failed_logins",
    "active_users", "open_ports", "hour_of_day"
]
EPOCHS = 100
BATCH_SIZE = 32
VALIDATION_SPLIT = 0.1
ANOMALY_PERCENTILE = 99.5   # Top 0.5% reconstruction error = anomaly

# ─── Data Loading ──────────────────────────────────────────────────────────────

def load_data():
    print("[*] Loading training data...")
    df = pd.read_csv(DATA_FILE)
    print(f"  [+] Loaded {len(df)} rows")
    print(f"  [+] Columns: {list(df.columns)}")
    print(f"  [+] Date range: {df['timestamp'].iloc[0]} to {df['timestamp'].iloc[-1]}")
    return df

# ─── Preprocessing ─────────────────────────────────────────────────────────────

def preprocess(df):
    print("\n[*] Preprocessing data...")

    # Extract feature columns only
    data = df[FEATURES].values.astype(np.float32)
    print(f"  [+] Feature matrix shape: {data.shape}")

    # Normalize to 0-1 range
    scaler = MinMaxScaler()
    data_scaled = scaler.fit_transform(data)
    print(f"  [+] Data normalized to [0, 1] range")

    # Create sequences
    sequences = []
    for i in range(len(data_scaled) - SEQUENCE_LENGTH):
        sequences.append(data_scaled[i:i + SEQUENCE_LENGTH])

    sequences = np.array(sequences)
    print(f"  [+] Created {len(sequences)} sequences of length {SEQUENCE_LENGTH}")
    print(f"  [+] Final shape: {sequences.shape}")

    return sequences, scaler

# ─── Model Architecture ────────────────────────────────────────────────────────

def build_model(sequence_length, n_features):
    print("\n[*] Building LSTM Autoencoder...")

    # ── Encoder ──
    inputs = Input(shape=(sequence_length, n_features))
    encoded = LSTM(64, activation='relu', return_sequences=False)(inputs)
    encoded = Dense(32, activation='relu')(encoded)

    # ── Bottleneck → Decoder bridge ──
    decoded = RepeatVector(sequence_length)(encoded)

    # ── Decoder ──
    decoded = LSTM(64, activation='relu', return_sequences=True)(decoded)
    outputs = TimeDistributed(Dense(n_features))(decoded)

    model = Model(inputs, outputs)
    model.compile(optimizer='adam', loss='mse')

    print(f"  [+] Model built successfully")
    model.summary()

    return model

# ─── Training ──────────────────────────────────────────────────────────────────

def train_model(model, sequences):
    print(f"\n[*] Training model...")
    print(f"  [+] Epochs: {EPOCHS}")
    print(f"  [+] Batch size: {BATCH_SIZE}")
    print(f"  [+] Training sequences: {len(sequences)}")

    os.makedirs(MODEL_DIR, exist_ok=True)

    callbacks = [
        EarlyStopping(
            monitor='val_loss',
            patience=10,
            restore_best_weights=True,
            verbose=1
        ),
        ModelCheckpoint(
            filepath=f"{MODEL_DIR}/best_model.keras",
            monitor='val_loss',
            save_best_only=True,
            verbose=0
        )
    ]

    history = model.fit(
        sequences, sequences,     # Input = Output (autoencoder)
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_split=VALIDATION_SPLIT,
        callbacks=callbacks,
        verbose=1,
        shuffle=True
    )

    print(f"\n  [+] Training complete")
    print(f"  [+] Best val_loss: {min(history.history['val_loss']):.6f}")

    return history

# ─── Threshold Calculation ─────────────────────────────────────────────────────

def calculate_threshold(model, sequences):
    print(f"\n[*] Calculating anomaly threshold...")

    # Get reconstruction errors on all normal data
    reconstructions = model.predict(sequences, verbose=0)
    errors = np.mean(np.abs(sequences - reconstructions), axis=(1, 2))

    threshold = float(np.percentile(errors, ANOMALY_PERCENTILE))

    print(f"  [+] Reconstruction errors — "
          f"min: {errors.min():.6f}, "
          f"mean: {errors.mean():.6f}, "
          f"max: {errors.max():.6f}")
    print(f"  [+] Anomaly threshold ({ANOMALY_PERCENTILE}th percentile): {threshold:.6f}")

    return threshold, errors

# ─── Save Everything ───────────────────────────────────────────────────────────

def save_artifacts(model, scaler, threshold, history):
    print(f"\n[*] Saving model artifacts...")
    os.makedirs(MODEL_DIR, exist_ok=True)

    # Save model
    model.save(f"{MODEL_DIR}/aegis_model.keras")
    print(f"  [+] Model saved to {MODEL_DIR}/aegis_model.keras")

    # Save scaler
    joblib.dump(scaler, f"{MODEL_DIR}/scaler.pkl")
    print(f"  [+] Scaler saved to {MODEL_DIR}/scaler.pkl")

    # Save metadata
    metadata = {
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "threshold": threshold,
        "sequence_length": SEQUENCE_LENGTH,
        "features": FEATURES,
        "epochs_trained": len(history.history['loss']),
        "final_train_loss": float(history.history['loss'][-1]),
        "final_val_loss": float(history.history['val_loss'][-1]),
        "anomaly_percentile": ANOMALY_PERCENTILE
    }

    with open(f"{MODEL_DIR}/metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"  [+] Metadata saved to {MODEL_DIR}/metadata.json")

    return metadata

# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  PROJECT AEGIS — LSTM Autoencoder Training")
    print("=" * 60)

    # Check data exists
    if not os.path.exists(DATA_FILE):
        print(f"\n[!] No training data found at {DATA_FILE}")
        print(f"[!] Run data_collector.py first")
        return

    # Load and preprocess
    df = load_data()

    if len(df) < 50:
        print(f"\n[!] Only {len(df)} rows found. Need at least 50.")
        print(f"[!] Run data_collector.py for longer.")
        return

    sequences, scaler = preprocess(df)

    if len(sequences) < 30:
        print(f"\n[!] Not enough sequences to train. Collect more data.")
        return

    # Build model
    model = build_model(SEQUENCE_LENGTH, len(FEATURES))

    # Train
    history = train_model(model, sequences)

    # Calculate threshold
    threshold, errors = calculate_threshold(model, sequences)

    # Save everything
    metadata = save_artifacts(model, scaler, threshold, history)

    print("\n" + "=" * 60)
    print("  TRAINING COMPLETE")
    print("=" * 60)
    print(f"  Model    : {MODEL_DIR}/aegis_model.keras")
    print(f"  Scaler   : {MODEL_DIR}/scaler.pkl")
    print(f"  Threshold: {threshold:.6f}")
    print(f"  Status   : Ready for integration into daemon")
    print("=" * 60)

if __name__ == "__main__":
    main()

