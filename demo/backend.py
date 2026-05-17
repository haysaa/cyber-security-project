from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import torch
import torch.nn as nn
import numpy as np
import pandas as pd
import joblib
from pathlib import Path

MODEL_DIR = Path("./model")
THRESHOLD = 0.000029
DEVICE = torch.device("cpu")


class DeepAutoencoder(nn.Module):
    def __init__(self, input_dim, latent_dim=8):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128), nn.ReLU(), nn.BatchNorm1d(128),
            nn.Linear(128, 64), nn.ReLU(), nn.BatchNorm1d(64),
            nn.Linear(64, 32), nn.ReLU(), nn.Linear(32, latent_dim))
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 32), nn.ReLU(),
            nn.Linear(32, 64), nn.ReLU(), nn.BatchNorm1d(64),
            nn.Linear(64, 128), nn.ReLU(), nn.BatchNorm1d(128),
            nn.Linear(128, input_dim), nn.Sigmoid())

    def forward(self, x):
        return self.decoder(self.encoder(x))

    def reconstruction_error(self, x):
        self.eval()
        with torch.no_grad():
            return torch.mean((x - self.forward(x)) ** 2, dim=1).cpu().numpy()


# Load model artifacts
keep_cols = joblib.load(MODEL_DIR / "keep_cols_unsw.pkl")
scaler = joblib.load(MODEL_DIR / "scaler_unsw.pkl")
model = DeepAutoencoder(len(keep_cols))
model.load_state_dict(torch.load(MODEL_DIR / "unsw_ae_weights.pt", map_location=DEVICE))
model.eval()

# Flask app
app = Flask(__name__)
CORS(app)


@app.route("/")
def index():
    return send_file("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    packet_str = data.get("packet", "")
    values = [float(x.strip()) for x in packet_str.replace("\t", ",").split(",") if x.strip()]
    df = pd.DataFrame([values], columns=keep_cols)
    df.replace([float("inf"), float("-inf")], 0, inplace=True)
    df.fillna(0, inplace=True)
    scaled = scaler.transform(df)
    x = torch.tensor(scaled, dtype=torch.float32)
    error = float(model.reconstruction_error(x)[0])
    if error > THRESHOLD:
        label = "Malicious"
        confidence = min(0.50 + (error - THRESHOLD) / THRESHOLD * 0.45, 0.99)
    else:
        label = "Safe"
        confidence = min(0.50 + (THRESHOLD - error) / THRESHOLD * 0.45, 0.99)
    return jsonify({
        "label": label,
        "confidence": round(confidence, 4),
        "reconstruction_error": round(error, 8)
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
