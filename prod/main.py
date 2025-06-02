import os
import json
import pandas as pd
from prod.VulnerabilityModelTrainer import VulnerabilityModelTrainer
from prod.VulnerabilityReportGenerator import VulnerabilityReportGenerator

# === PHASE 1: Train model ===
def train_model():
    print("[*] Training model from training_data/training_data.csv...")
    df = pd.read_csv("training_data/training_data.csv")

    trainer = VulnerabilityModelTrainer()
    trainer.load_data(df)
    trainer.preprocess()
    accuracy = trainer.train()
    print(f"[+] Training complete. Accuracy: {accuracy:.2f}")

    os.makedirs("model", exist_ok=True)
    trainer.save("model/severity_model.pkl", "model/severity_scaler.pkl")
    print("[+] Model and scaler saved in /model")

# === PHASE 2: Analyze source code and generate report ===
def generate_report():
    print("[*] Analyzing source code in /code")
    generator = VulnerabilityReportGenerator(
        model_path="model/severity_model.pkl",
        scaler_path="model/severity_scaler.pkl"
    )

    reports = generator.analyze_path("code")
    os.makedirs("report", exist_ok=True)
    report_path = os.path.join("report", "vulnerability_report.json")

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2)

    print(f"[+] Report written to: {report_path}")

# === MAIN EXECUTION ===
if __name__ == "__main__":
    train_model()
    generate_report()
