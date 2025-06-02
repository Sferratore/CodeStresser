import os
import json
import pandas as pd

from prod.VulnerabilityModelTrainer import VulnerabilityModelTrainer
from prod.StaticAnalyzer import StaticAnalyzer
from prod.VulnerabilityReportGenerator import VulnerabilityReportGenerator
from prod.CodeReader import CodeReader

# ===========================
# Configuration
# ===========================

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

TRAINING_DATA_PATH = os.path.join(PROJECT_ROOT, "../training_data/training_data.csv")
MODEL_DIR = os.path.join(PROJECT_ROOT, "../model")
CODE_DIR = os.path.join(PROJECT_ROOT, "../code")
REPORT_PATH = os.path.join(PROJECT_ROOT, "../report/report.json")

SEVERITY_MODEL_PATH = os.path.join(MODEL_DIR, "severity_model.pkl")
CONFIDENCE_MODEL_PATH = os.path.join(MODEL_DIR, "confidence_model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")

# ===========================
# Phase 1: Train and Save Models
# ===========================

def train_models():
    print("[*] Training models on labeled vulnerability data...")
    data = pd.read_csv(TRAINING_DATA_PATH)
    trainer = VulnerabilityModelTrainer()
    trainer.load_data(data)
    trainer.preprocess()
    trainer.train()
    trainer.save(SEVERITY_MODEL_PATH, CONFIDENCE_MODEL_PATH, SCALER_PATH)
    print(f"[+] Models saved to {MODEL_DIR}")


# ===========================
# Phase 2: Run Static Analysis & Generate Report
# ===========================

def generate_report():
    print("[*] Running static analysis and generating report...")

    generator = VulnerabilityReportGenerator(
        severity_model_path=SEVERITY_MODEL_PATH,
        confidence_model_path=CONFIDENCE_MODEL_PATH,
        scaler_path=SCALER_PATH
    )

    report = generator.analyze_path(CODE_DIR)

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[+] Report generated at: {REPORT_PATH}")


# ===========================
# Main Entry Point
# ===========================

if __name__ == "__main__":
    train_models()
    generate_report()
