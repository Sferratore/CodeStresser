# CodeStresser

CodeStresser is a static code analysis tool powered by machine learning models. The system analyzes source code, detects common vulnerabilities, and generates a report estimating the severity and confidence level for each finding.

# Architecture

The project is organized into the following main modules:

- prod/StaticAnalyzer.py: AST-based parser for Python code that detects vulnerabilities like eval, exec, dynamic SQL, uninitialized variables, tainted file access, unsafe deserialization, etc.
- prod/VulnerabilityModelTrainingPipeline.py: supervised training pipeline for two models: severity classification and confidence regression.
- prod/VulnerabilityReportGenerator.py: loads trained models and generates reports from files or directories.
- prod/CodeReader.py: reads files with specified extensions; supports multi-language with simple extension.
- training_data/training_data.csv: CSV training dataset containing feature vectors and target labels (severity, confidence).
- tests/: unit tests verifying the main modules.

# Requirements

- Python >= 3.10
- pandas
- scikit-learn
- joblib

# Installation

Clone the repository:

git clone https://github.com/Sferratore/CodeStresser.git
cd CodeStresser

Create a virtual environment:

python -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

If requirements.txt is missing:

pip install pandas scikit-learn joblib

# Training

To train the models using the existing CSV dataset:

python prod/VulnerabilityModelTrainingPipeline.py

This will generate the following files:

- severity_model.pkl
- confidence_model.pkl
- scaler.pkl

# Usage

Basic example of using the report generator:

from prod.VulnerabilityReportGenerator import VulnerabilityReportGenerator

reporter = VulnerabilityReportGenerator(
    severity_model_path="severity_model.pkl",
    confidence_model_path="confidence_model.pkl",
    scaler_path="scaler.pkl"
)

report = reporter.analyze_path("path/to/file_or_directory")
for entry in report:
    print(entry)

Each report entry contains:

- problematic_function
- problematic_variable
- file
- line
- issue
- severity
- confidence
- suggested_fix

# Running Tests

To run all unit tests:

python -m unittest discover tests

# Dataset

The dataset is located at training_data/training_data.csv. Each row represents a vulnerability with 12 numerical features and two labels: "severity" (Low, Medium, High) and "confidence" (float between 0 and 1). The dataset can be extended with new vulnerabilities detected by the StaticAnalyzer.

# Extending to Other Languages

To support additional languages:

1. Extend CodeReader with new file extensions (e.g., .c, .java, .js, etc.).
2. Implement a language-specific analyzer similar to StaticAnalyzer.
3. Adapt the feature generator to maintain consistent vector format across languages.

# Author

https://github.com/Sferratore
