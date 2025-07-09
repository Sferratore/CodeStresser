# CodeStresser

CodeStresser is a static code analysis tool that relies on Machine Learning. The system analyzes source code, detects common vulnerabilities, and generates a report estimating the severity and confidence level for each finding.

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
- radon

# Installation

Clone the repository:

`git clone https://github.com/Sferratore/CodeStresser.git
cd CodeStresser`

Create a virtual environment:

`python -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate`

Install dependencies:

`pip install pandas scikit-learn joblib`

# Training

To train the models using the existing CSV dataset:

`python prod/VulnerabilityModelTrainingPipeline.py`

This will generate the following files:

- severity_model.pkl
- confidence_model.pkl
- scaler.pkl

# Author

https://github.com/Sferratore
