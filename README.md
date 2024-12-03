# Honeyless Pot

Honeyless Pot is a honeypot system designed to detect and log HTTP requests while analyzing potential SQL injection attacks using a machine learning model. This project is intended for educational and research purposes to understand and mitigate security vulnerabilities.

## Features

- Logs HTTP GET requests and other activities.
- Extracts and processes GET queries.
- Detects potential SQL injection attacks using a pre-trained machine learning model.
- Modular design for easy extension.

## Components

1. **Honeypot Server**:
   - A simple HTTP server that logs incoming requests.
   - Supports real-time analysis of GET requests.

2. **Query Extraction**:
   - Extracts GET requests from the log files and saves them in a CSV format.

3. **Machine Learning Model**:
   - A Random Forest-based model trained to classify queries as benign or SQL injection.
   - Model is serialized and used for real-time classification.

## Setup and Usage

### Prerequisites

- Python 3.11 or higher
- Required libraries:
  ```bash
  pip install pandas scikit-learn joblib matplotlib
  ```
## Usage
Run the honeypot with the following command:

```bash
sudo python honeypot.py
```
