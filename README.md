

# Xploit0 - Security Analysis Tool

![Logo](https://i.ibb.co/gQt4BM1/i-1-removebg-preview.png")


Xploit0 is a powerful security tool designed to scan and analyze all dependencies present in your repository, ensuring your digital infrastructure stays safe and secure. It helps organizations identify vulnerabilities, track CVEs (Common Vulnerabilities and Exposures), and predict potential security risks using advanced machine learning models. Xploit0 is ideal for keeping your systems protected by continuously evaluating your software’s dependencies.

This README will guide you through the process of setting up Xploit0, running the security analysis, and viewing the results through an interactive Streamlit dashboard.

---

## Prerequisites

Before you get started, ensure you have the following installed:

- Python 3.x
- `pip` (Python package manager)
- Streamlit (`pip install streamlit`)
- Virtual environment tool (`python -m venv`)

---

## Steps to Set Up and Run Xploit0

### 1. Set Up a Virtual Environment

Start by creating a virtual environment named `xenv` to isolate your project’s dependencies:

```bash
python -m venv xenv
```

Activate the virtual environment:

- **On Windows:**

```bash
.\xenv\Scripts\activate
```

- **On macOS/Linux:**

```bash
source xenv/bin/activate
```

### 2. Install Dependencies

Once the virtual environment is activated, install all the necessary dependencies from the `requirements.txt` file:

```bash
pip install -r requirements.txt
```

### 3. Run the Security Analysis

To start the security analysis, run the `run_analysis.py` script. This script will perform the following steps in sequence:

1. **Dependency Scanning**: Runs `depscan.py` to scan all dependencies in your project.
2. **CVE Data Fetching**: Fetches CVE data using `cvefetch.py`.
3. **CVE Data Processing**: Processes the fetched CVE data with `cvedata.py`.
4. **Data Preprocessing**: Prepares the data using `preproscsv.py`.
5. **Model Training**: Trains a machine learning model to predict vulnerabilities with `modeltrain.py`.
6. **Vulnerability Prediction**: Runs the trained model to predict potential vulnerabilities with `predict.py`.

To run the analysis, use the following command:

```bash
python run_analysis.py
```

Each script will execute in order, and the output will be saved in logs for later review.

### 4. View the Dashboard

Once the analysis is complete, run the following command to launch the Streamlit dashboard, which provides detailed insights into the vulnerabilities detected during the analysis:

```bash
streamlit run dashboard.py
```

The dashboard will open in your browser at:

[http://localhost:8501](http://localhost:8501)

The interactive dashboard will display:

- Detected vulnerabilities
- CVE data
- Model predictions
- And much more!

### 5. Check Logs and Reports

After running the analysis, you can find additional information in the following directories:

- **Logs**: Detailed logs of each script execution (with timestamps and status) will be saved in the `logs` directory.
- **Reports**: A comprehensive analysis report will be generated and saved in the `analysis_results` directory.

### 6. Stopping the Analysis and Dashboard

To stop the analysis or the dashboard, simply terminate the process using **CTRL+C** in the terminal.

---
## Contributors

- [Prajakta](https://github.com/prajaktanaik17)
- [Ashlesh](https://github.com/Ash-the-k)
- [Madhuri](https://github.com/Madhuri-V-S)
- [Kushagra](https://github.com/KushagraShukla30)

---
