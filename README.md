# Xpl2 - Vulnerability Analysis Dashboard

A comprehensive vulnerability analysis and visualization system that combines machine learning predictions with interactive dashboards.

## Quick Start

1. Install Python 3.8 or higher if not already installed
2. Install required packages:
```bash
pip install flask pandas numpy scikit-learn joblib streamlit plotly
```

3. Run the Flask dashboard:
```bash
python app.py
```

4. In a new terminal, run the Streamlit dashboard:
```bash
streamlit run dashboard.py
```

5. Access the dashboards:
- Main Dashboard: http://localhost:5000
- Advanced Analytics: http://localhost:8501

## Detailed Setup

### Prerequisites
- Python 3.8+
- pip (Python package installer)
- Git (optional)

### Installation Steps

1. **Download and Extract Files**
   - Download the provided zip file
   - Extract to your preferred location

2. **Create Virtual Environment (Recommended)**
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux/Mac
python -m venv venv
source venv/bin/activate
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

### Running the System

1. **Start Flask Server**
```bash
# Make sure you're in the project directory
python app.py
```
You should see: "Running on http://127.0.0.1:5000"

2. **Start Streamlit Dashboard**
Open a new terminal:
```bash
# Activate virtual environment again if using one
.\venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# Run Streamlit
streamlit run dashboard.py
```

3. **Access the Dashboards**
- Main Dashboard: http://localhost:5000
- Advanced Dashboard: http://localhost:8501
- Or click "Advanced Dashboard" in the main interface

## Troubleshooting

### Common Issues

1. **"Module not found" errors**
```bash
pip install [missing_module_name]
```

2. **Port already in use**
- Close other applications using ports 5000 or 8501
- Or modify port in app.py:
```python
app.run(port=5001)  # Change to different port
```

3. **Dashboard not loading**
- Ensure both Flask and Streamlit servers are running
- Check if you're using the correct URLs
- Try refreshing the page

### File Structure
Make sure you have these essential files: