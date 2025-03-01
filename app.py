from flask import Flask, render_template, jsonify
import pandas as pd
import os
import glob
from datetime import datetime

app = Flask(__name__)

def load_latest_predictions():
    prediction_files = glob.glob('vulnerability_reports/predictions_*.csv')
    if not prediction_files:
        return None
    latest_file = max(prediction_files, key=os.path.getctime)
    return pd.read_csv(latest_file), latest_file

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    try:
        data_load = load_latest_predictions()
        if data_load is None:
            return jsonify({'error': 'No prediction data found'})
        
        df, _ = data_load
        return jsonify({
            'data': df.to_dict('records'),
            'summary': {
                'total': len(df),
                'critical': len(df[df['Predicted_Severity'] == 'CRITICAL']),
                'high': len(df[df['Predicted_Severity'] == 'HIGH']),
                'medium': len(df[df['Predicted_Severity'] == 'MEDIUM']),
                'low': len(df[df['Predicted_Severity'] == 'LOW']),
                'packages': df['Package'].nunique(),
                'avg_cvss': float(df['CVSS'].mean())
            }
        })
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': 'Internal server error'})

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    # Create necessary directories if they don't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    
    print("Starting Flask server...")
    print("Access the dashboard at: http://127.0.0.1:5000")
    app.run(debug=True)