import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
from datetime import datetime
import glob

def load_latest_predictions():
    """Load the most recent predictions file"""
    prediction_files = glob.glob('vulnerability_reports/predictions_*.csv')
    if not prediction_files:
        return None
    latest_file = max(prediction_files, key=os.path.getctime)
    return pd.read_csv(latest_file), latest_file

def load_latest_report():
    """Load the most recent report file"""
    report_files = glob.glob('vulnerability_reports/vulnerability_report_*.txt')
    if not report_files:
        return None
    latest_file = max(report_files, key=os.path.getctime)
    with open(latest_file, 'r') as f:
        return f.read()

def create_severity_chart(df):
    """Create severity distribution chart"""
    severity_counts = df['Predicted_Severity'].value_counts()
    fig = px.pie(
        values=severity_counts.values,
        names=severity_counts.index,
        title='Vulnerability Severity Distribution',
        color=severity_counts.index,
        color_discrete_map={
            'CRITICAL': 'red',
            'HIGH': 'orange',
            'MEDIUM': 'yellow',
            'LOW': 'green'
        }
    )
    return fig

def create_package_severity_chart(df):
    """Create package-wise severity distribution"""
    package_severity = pd.crosstab(df['Package'], df['Predicted_Severity'])
    fig = px.bar(
        package_severity,
        title='Package-wise Vulnerability Distribution',
        barmode='stack',
        color_discrete_map={
            'CRITICAL': 'red',
            'HIGH': 'orange',
            'MEDIUM': 'yellow',
            'LOW': 'green'
        }
    )
    fig.update_layout(xaxis_title='Package', yaxis_title='Number of Vulnerabilities')
    return fig

def create_cvss_severity_scatter(df):
    """Create CVSS vs Predicted Severity scatter plot"""
    fig = px.scatter(
        df,
        x='CVSS',
        y='Predicted_Severity',
        color='Predicted_Severity',
        hover_data=['CVE_ID', 'Package'],
        title='CVSS Score vs Predicted Severity',
        color_discrete_map={
            'CRITICAL': 'red',
            'HIGH': 'orange',
            'MEDIUM': 'yellow',
            'LOW': 'green'
        }
    )
    return fig

def main():
    st.set_page_config(page_title="Advanced Vulnerability Analysis", layout="wide")
    
    st.title("Advanced Vulnerability Analysis Dashboard")
    
    # Load data
    data_load = load_latest_predictions()
    if data_load is None:
        st.error("No prediction files found. Please run predictions first.")
        return
        
    df, latest_file = data_load
    report_text = load_latest_report()
    
    # Display last update time
    st.sidebar.write(f"Last Updated: {datetime.fromtimestamp(os.path.getctime(latest_file)).strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Sidebar filters
    st.sidebar.title("Filters")
    selected_packages = st.sidebar.multiselect(
        "Select Packages",
        options=sorted(df['Package'].unique()),
        default=sorted(df['Package'].unique())
    )
    
    selected_severities = st.sidebar.multiselect(
        "Select Severities",
        options=sorted(df['Predicted_Severity'].unique()),
        default=sorted(df['Predicted_Severity'].unique())
    )
    
    # Filter data
    filtered_df = df[
        (df['Package'].isin(selected_packages)) &
        (df['Predicted_Severity'].isin(selected_severities))
    ]
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Vulnerabilities", len(filtered_df))
    with col2:
        st.metric("Critical Vulnerabilities", len(filtered_df[filtered_df['Predicted_Severity'] == 'CRITICAL']))
    with col3:
        st.metric("Affected Packages", filtered_df['Package'].nunique())
    with col4:
        st.metric("Average CVSS", f"{filtered_df['CVSS'].mean():.2f}")
    
    # Charts
    col1, col2 = st.columns(2)
    with col1:
        st.plotly_chart(create_severity_chart(filtered_df), use_container_width=True)
    with col2:
        st.plotly_chart(create_package_severity_chart(filtered_df), use_container_width=True)
    
    st.plotly_chart(create_cvss_severity_scatter(filtered_df), use_container_width=True)
    
    # Detailed vulnerability table
    st.subheader("Vulnerability Details")
    st.dataframe(
        filtered_df[['CVE_ID', 'Package', 'CVSS', 'Predicted_Severity', 'Description']],
        use_container_width=True
    )
    
    # Full vulnerability report
    with st.expander("View Full Analysis Report"):
        if report_text:
            st.text(report_text)
        else:
            st.warning("No analysis report found.")
    
    # Download buttons
    col1, col2 = st.columns(2)
    with col1:
        csv = filtered_df.to_csv(index=False)
        st.download_button(
            label="Download Filtered Data (CSV)",
            data=csv,
            file_name="filtered_vulnerabilities.csv",
            mime="text/csv"
        )
    with col2:
        if report_text:
            st.download_button(
                label="Download Full Report (TXT)",
                data=report_text,
                file_name="vulnerability_report.txt",
                mime="text/plain"
            )

if __name__ == "__main__":
    main()
