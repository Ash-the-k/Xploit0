document.addEventListener('DOMContentLoaded', function() {
    fetchData();
});

async function fetchData() {
    try {
        const response = await fetch('/api/vulnerabilities');
        const data = await response.json();
        
        updateSummaryCards(data.summary);
        updateCharts(data.data);
        updateTable(data.data);
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}

function updateSummaryCards(summary) {
    document.querySelector('#total-vulns .number').textContent = summary.total;
    document.querySelector('#critical-vulns .number').textContent = summary.critical;
    document.querySelector('#high-vulns .number').textContent = summary.high;
    document.querySelector('#avg-cvss .number').textContent = summary.avg_cvss.toFixed(2);
}

function updateCharts(data) {
    // Severity Distribution Chart
    const severityCounts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0
    };
    
    data.forEach(item => {
        severityCounts[item.Predicted_Severity]++;
    });

    new Chart(document.getElementById('severityChart'), {
        type: 'doughnut',
        data: {
            labels: Object.keys(severityCounts),
            datasets: [{
                data: Object.values(severityCounts),
                backgroundColor: ['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71']
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Vulnerability Severity Distribution'
                }
            }
        }
    });

    // Package Distribution Chart
    const packageData = {};
    data.forEach(item => {
        if (!packageData[item.Package]) {
            packageData[item.Package] = {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            };
        }
        packageData[item.Package][item.Predicted_Severity]++;
    });

    new Chart(document.getElementById('packageChart'), {
        type: 'bar',
        data: {
            labels: Object.keys(packageData),
            datasets: [
                {
                    label: 'Critical',
                    data: Object.values(packageData).map(p => p.CRITICAL),
                    backgroundColor: '#e74c3c'
                },
                {
                    label: 'High',
                    data: Object.values(packageData).map(p => p.HIGH),
                    backgroundColor: '#e67e22'
                },
                {
                    label: 'Medium',
                    data: Object.values(packageData).map(p => p.MEDIUM),
                    backgroundColor: '#f1c40f'
                },
                {
                    label: 'Low',
                    data: Object.values(packageData).map(p => p.LOW),
                    backgroundColor: '#2ecc71'
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Package-wise Vulnerability Distribution'
                }
            },
            scales: {
                x: {
                    stacked: true
                },
                y: {
                    stacked: true
                }
            }
        }
    });
}

function updateTable(data) {
    const tbody = document.querySelector('#vulnTable tbody');
    tbody.innerHTML = '';
    
    const highSeverityData = data.filter(item => 
        ['CRITICAL', 'HIGH'].includes(item.Predicted_Severity)
    );
    
    highSeverityData.forEach(item => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${item.CVE_ID}</td>
            <td>${item.Package}</td>
            <td>${item.Predicted_Severity}</td>
            <td>${item.CVSS}</td>
            <td>${item.Recommendation}</td>
        `;
        tbody.appendChild(row);
    });
}