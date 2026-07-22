$PROJECT_DIR = "D:\MSc-Research\Healthcare-risk-engine"
$PYTHON = "D:\MSc-Research\venv\Scripts\python.exe"
$SSH_KEY = "$env:USERPROFILE\.ssh\msc_risk_key"
$ZEEK_SERVER = "192.168.100.120"
$ZEEK_USER = "vagrant"

cd $PROJECT_DIR

while ($true) {
    Write-Host "Collecting latest Wazuh alerts..."
    & $PYTHON src\wazuh_live_collector.py

    Write-Host "Copying latest Zeek conn.log..."
    scp -i $SSH_KEY -o BatchMode=yes "${ZEEK_USER}@${ZEEK_SERVER}:/home/vagrant/conn.log" "$PROJECT_DIR\data\live_zeek_conn.log"

    Write-Host "Parsing Zeek conn.log..."
    & $PYTHON src\zeek_log_parser.py

    Write-Host "Running risk engine..."
    & $PYTHON src\risk_engine.py

    Write-Host "Pushing scored events to OpenSearch..."
    & $PYTHON src\push_scored_events.py

    Write-Host "Dashboard data updated. Waiting 30 seconds..."
    Start-Sleep -Seconds 30
}