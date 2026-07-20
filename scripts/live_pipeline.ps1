while ($true) {
    Write-Host "Collecting latest Wazuh alerts..."
    D:\MSc-Research\venv\Scripts\python.exe src\wazuh_live_collector.py

    Write-Host "Collecting latest Zeek conn.log..."
    scp vagrant@192.168.100.120:/home/vagrant/conn.log D:\MSc-Research\Healthcare-risk-engine\data\live_zeek_conn.log

    Write-Host "Parsing Zeek conn.log..."
    D:\MSc-Research\venv\Scripts\python.exe src\zeek_log_parser.py

    Write-Host "Running contextual risk engine..."
    D:\MSc-Research\venv\Scripts\python.exe src\risk_engine.py

    Write-Host "Pushing scored events to OpenSearch..."
    D:\MSc-Research\venv\Scripts\python.exe src\push_scored_events.py

    Write-Host "Pipeline completed. Waiting 30 seconds..."
    Start-Sleep -Seconds 30
}