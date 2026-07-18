while ($true) {
    scp vagrant@192.168.100.120:/home/vagrant/conn.log D:\MSc-Research\Healthcare-risk-engine\data\live_zeek_conn.log

    cd D:\MSc-Research\Healthcare-risk-engine

    D:\MSc-Research\venv\Scripts\python.exe src\zeek_log_parser.py
    D:\MSc-Research\venv\Scripts\python.exe src\risk_engine.py

    Start-Sleep -Seconds 30
}