test pipeline

1. Confirm all required lab machines are reachable

From Windows PowerShell:
$Hosts = @(
    "192.168.100.10",   # attacker-kali
    "192.168.100.20",   # user-pc-01
    "192.168.100.21",   # admin-pc-01
    "192.168.100.30",   # ehr-app-server-01
    "192.168.100.40",   # ehr-db-server-01
    "192.168.100.50",   # file-server-01
    "192.168.100.100",  # monitoring/Wazuh server
    "192.168.100.120"   # Zeek sensor
)

foreach ($HostIP in $Hosts) {
    Test-Connection $HostIP -Count 1 -Quiet |
        ForEach-Object {
            "$HostIP reachable: $_"
        }
}

2. Confirm all clocks are synchronized

date
date -u
chronyc tracking
chronyc -n sources -v

### Required:

Leap status : Normal
System time : close to 0 seconds

3. Confirm Wazuh services are running

for svc in wazuh-manager wazuh-indexer wazuh-dashboard filebeat
do
    printf "%-20s " "$svc"
    systemctl is-active "$svc"
done

### wazuh machine

sudo systemctl status wazuh-manager --no-pager
sudo systemctl status wazuh-indexer --no-pager
sudo systemctl status wazuh-dashboard --no-pager
sudo systemctl status filebeat --no-pager

4. check required wazuh agent are active

sudo /var/ossec/bin/agent_control -lc

sudo systemctl status wazuh-agent --no-pager


5. Confirm Zeek is running and capturing traffic

sudo /opt/zeek/bin/zeekctl status 2>/dev/null || \
sudo /usr/local/zeek/bin/zeekctl status

# Check that the log exists:

ls -lh /home/vagrant/conn.log
tail -n 3 /home/vagrant/conn.log

6. Confirm the OpenSearch SSH tunnel

Directory - D:\MSc-Research\Healthcare-risk-engine

Test-NetConnection 127.0.0.1 -Port 9200

## When it is false, establish the tunnel:

ssh -N `
  -L 9200:127.0.0.1:9200 `
  -i "$env:USERPROFILE\.ssh\msc_lab_ed25519" `
  vagrant@192.168.100.100


