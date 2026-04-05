# dummy_data.py
# fake... real data aayega backend se

sample_processes = [
    {"pid": 1, "name": "init", "ppid": 0, "time": "10:00:01"},
    {"pid": 2, "name": "kthreadd", "ppid": 0, "time": "10:00:01"},
    {"pid": 1234, "name": "bash", "ppid": 1, "time": "10:05:32"},
    {"pid": 5678, "name": "malware", "ppid": 1234, "time": "10:10:15"},
]

sample_connections = [
    {"pid": 5678, "local_ip": "192.168.1.5", "local_port": 4444, 
     "remote_ip": "185.130.5.253", "remote_port": 80, "protocol": "TCP"},
    {"pid": 1234, "local_ip": "192.168.1.5", "local_port": 54321, 
     "remote_ip": "8.8.8.8", "remote_port": 53, "protocol": "UDP"},
]