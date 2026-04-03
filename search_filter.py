# search_filter.py
# Yeh function processes ki list mein search karega

def filter_processes(process_list, search_term):
    """
    Ye function process list mein se wo processes dhundlega
    jinke naam mein search_term hai
    """
    # Agar search_term khali hai to saari list wapas kar do
    if not search_term:
        return process_list
    
    # search_term ko chota (lowercase) kar do taaki a, A same lage
    search_term = search_term.lower()
    
    # Filter logic: har process check karo
    result = []
    for process in process_list:
        # process ka naam bhi lowercase karo aur check karo
        if search_term in process['name'].lower():
            result.append(process)
    
    return result


# Test code - yeh check karne ke liye ki function sahi kaam kar raha hai
if __name__ == "__main__":
    # Pehle dummy data import karo
    from dummy_data import sample_processes
    
    # Test 1: "malware" search karo
    result1 = filter_processes(sample_processes, "malware")
    print("Malware search result:", result1)
    
    # Test 2: "bash" search karo
    result2 = filter_processes(sample_processes, "bash")
    print("Bash search result:", result2)
    
    # Test 3: kuch bhi nahi likha (empty search)
    result3 = filter_processes(sample_processes, "")
    print("Empty search result (sab kuch aana chahiye):", result3)


    # Network connections search function
def filter_connections(conn_list, search_term):
    """
    Ye function connections ki list mein search karega
    IP address, port, protocol, ya PID mein se match karega
    """
    if not search_term:
        return conn_list
    
    search_term = search_term.lower()
    result = []
    
    for conn in conn_list:
        # Check in multiple fields
        if (search_term in str(conn.get('pid', '')).lower() or
            search_term in conn.get('local_ip', '').lower() or
            search_term in str(conn.get('local_port', '')).lower() or
            search_term in conn.get('remote_ip', '').lower() or
            search_term in str(conn.get('remote_port', '')).lower() or
            search_term in conn.get('protocol', '').lower()):
            result.append(conn)
    
    return result


# Test code (neechay likho)
if __name__ == "__main__":
    from dummy_data import sample_processes, sample_connections
    
    # Processes test
    print("=== PROCESS SEARCH ===")
    print(filter_processes(sample_processes, "malware"))
    
    # Connections test
    print("\n=== CONNECTIONS SEARCH ===")
    print(filter_connections(sample_connections, "185.130"))  # IP search
    print(filter_connections(sample_connections, "4444"))      # Port search
    print(filter_connections(sample_connections, "TCP"))       # Protocol search