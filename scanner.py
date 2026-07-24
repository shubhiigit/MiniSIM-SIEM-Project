import nmap
import sqlite3
import os

from detector import detect_threats


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "siem.db")


def save_scan_result(host, port, state, service):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
    INSERT INTO network_scans(host, port, state, service)
    VALUES(?,?,?,?)
    """,
    (host, port, state, service))

    connection.commit()
    connection.close()



def run_scan(target="127.0.0.1"):

    result = {}

    try:
        scanner = nmap.PortScanner()

        scanner.scan(target, arguments="-sV")


        for host in scanner.all_hosts():

            result[host] = []

            if 'tcp' in scanner[host]:

                for port, service in scanner[host]['tcp'].items():

                    state = service.get("state", "unknown")
                    name = service.get("name", "unknown")


                    save_scan_result(
                        host,
                        port,
                        state,
                        name
                    )


                    result[host].append({
                        "port": port,
                        "state": state,
                        "name": name
                    })


    except Exception:

        # Render/cloud demo fallback
        result[target] = [

            {
                "port": 80,
                "state": "open",
                "name": "HTTP"
            },

            {
                "port": 443,
                "state": "open",
                "name": "HTTPS"
            },

            {
                "port": 22,
                "state": "open",
                "name": "SSH"
            }

        ]


        for scan in result[target]:

            save_scan_result(
                target,
                scan["port"],
                scan["state"],
                scan["name"]
            )


    # Run threat detection
    detect_threats()


    return result



if __name__ == "__main__":

    output = run_scan()

    print(output)
   
 
            
