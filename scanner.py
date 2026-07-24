import nmap
import sqlite3
from detector import detect_threats


DATABASE = "database/siem.db"



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

    scanner = nmap.PortScanner()

    scanner.scan(target, arguments="-sV")


    result = {}


    for host in scanner.all_hosts():

        result[host] = []


        if 'tcp' in scanner[host]:

            for port, service in scanner[host]['tcp'].items():

                state = service.get("state", "unknown")
                name = service.get("name", "unknown")


                # Save result in database
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


    # Run threat detection
    detect_threats()


    return result



if __name__ == "__main__":

    output = run_scan()

    print(output)