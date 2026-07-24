import sqlite3


DATABASE = "database/siem.db"



def detect_threats():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()



    # Check failed login attempts

    cursor.execute("""
    SELECT source_ip, COUNT(*)
    FROM logs
    WHERE event='Failed Login Attempt'
    GROUP BY source_ip
    """)


    failed_logins = cursor.fetchall()


    for ip, count in failed_logins:

        if count >= 3:

            cursor.execute(
            """
            INSERT INTO alerts(
                alert_type,
                description,
                severity
            )
            VALUES(?,?,?)
            """,
            (
                "Brute Force Attack",
                f"Multiple failed login attempts from {ip}",
                "High"
            )
            )



    # Check old port scan logs

    cursor.execute("""
    SELECT source_ip
    FROM logs
    WHERE event='Port Scan Detected'
    """)


    scans = cursor.fetchall()


    for scan in scans:

        cursor.execute(
        """
        INSERT INTO alerts(
            alert_type,
            description,
            severity
        )
        VALUES(?,?,?)
        """,
        (
            "Port Scan",
            f"Network scanning detected from {scan[0]}",
            "Medium"
        )
        )



    # Check Nmap scan results

    cursor.execute("""
    SELECT host, COUNT(*)
    FROM network_scans
    WHERE state='open'
    GROUP BY host
    """)


    open_ports = cursor.fetchall()


    for host, count in open_ports:

        if count >= 5:

            cursor.execute(
            """
            INSERT INTO alerts(
                alert_type,
                description,
                severity
            )
            VALUES(?,?,?)
            """,
            (
                "Suspicious Port Scan",
                f"{count} open ports detected on {host}",
                "Medium"
            )
            )



    connection.commit()

    connection.close()


    print("Threat detection completed")



if __name__ == "__main__":

    detect_threats()