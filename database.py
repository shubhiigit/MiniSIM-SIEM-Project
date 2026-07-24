import sqlite3


DATABASE = "database/siem.db"



def create_database():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()


    # Logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        event TEXT,
        source_ip TEXT,
        severity TEXT
    )
    """)


    # Alerts table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT,
        description TEXT,
        severity TEXT
    )
    """)


    # Network Scan Results table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT,
        port INTEGER,
        state TEXT,
        service TEXT
    )
    """)


    connection.commit()
    connection.close()



def insert_scan_result(host, port, state, service):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()


    cursor.execute("""
    INSERT INTO network_scans(host, port, state, service)
    VALUES(?,?,?,?)
    """,
    (host, port, state, service))


    connection.commit()
    connection.close()



def insert_sample_logs():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()


    logs = [
        ("2026-07-15 10:30", "Failed Login Attempt", "192.168.1.10", "High"),
        ("2026-07-15 10:35", "Port Scan Detected", "192.168.1.25", "Medium"),
        ("2026-07-15 10:40", "Successful Login", "192.168.1.5", "Low")
    ]


    cursor.executemany(
        """
        INSERT INTO logs(timestamp,event,source_ip,severity)
        VALUES(?,?,?,?)
        """,
        logs
    )


    connection.commit()
    connection.close()



def insert_sample_alerts():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()


    alerts = [
        ("Brute Force Attack",
         "Multiple failed login attempts detected",
         "High"),

        ("Port Scan",
         "Suspicious network scanning activity",
         "Medium")
    ]


    cursor.executemany(
        """
        INSERT INTO alerts(alert_type,description,severity)
        VALUES(?,?,?)
        """,
        alerts
    )


    connection.commit()
    connection.close()



if __name__ == "__main__":

    create_database()

    insert_sample_logs()

    insert_sample_alerts()

    print("Database setup completed successfully")