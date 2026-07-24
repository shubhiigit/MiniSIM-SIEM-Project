import sqlite3

DATABASE = "database/siem.db"

def generate_report():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # Total Logs
    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]

    # Total Alerts
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]

    # Critical Threats
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='High'")
    critical_threats = cursor.fetchone()[0]

    # Scan Results
    cursor.execute("SELECT host, port, state, service FROM network_scans")
    scans = cursor.fetchall()

    connection.close()

    with open("MiniSIM_Report.txt", "w") as file:
        file.write("========== Mini SIEM Security Report ==========\n\n")
        file.write(f"Total Logs: {total_logs}\n")
        file.write(f"Security Alerts: {total_alerts}\n")
        file.write(f"Critical Threats: {critical_threats}\n\n")

        file.write("Network Scan Results\n")
        file.write("--------------------------------------\n")

        for scan in scans:
            file.write(
                f"Host: {scan[0]} | Port: {scan[1]} | State: {scan[2]} | Service: {scan[3]}\n"
            )

    return "MiniSIM_Report.txt"