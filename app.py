from flask import Flask, render_template, send_file
import sqlite3
import os

from scanner import run_scan
from report import generate_report


# Correct static and template paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
    static_url_path="/static"
)


DATABASE = os.path.join(BASE_DIR, "database", "siem.db")


def get_dashboard_data():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity='High'"
    )
    critical_threats = cursor.fetchone()[0]

    connection.close()

    return total_logs, total_alerts, critical_threats



def get_alerts():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT alert_type, description, severity
        FROM alerts
        ORDER BY id DESC
    """)

    alerts = cursor.fetchall()

    connection.close()

    return alerts



@app.route("/")
def home():

    logs, alerts, threats = get_dashboard_data()

    alert_data = get_alerts()

    return render_template(
        "dashboard.html",
        logs=logs,
        alerts=alerts,
        threats=threats,
        alert_data=alert_data
    )



@app.route("/scan")
def scan():

    scan_result = run_scan("127.0.0.1")

    return {
        "scan_result": scan_result
    }



@app.route("/report")
def report():

    report_file = generate_report()

    return send_file(
        report_file,
        as_attachment=True
    )



if __name__ == "__main__":

    print("STATIC FOLDER:", app.static_folder)
    print("TEMPLATE FOLDER:", app.template_folder)

    app.run(debug=True)
