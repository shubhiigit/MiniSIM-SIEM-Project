import sqlite3
from detector import detect_threats


DATABASE = "database/siem.db"

LOG_FILE = "logs/system.log"



def collect_logs():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()


    with open(LOG_FILE, "r") as file:

        logs = file.readlines()


    for log in logs:

        data = log.strip().split("|")


        timestamp = data[0].strip()
        event = data[1].strip()
        source_ip = data[2].strip()
        severity = data[3].strip()


        cursor.execute(
            """
            INSERT INTO logs(
                timestamp,
                event,
                source_ip,
                severity
            )
            VALUES(?,?,?,?)
            """,
            (
                timestamp,
                event,
                source_ip,
                severity
            )
        )


    connection.commit()

    connection.close()


    print("Logs collected successfully")


    # Automatically run threat detection
    detect_threats()



if __name__ == "__main__":

    collect_logs()