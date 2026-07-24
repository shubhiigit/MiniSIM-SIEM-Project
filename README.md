# MiniSIM - Mini Security Information and Event Management System

## Overview

MiniSIM is a lightweight Security Information and Event Management (SIEM) system developed to demonstrate the basic concepts of cybersecurity monitoring. It collects system logs, analyzes security events, detects suspicious activities, and displays results through a web-based dashboard.

The project helps in understanding log management, threat detection, database handling, and security event monitoring.

## Features

- Log collection and analysis
- Log parsing and structured data processing
- Basic threat detection using predefined rules
- Security event storage using SQLite database
- Web-based monitoring dashboard
- Security report generation

## Technologies Used

- Python
- Flask
- SQLite
- HTML
- CSS
- JavaScript
- Pandas
- NumPy

## Project Structure

MiniSIM/
│
├── app.py  
├── config.py  
├── database.py  
├── detector.py  
├── log_collector.py  
├── parse.py  
├── report.py  
├── scanner.py  
├── requirements.txt  
├── templates/  
├── static/  
├── database/  
└── log/  

## Installation and Setup

### Clone the repository

git clone <repository-url>

### Install dependencies

pip install -r requirements.txt

### Run the application

python app.py

### Open in browser

http://127.0.0.1:5000

## Future Enhancements

- Real-time threat monitoring
- Machine learning based threat detection
- Cloud deployment
- Automated security alerts
- Advanced security analytics

## Project Report

The detailed project report is available in ProjectReport.pdf.

## Author

MiniSIM - Cybersecurity Learning Project
