# SSH Log Monitoring & Threat Detection

A Python script that monitors SSH logs in real-time, detects suspicious login attempts such as invalid user access, and sends email alerts to the administrator.

## Features

- Monitors SSH authentication logs continuously  
- Detects failed login attempts and unauthorized access  
- Sends automated email notifications for security alerts  
- Easy to configure and customize for different environments

## Technologies Used

- Python  
- Linux system logs (`journalctl` or `/var/log/auth.log`)  
- SMTP for sending email alerts

## Prerequisites

- Python 3.x installed  
- Access to SSH logs (usually requires root or sudo privileges)  
- Email account credentials for sending alerts (SMTP)

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/<your-username>/<repo-name>.git
   cd <repo-name>
