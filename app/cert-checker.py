import datetime
import ssl
import socket
import logging
import sys
import time
import os
import subprocess
import yaml
import smtplib
import warnings

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

logging.basicConfig(level=logging.INFO , stream=sys.stdout, format='%(asctime)s %(levelname)s %(message)s', datefmt='%d/%m/%Y %I:%M:%S %p')
# Suppress the DeprecationWarning
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Comment out the following lines if you want to run the app locally and uncomment the lines below them if you want to run the app in a container
email_alerts_enabled = os.environ["EMAIL_ALERTS_ENABLED"]
from_email = os.environ["FROM_EMAIL"]
smtp_server = os.environ["SMTP_SERVER"]
config_file_path = os.environ["CONFIG_FILE_PATH"]

# Uncomment the following lines if you want to run the app locally and comment out the lines above them if you want to run the app in a container
# email_alerts_enabled = "true"
# from_email = "from_email"
# smtp_server = "smtp_server"
# config_file_path = "config_file_path"


logging.info(f"Starting sites cert checker")
def email_alert(to_email, from_email, smtp_server, host, port, site_status, expiration_date):
    msg = MIMEMultipart()
    msg['To'] = to_email
    msg['From'] = from_email
    msg['Subject'] = f"CERTIFICATE EXPIRATION ALERT For {host}:{port}"
    if site_status == "near_expiration":
          body_text_html_part_1 = f"<p>Hello,<br>The certificate for <span style=\"color:yellow\"><b>{host}:{port}</b></span> will expire on <span style=\"color:yellow\"><b>{expiration_date}</b></span>.</p>"
          body_text_html_part_2 = "<p>Please take appropriate action to renew the certificate before it expires.</p>"
          body_html = MIMEText("<html><body><p>" + body_text_html_part_1 + "</p><p>" + body_text_html_part_2 + "</p></body></html>", "html")
    if site_status == "expired":
          body_text_html_part_1 = f"<p>Hello,<br>The certificate for <span style=\"color:red\"><b>{host}:{port}</b></span> is expired on {expiration_date}</p>"
          body_text_html_part_2 = "<p>Please take immediate appropriate action to renew the certificate.</p>"
          body_html = MIMEText("<html><body><p>" + body_text_html_part_1 + "</p><p>" + body_text_html_part_2 + "</p></body></html>", "html")
    if site_status == "error" or site_status == "unreachable" or site_status == "non_ssl_site":
          body_text_html_part_1 = f"<p>Hello,<br>There was an error (status code: <span style=\"color:red\"><b>{site_status}</b></span>) checking the certificate for <span style=\"color:red\"><b>{host}:{port}</b></span> please double check if site is reachable and certificate is readable.</p>"
          body_text_html_part_2 = "<p>Please take immediate appropriate action to fix the issue.</p>"
          body_html = MIMEText("<html><body><p>" + body_text_html_part_1 + "</p><p>" + body_text_html_part_2 + "</p></body></html>", "html")
    msg.attach(body_html)
    logging.info(f"----- Sending alert to {to_email}-----")
    server = smtplib.SMTP(smtp_server)
    try:
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        logging.error(f"Error sending email: {e}")
        raise Exception(f"Error sending email") from e

def check_site_availability(host, port):
    try:
        # First, try to establish an SSL connection
        sock = socket.create_connection((host, port), timeout=10)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()
        conn = context.wrap_socket(sock, server_hostname=host)
        conn.close()
        return "available"
    except ssl.SSLError as e:
        # If the SSL connection fails with an SSLError, check the message of the exception
        if "certificate verify failed" in str(e):
            # This means the site is an SSL site but has an untrusted certificate
            return "untrusted_certificate"
        else:
            # This means the site is not an SSL site, try to establish a non-SSL connection
            try:
                sock = socket.create_connection((host, port), timeout=10)
                sock.close()
                return "non_ssl_site"
            except Exception:
                # If the non-SSL connection also fails, the site is unreachable
                return "unreachable"
    except Exception:
        # If the SSL connection fails with a different exception, the site is unreachable
        return "unreachable"
            
def site_cert_checker(host, port, validity_threshold):
     try:
          cmd = f"echo | openssl s_client -servername {host} -connect {host}:{port} 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null"
          result = subprocess.check_output(cmd, shell=True).decode().strip()
          expiration_date_str = result.split("=")[1]
          expiration_date = datetime.datetime.strptime(expiration_date_str, '%b %d %H:%M:%S %Y %Z')           
          #Calculate the date 30 days from now
          threshold_date = datetime.datetime.utcnow() + datetime.timedelta(days=validity_threshold)
          current_date = datetime.datetime.utcnow()
          # Check if the certificate will expire in less than 30 days
          if expiration_date < threshold_date:
               logging.warning(f"The certificate for {host} will expire on {expiration_date}")
               site_status = "near_expiration"
          elif expiration_date < current_date:
               logging.error(f"The certificate for {host} is expired!")
               site_status = "expired"                
          else:
               logging.info(f"The certificate for {host} is still valid until {expiration_date} so it's more than defined {validity_threshold} days threshold")
               site_status = "valid"
     except subprocess.CalledProcessError as e:
          logging.exception(f"Error checking site {host}: {e}")
          site_status = "error"
     return site_status, expiration_date

def main():
     # In case you want to inspect the container, uncomment the following line this will give you 20 minutes to inspect the container then 
     # main code will start running. It's useful for debugging purposes for example if you want to check if the config file is mounted correctly.
     #time.sleep(1200)
     
     with open(config_file_path, 'r') as f:
        data = yaml.safe_load(f)
        sites = data.get('sites', [])
        logging.info(f"Total amount of sites to be checked: {len(sites)}")
        for site in sites:
            host, port, validity_threshold, to_email = site['name'], site['port'], site['threshold'], site['email']
            logging.info(f"Checking site: {host}")
            site_availability = check_site_availability(host, port)
            if site_availability != "unreachable" and site_availability != "non_ssl_site":
               site_status, expiration_date = site_cert_checker(host, port, validity_threshold)
               if email_alerts_enabled == "true":
                    for email in to_email:
                         if site_status == "near_expiration":
                              email_alert(email, from_email, smtp_server, host, port, site_status, expiration_date)
                         if site_status == "expired":
                              email_alert(email, from_email, smtp_server, host, port, site_status, expiration_date)
                         if site_status == "error":
                              email_alert(email, from_email, smtp_server, host, port, site_status, "N/A")             
            else:
                if site_availability == "unreachable":
                    logging.error(f"Site {host} is unreachable!")
                    site_status = site_availability
                    if email_alerts_enabled == "true":
                         for email in to_email:
                              email_alert(email, from_email, smtp_server, host, port, site_status, "N/A")
                    continue
                if site_availability == "non_ssl_site":
                    logging.error(f"Site {host} is not an SSL site!")
                    site_status = site_availability
                    if email_alerts_enabled == "true":
                         for email in to_email:
                              email_alert(email, from_email, smtp_server, host, port, site_status, "N/A")
                    continue
if __name__ == "__main__":
     main()