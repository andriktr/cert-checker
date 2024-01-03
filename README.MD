# Cert Checker

## Table of Contents

- [Description](#description)
- [Configure](#configure)
  - [Configure app to run locally](#configure-app-to-run-locally)
  - [Configure cert-checker Helm chart](#configure-cert-checker-helm-chart)
- [Deploy](#deploy)
  - [Run application locally](#run-application-locally)
  - [Build Docker image](#build-docker-image)
  - [Deploy to Kubernetes](#deploy-to-kubernetes)
- [Remove](#remove)

## Description

This repository contains a simple python application that checks the expiration date of the site certificate and sends an email if the certificate is about to expire or expired. The application is meant to be deployed as a Kubernetes Cronjob. A [Helm chart](cert-checker/) is provided to configure and deploy the application to a Kubernetes cluster.

## Configure

### Configure app to run locally

Although application meant to be deployed as a Kubernetes Cronjob, it can also be run locally. To run the application locally, you need to set several environment variables:

```bash
export EMAIL_ALERTS_ENABLED= "" # Set to "true" to enable email alerts or "false" to disable email alerts
export FROM_EMAIL= "" # Email address to send alerts from
export SMTP_SERVER= "" # SMTP server to use to send alerts from
export CONFIG_FILE_PATH= "" # Path to sites.yaml file
```

As alternative to setting environment variables, you can modify the [cert-checker.py](app/cert-checker.py) file and set the variables there by commenting/uncommenting the appropriate lines shown below:

```python
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
```

Then create a `sites.yaml` and put it in the CONFIG_FILE_PATH directory. The `sites.yaml` file should be formatted as follows:

```yaml
- name: sysadminas.eu
  port: 443
  threshold: 30
  email: email.address@domain.com
- name: google.com
  port: 443
  threshold: 30
  email: email.address@domain.com
```

### Configure cert-checker Helm chart

The [cert-checker Helm chart values.yaml](cert-checker/values.yaml should be used to configure the application. The following table lists the configurable parameters of the cert-checker chart and their default values:

Parameter | Description | Default
--------- | ----------- | -------
labels | Labels to add to the Cronjob | `{}`
sites | List of sites to check see [values.yaml](cert-checker/values.yaml) for example | `[]`
configPath | Path where the sites.yaml file will be mounted | `/config`
cronjob.schedule | Schedule for the Cronjob | `0 20 * * 6`
cronjob.name | Name of the Cronjob | `cert-checker`
cronjob.annotations | Annotations to add to the Cronjob | `{}`
cronjob.restartPolicy | Restart policy for the Cronjob | `Never`
cronjob.backoffLimit | Number of retries before considering a job as failed | `0`
cronjob.failedJobsHistoryLimit | Number of failed jobs to keep | `1`
cronjob.successfulJobsHistoryLimit | Number of successful jobs to keep | `3`
cronjob.concurrencyPolicy | Concurrency policy for the Cronjob | `Forbid`
cronjob.timeZone | Time zone for the Cronjob | `Europe/Vilnius`
image.repository | # Repository name in format repository/image-name | cert-checker
image.pullPolicy | Image pull policy | `IfNotPresent`
image.tag | Image tag | ``
serviceAccount.create | Create a service account | `true`
serviceAccount.annotations | Annotations to add to the service account | `{}`
serviceAccount.name | Name of the service account | `cert-checker`
podAnnotations | Annotations on the pod level | `{}`
podSecurityContext | Security context on the pod level | `{}`
securityContext | Security context on the container level | `{}`
resources | Resource requests and limits | `{}`
emailAlerts.enabled | Enable email alerts | `true`
smtp.server | SMTP server to use to send alerts from | ``
smtp.from | Email address to send alerts from | ``
additionalEnvVars | Additional environment variables to add to the container | `[]`

## Deploy

### Run application locally

To run the application locally first configure the application as described in [Configure app to run locally](#configure-app-to-run-locally) and then run the following commands assuming you have python3 installed and your current working directory is the root of this repository:

```bash
# Change to the app directory
cd app
# Install dependencies
pip3 install -r requirements.txt
# Run the application
python3.11 cert-checker.py
```

### Build Docker image

To build the Docker image run the following commands assuming your current working directory is the root of this repository:

```bash
export REGISTRY=andriktr
# Change to the app directory
cd app
# Build the Docker image
docker build --platform linux/amd64 -t andriktr/cert-checker:0.1.0 . --no-cache --pull
# Push the Docker image to Docker Hub
docker push andriktr/cert-checker:0.1.0
```

### Deploy to Kubernetes

Once the Docker image is ready and your helm `values.yaml` is adjusted to your needs, you can test and deploy the application to Kubernetes by running the following commands assuming your current working directory is the root of this repository:

`Test cert-checker Helm chart:`

```bash
helm upgrade --install cert-checker cert-checker --namespace cert-checker --create-namespace --values cert-checker/values.yaml --dry-run --debug
```

`Deploy cert-checker Helm chart:`

```bash
helm upgrade --install cert-checker cert-checker --namespace cert-checker --create-namespace --values cert-checker/values.yaml
```

## Remove

To remove the application from Kubernetes run the following command:

```bash
helm uninstall cert-checker --namespace cert-checker
```
