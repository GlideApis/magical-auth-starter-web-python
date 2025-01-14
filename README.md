# Magical Auth Quickstart App Python

Welcome to Glide Magical Auth Quickstart project! This web app is built with Flask and deploys seamlessly to Google Cloud Platform (GCP) using Cloud Run. Follow the instructions below to get started quickly.

## Prerequisites

1. **GCP Account**: Ensure you have an active Google Cloud Platform (GCP) account.
2. **Magical Auth Service**: Subscribe to the Magical Auth service in your GCP account. [Subscribe here](https://console.cloud.google.com/marketplace/product/opengatewayaggregation-public/magical-auth).
3. **Python Environment**: Python 3.11+ installed on your system.
4. **Docker**: Docker installed for building and deploying containers.

## Quick Start Guide

### 1. Clone the Repository

```bash
git clone https://github.com/GlideApis/magical-auth-starter-web-python.git
cd magical-auth-starter-web-python
```

### 2. Set Up Local Development Environment

```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Deploy the Application

Make the deployment script executable and run it:

```bash
chmod +x deploy.sh
./deploy.sh
```

This command will handle everything, including:
- Building the Docker container
- Enabling required GCP APIs
- Deploying the app to Cloud Run

### 4. Follow the CLI Guidelines

During the deployment process, the CLI will guide you through several steps:

- **Credentials Setup**: 
  - You will be prompted to provide credentials. 
  - Go to your Glide dashboard, click the "Copy All Fields" button, and then paste the copied fields into the CLI when prompted.

### 5. Launch the Application

- The CLI will print the URL of the deployed application.
- Click this URL to start the app.

### 6. Local Development

To run the app locally:

```bash
python src/app.py
```

The app will be available at `http://localhost:8080`

### 7. Explore the Demo

- **Non-Mobile Devices**: If you're accessing the app from a non-mobile device, you can use our test number to get the full experience:
  - Test Number: `+555123456789`
 
- **Mobile Devices**: If you're accessing the app from your phone, feel free to test it with any valid number.

## Project Structure

```
├── src/
│   ├── app.py          # Main Flask application
│   ├── __init__.py     # Makes src a Python package
│   └── static/         # Static files (HTML, CSS, JS)
├── requirements.txt    # Python dependencies
├── Dockerfile         # Container configuration
├── deploy.sh          # Deployment script
└── README.md         # This file
```

## Environment Variables

The following environment variables are required:

- `GLIDE_CLIENT_ID`: Your Glide client ID
- `GLIDE_CLIENT_SECRET`: Your Glide client secret
- `MAGIC_REDIRECT_URI`: The callback URL (set automatically during deployment)
- `PORT`: The port to run on (defaults to 8080)

These are managed automatically by the deployment script.

Enjoy testing and exploring the app!
