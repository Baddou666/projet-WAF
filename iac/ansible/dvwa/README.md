# DVWA (Damn Vulnerable Web Application)

This is a Docker Compose setup for DVWA, a PHP/MySQL web application designed for security testing and learning purposes.

## Prerequisites

- Docker and Docker Compose installed on your system.

## Usage

1. Navigate to this directory (`dvwa`).

2. Run `docker-compose up` to start the services.

3. Open your web browser and go to http://localhost to access the DVWA application.

4. Default login credentials:
   - Username: `admin`
   - Password: `password`

## Services

- **dvwa**: The web application running on PHP with Apache.
- **db**: MySQL database for storing application data.

## Troubleshooting

- If port 80 is already in use on your system, you can change the port mapping in `docker-compose.yml` (e.g., change `"80:80"` to `"8080:80"` and access at http://localhost:8080).
- Ensure Docker is running before executing `docker-compose up`.
- If you encounter database connection issues, wait a moment for the database to initialize.

## Stopping the Application

Run `docker-compose down` to stop and remove the containers.