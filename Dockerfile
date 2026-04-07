# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Automatically clean up any accidental markdown backticks/eof from copy-pasting, then install dependencies
RUN sed -i '/`/d' requirements.txt && \
    sed -i '/eof/d' requirements.txt && \
    pip install --no-cache-dir -r requirements.txt

# Let Playwright automatically install all the correct Linux system dependencies!
RUN playwright install-deps chromium
RUN playwright install chromium

# Copy project files
COPY . .

# Expose the port Flask runs on
EXPOSE 5001

# Command to run the application
CMD ["python", "app.py"]