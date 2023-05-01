# For more information, please refer to https://aka.ms/vscode-docker-python
FROM python:alpine3.17

EXPOSE 8000

# Keeps Python from generating .pyc files in the container
ENV PYTHONDONTWRITEBYTECODE=1

# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED=1

# Install pip requirements
COPY requirements.txt .
RUN python -m pip install -r requirements.txt
RUN rm requirements.txt

WORKDIR /app
COPY . /app

# Creates a non-root user with an explicit UID and adds permission to access the /app folder
# For more info, please refer to https://aka.ms/vscode-docker-python-configure-containers
RUN adduser -u 5678 --disabled-password --gecos "" appuser && chown -R appuser /app
USER appuser

# ENTRYPOINT ["nohup", "python3", "-u", "gpt.py", "> run.log", "2>&1", "&"] # did not create run.log!
ENTRYPOINT ["/bin/sh", "./entrypoint.sh"]
