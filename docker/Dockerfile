#Download base image ubuntu 18.04
FROM ubuntu:16.04

# Update Ubuntu Software repository
RUN apt-get update

# Install python3
RUN apt install -qy python3

# Install python3-pip
RUN apt install -qy python3-pip

# Upgrade pip3
RUN pip3 install --upgrade pip

ADD /app /app

WORKDIR /app

# Install requirements
RUN pip3 install -r requirements.txt