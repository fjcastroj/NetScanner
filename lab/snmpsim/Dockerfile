# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
#
# Lab SNMP simulator (design D9, D10): snmpsim in its own image so that its
# PySNMP version never constrains the project's. Every dependency is pinned
# with hashes in requirements.txt. Each container serves one data file,
# mounted read-only as /data/netscanner-lab.snmprec, so the lab community is
# netscanner-lab.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt /tmp/requirements.txt
RUN pip install --require-hashes --no-deps -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt \
    && useradd --system --uid 10002 --home-dir /nonexistent --shell /usr/sbin/nologin snmpsim

USER snmpsim

# Port 161 needs net.ipv4.ip_unprivileged_port_start=0 (set in docker-compose.lab.yml).
CMD ["snmpsim-command-responder", "--data-dir=/data", "--cache-dir=/tmp/snmpsim", "--agent-udpv4-endpoint=0.0.0.0:161"]
