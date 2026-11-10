# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Discovery runs (device-discovery spec, design D8 and D9).

Depends on the client protocol, the scope policy and the store; it never
imports the SNMP library nor decrypts credentials (design D1).
"""
