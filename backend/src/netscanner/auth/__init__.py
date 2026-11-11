# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Administrator authentication (admin-authentication spec, RNF-05, RNF-01).

Password hashing, the account, server-side sessions, the guessing limit and
the route protection. Only this package imports ``argon2`` and reads the
session cookie (design D1).
"""
