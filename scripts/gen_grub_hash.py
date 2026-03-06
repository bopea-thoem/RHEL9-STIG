#!/usr/bin/env python3
import os, hashlib, base64
password = 'FCSupport@2026'
iterations = 10000
salt = os.urandom(16)
# derive key
dk = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, iterations, dklen=64)
# base64 without padding
salt_b64 = base64.b64encode(salt).decode('ascii').rstrip('=')
dk_b64 = base64.b64encode(dk).decode('ascii').rstrip('=')
print(f'grub.pbkdf2.sha512.{iterations}.{salt_b64}.{dk_b64}')
