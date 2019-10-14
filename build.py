#!/usr/bin/env python3

import os
import subprocess
import shutil
from Crypto import Random
from Crypto.Cipher import AES

cwd = os.getcwd()

# Build the whitebox if it doesn't exists
if not os.path.exists('./bin/whitebox'):
    try:
        os.mkdir("bin")
    except:
        print("bin folder exists, proceeding...")
    os.chdir("./build")
    subprocess.run(['cmake', '..'])
    subprocess.run(['make', '-j'])

    # Copy the built white-box to /bin
    os.chdir(cwd)
    shutil.copy('./build/bin/whitebox', './bin/whitebox')
else:
    print("White box binary found!")

# Generate whitebox tables with random keys
if not os.path.exists('./tables'):
    try:
        os.mkdir("tables")
    except:
        print("tables folder exists, proceeding...")

# Generate random AES key
AES_key = Random.new().read(AES.block_size)

subprocess.run(['./bin/whitebox', "--create-encryption-tables", './gen/whiteboxtable.h',
    '--key', AES_key.hex(), '--create-c-file'])
subprocess.run(['g++', './gen/whitebox.cpp', '-o', './gen/whitebox'])
shutil.copy('./gen/whitebox', './gen/whitebox.gold')
subprocess.run(['./bin/whitebox', "--create-encryption-tables", './tables/encryption.table',
    '--key', AES_key.hex()])
subprocess.run(['./bin/whitebox', "--create-decryption-tables", './tables/decryption.table',
    '--key', AES_key.hex()])

key_file = open('./tables/key', 'w')
key_file.write(AES_key.hex())
key_file.close()
