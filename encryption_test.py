#!/usr/bin/env python3

import os
import sys
import tempfile
import subprocess
from Crypto import Random
from Crypto.Cipher import AES

if len(sys.argv) != 2:
    print("Usage: ./encryption_test.py <path to whitebox binary>")
    sys.exit(-1)

# This is a test bed for testing the correctness and performance
# of the white box AES cipher implementation
# In order to do this, a random AES key and IV is generated
# and then a chunk of data is encrypted and compared

AES_key = Random.new().read(AES.block_size)
AES_iv = Random.new().read(AES.block_size)

# Generate a random file as a testbed
out_file = tempfile.NamedTemporaryFile()
out_file_name = out_file.name
out_file.write(os.getrandom(1024 * 1024))
out_file.flush()

# Generate white box tables
whitebox_table_name_encryption = next(tempfile._get_candidate_names())
whitebox_table_name_decryption = next(tempfile._get_candidate_names())
subprocess.run([sys.argv[1], "--create-encryption-tables", whitebox_table_name_encryption,
    '--key', AES_key.hex()])
subprocess.run([sys.argv[1], '--create-decryption-tables', whitebox_table_name_decryption,
    '--key', AES_key.hex()])

# Encrypt reference file using white box
whitebox_result_enc_cbc = subprocess.run([sys.argv[1], '--whitebox-table',
whitebox_table_name_encryption, '--set-mode', 'CBC', '--set-padding', 'PKCS',
'--encrypt', '--input-file', out_file_name, '--iv', AES_iv.hex()], stdout=subprocess.PIPE)
whitebox_result_enc_ecb = subprocess.run([sys.argv[1], '--whitebox-table',
    whitebox_table_name_encryption, '--set-mode', 'ECB', '--set-padding', 'PKCS',
    '--encrypt', '--input-file', out_file_name], stdout=subprocess.PIPE)
whitebox_result_enc_ctr = subprocess.run([sys.argv[1], '--whitebox-table',
    whitebox_table_name_encryption, '--set-mode', 'CTR', '--set-padding', 'NONE',
    '--encrypt', '--input-file', out_file_name, '--iv', AES_iv.hex()], stdout=subprocess.PIPE)

# Encrypt reference file with OpenSSL
# OpenSSL should normally use PKCS padding
openssl_result_enc_cbc = subprocess.run(['openssl', 'enc',  '-aes-128-cbc', '-e', '-in', out_file_name,
    '-K', AES_key.hex(), '-iv', AES_iv.hex()], stdout=subprocess.PIPE)
openssl_result_enc_ecb = subprocess.run(['openssl', 'enc', '-aes-128-ecb', '-e', '-in', out_file_name,
    '-K', AES_key.hex()], stdout=subprocess.PIPE)
openssl_result_enc_ctr = subprocess.run(['openssl', 'enc', '-aes-128-ctr', '-e', '-in', out_file_name,
    '-K', AES_key.hex(), '-iv', AES_iv.hex()], stdout=subprocess.PIPE)

# Check if results were correct
if whitebox_result_enc_ecb.stdout == openssl_result_enc_ecb.stdout:
    print("ECB encryption result correct")
else:
    print("ECB encryption result incorrect")
if whitebox_result_enc_cbc.stdout == openssl_result_enc_cbc.stdout:
    print("CBC encryption result correct")
else:
    print("CBC encryption result incorrect")
if whitebox_result_enc_ctr.stdout == openssl_result_enc_ctr.stdout:
    print("CTR encryption result correct")
else:
    print("CTR encryption result incorrect")

# Decrypt reference file using white box
whitebox_result_dec_cbc = subprocess.run([sys.argv[1], '--whitebox-table',
    whitebox_table_name_decryption, '--set-mode', 'CBC', '--set-padding', 'PKCS',
    '--decrypt', '--iv', AES_iv.hex()], stdout=subprocess.PIPE, input=whitebox_result_enc_cbc.stdout)
whitebox_result_dec_ecb = subprocess.run([sys.argv[1], '--whitebox-table',
    whitebox_table_name_decryption, '--set-mode', 'ECB', '--set-padding', 'PKCS',
    '--decrypt'], stdout=subprocess.PIPE, input=whitebox_result_enc_ecb.stdout)
whitebox_result_dec_ctr = subprocess.run([sys.argv[1], '--whitebox-table',
    whitebox_table_name_encryption, '--set-mode', 'CTR', '--set-padding', 'NONE',
    '--decrypt', '--iv', AES_iv.hex()], stdout=subprocess.PIPE,
    input=whitebox_result_enc_ctr.stdout)

# Decrypt reference file with OpenSSL
# OpenSSL should normally use PKCS padding
openssl_result_dec_cbc = subprocess.run(['openssl', 'enc',  '-aes-128-cbc', '-d',
    '-K', AES_key.hex(), '-iv', AES_iv.hex()], stdout=subprocess.PIPE, input=openssl_result_enc_cbc.stdout)
openssl_result_dec_ecb = subprocess.run(['openssl', 'enc', '-aes-128-ecb', '-d', '-K', AES_key.hex()],
        stdout=subprocess.PIPE, input=openssl_result_enc_ecb.stdout)
openssl_result_dec_ctr = subprocess.run(['openssl', 'enc', '-aes-128-ctr', '-d', '-K',
    AES_key.hex(), '-iv', AES_iv.hex()], stdout=subprocess.PIPE,
    input=openssl_result_enc_ctr.stdout)

# Check if results were correct
if whitebox_result_dec_ecb.stdout == openssl_result_dec_ecb.stdout:
    print("ECB decryption result correct")
else:
    print("ECB decryption result incorrect")
if whitebox_result_dec_cbc.stdout == openssl_result_dec_cbc.stdout:
    print("CBC encryption result correct")
else:
    print("CBC decryption result incorrect")
if whitebox_result_dec_ctr.stdout == openssl_result_dec_ctr.stdout:
    print("CTR decryption result correct")
else:
    print("CTR decryption result incorrect")

os.remove(whitebox_table_name_encryption)
os.remove(whitebox_table_name_decryption)
