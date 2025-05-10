# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-19.

from pwn import *

# Establish connection to challenge-and-response server
conn = remote('172.232.27.9', 64392)

# Read bit offset (DOV) of data packet
offset = conn.recvn(2)

# Code here: convert the 2 byte offset value to a short
offset_short = u16(offset)  # Unpack the 2 bytes into a 16-bit unsigned integer

# Read 100 bytes of challenge packet
challenge = conn.recvn(100)
print(f'Received {len(challenge)} bytes.')
print(f'Data: {challenge}')

# Code here: with the offset value and challenge packet, find the data
# packet and determine which option to multiply by the multiple

# Calculate the byte offset from the bit offset
byte_offset = offset_short // 8
bit_position = offset_short % 8

# Extract the data at the calculated offset
data_byte = challenge[byte_offset]
# Get the specific bit at the bit position (0 or 1)
data_bit = (data_byte >> bit_position) & 1

# Determine which option to use based on the data bit
if data_bit == 0:
    # Option 1: Sum all bytes in the challenge
    K = sum(challenge)
else:
    # Option 2: Product of first and last bytes in the challenge
    K = challenge[0] * challenge[-1]

# Convert K to 8 bytes (64-bit value)
K_bytes = p64(K)  # Pack the value into 8 bytes in little-endian format
conn.send(K_bytes)

print(conn.recvn(16))  # Get the response from the server!