#!/bin/bash
# Script to automate mapping an encrypted partition in /dev/mapper with
# cryptsetup using a hash calculated by a Vivokey OTP token as an encryption
# passphrase (OATH account and password defined in /etc/users.vivokey for the
# user VIVOKEY_USER below), then optionally mount the encrypted partition

VIVOKEY_USER=enc
VIVOKEY_READ_WAIT=5 #s
CRYPT_MODE=plain

# Uncomment this if cryptsetup gives you the following warning and the
# encrypted partition can't be mounted:
# WARNING: Using default options for cipher (aes-xts-plain64, key size 256 bits)
# that could be incompatible with older versions.
#CRYPTSETUP_OPTIONS="--cipher aes-cbc-essiv:sha256 --key-size 256 --hash ripemd160"



# Show usage
if [ ! "$1" ] || [ ${1:0:1} = "-" ]; then
  echo "Usage $0 <blkdev> [mountpoint]"
  exit
fi

# Get the partition's UUID
if ! UUID=$(blkid -s PARTUUID -o value $1) || [ ! "$UUID" ]; then
  echo "Error getting PARTUUID of $1"
  exit
fi

# Ask the Vivokey token to calculate a hash from the partition UUID using the
# OATH credentials stored in /etc/users.vivokey for user VIVOKEY_USER
echo "Present your Vivokey to the reader within $VIVOKEY_READ_WAIT seconds..."
if ! HASH=$(echo -n $UUID | \
	vivokey_pam.py gethash -u $VIVOKEY_USER -w $VIVOKEY_READ_WAIT); then
  exit
fi

DMNAME=${UUID}_$CRYPT_MODE
DMPATH=/dev/mapper/$DMNAME

# Map the encrypted partition in /dev/mapper using the hash as a passphrase
if ! echo -n $HASH | cryptsetup open --type $CRYPT_MODE $CRYPTSETUP_OPTIONS $1 $DMNAME -d-; then
  exit
fi

echo $1 successfully mapped to $DMPATH

# Mount the encrypted partition if the user supplied a mount point
if [ "$2" ] && mount $DMPATH $2; then
  echo $DMPATH successfully mounted to $2
fi
