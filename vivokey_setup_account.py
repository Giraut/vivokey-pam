#!/usr/bin/python3
"""OATH account setup utility for the Vivokey PAM module.

This utility:

1/ Generates the QR code the user needs to create the account in the
   Vivokey Authenticator app. See:

   https://play.google.com/store/apps/details?id=com.vivokey.vivoauth

2/ Saves the account name, OATH password and OATH secret for this user in the
   Vivokey PAM configuration file at /etc/users.vivokey. Those details are
   used by the Vivokey PAM module to query the TOTP code for the correct OATH
   account in the Vivokey device and verify it against the code generated
   locally using the stored secret

The QR code may be saved into a PNG image file using -o <file>. This image may
then be mailed to the user.

However, by default, the QR code is rendered directly on the terminal using
ASCII art.  

This is convenient if the user is around while doing the setup - particularly
since they'll have to type in their OATH password if they have one set up in
their Vivokey device.
But more importantly, it avoids saving the secret to a file and mailing it,
and having to ask the user to carefully delete the image file and email after
they're done setting up the account in the Vivokey Authenticator app.

By default, the account name is <username>@<hostname>. However, this may be
overridden and set to anything using -a <name>. Care should be taken that the
account name be unique in the Vivokey device, as the PAM module relies on
it to be uniquely distinguishable from all other OATH accounts stored on
the device.
"""

### Modules
import os
import sys
import qrcode
import argparse
import numpy as np
from random import randint
from getpass import getpass
from base64 import b32encode



### Parameters
default_cfgfile = "/etc/users.vivokey"
default_qrcode_out = "-"
nb_secret_digits = 10



### Defines
unicode_upper_half_block = "\u2580"
unicode_lower_half_block = "\u2584"
unicode_full_block = "\u2588"
ansi_set_white_on_black = "\033[97;40m"
ansi_reset = "\033[00m"



### Routines
def generate_bw_ascii_art(img):
  """Generate a printable string containing a sequence of basic ANSI codes and
  block unicode characters to render a black and white image in ASCII art
  """

  data = np.array(img)

  s = ""

  # Scan even and odd pairs of lines if we do unicode, or all single lines
  # arranged as pairs if we don't
  for upper_line, lower_line in zip(data[:-1:2, ...], data[1::2, ...]):

    if s:
      s += "\n"

    # Scan all the pixels in that pair of lines
    for upper_pixel, lower_pixel in zip(upper_line, lower_line):

      if upper_pixel:	# White upper pixel
        if lower_pixel:	# White lower pixel
          s += unicode_full_block
        else:		# Black lower pixel
          s += unicode_upper_half_block
      else:		# Black upper pixel
        if lower_pixel:	# White lower pixel
          s += unicode_lower_half_block
        else:		# Black lower pixel
          s += " "

  # Set white on black before the rendering, in case the user has set their
  # terminal with some other color scheme, then reset the graphic mode
  s = ansi_set_white_on_black + s + ansi_reset

  return s



### Main routine
if __name__ == "__main__":

  hostname = os.uname().nodename

  # Parse the command line arguments
  argparser = argparse.ArgumentParser()

  argparser.add_argument(
	"-u", "--user",
	help = "User to create an OATH account for",
	type = str,
	required = True)

  argparser.add_argument(
	"-a", "--account",
	help = "OATH account name to use. Default: <user>@{}".format(hostname),
	type = str)

  argparser.add_argument(
	"-o", "--output",
	help = "PNG image file to save the QR code in. Use - to render the "
		"QR code in the console in ASCII art. Default: {}".
		format(default_qrcode_out),
	type = str,
	default = default_qrcode_out)

  argparser.add_argument(
	"-c", "--cfgfile",
	help = "Path to the configuration file. Default: {}".
		format(default_cfgfile),
	type = str,
	default = default_cfgfile)

  args = argparser.parse_args()

  # Resolve the default account name if an account name wasn't supplied
  account = args.account if args.account else \
		"{}@{}".format(args.user, hostname)

  # Create the secret
  secret = bytes([randint(0, 255) for _ in range(0, nb_secret_digits)])

  # Create the QR code data
  b32secret = b32encode(secret).decode("ascii")
  qrdata = "otpauth://totp/{}?secret={}".format(args.account, b32secret)

  # If we render the QR code directly in the terminal, generate it with a 1x1
  # block size, render it and print it
  if args.output == "-":
    print()
    print(generate_bw_ascii_art(qrcode.make(qrdata, box_size = 1)))
    print()

  # If we save the QR code into a file, generate it with the default block size
  # and save it
  else:
    img = qrcode.make(qrdata)

    try:
      img.save(args.output)

    except Exception as e:
      print("Error saving QR code image: {}".format(e), file = sys.stderr)
      exit(-1)

    print("Saved PNG image of QR code into {}".format(args.output))

  # Prompt for the OATH password
  password = getpass("OATH password (leave blank for none): ")

  # Ask confirmation to save this new user account configuration into the
  # configuration file
  print("Save account {} for user {} into {} [Y/N]? ".
	format(account, args.user, args.cfgfile), end = "")

  if input().upper() != "Y":
    print("Aborted")
    exit(0)

  # Read in the configuration file
  try:
    with open(args.cfgfile, "r") as f:
      lines = f.read().splitlines()

  except:
    lines = []

  # Prune any existing configuration lines that concern this user
  lines = [l for l in lines if not l.lstrip().startswith(args.user)]

  # Add the new configuration line
  hexsecret = "".join([format(v, "02x") for v in secret])
  lines.append("{} {} {} {}".format(args.user, account,
				password if password else "-", hexsecret))

  # Save the modified configuration back into the configuration file
  try:
    with open(args.cfgfile, "w") as f:
      for l in lines:
        print(l, file = f)

  except Exception as e:
    print("Error writing configuration file {}: {}".format(args.cfgfile, e),
		file = sys.stderr)
    exit(-1)

  # All done
  print("Done")
  exit(0)
