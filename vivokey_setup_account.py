#!/usr/bin/python3
"""OATH account setup utility for the Vivokey PAM module.

This utility:

1/ Generates the QR code the user needs to create the account in the
   Vivokey Authenticator or Yubikey Authenticator app. See:

   https://play.google.com/store/apps/details?id=com.vivokey.vivoauth
   https://play.google.com/store/apps/details?id=com.yubico.yubioath

2/ Saves the account name, OATH password and OATH secret for this user in the
   Vivokey PAM configuration file at /etc/users.vivokey. Those details are
   used by the Vivokey PAM module to query the cryptographic hash for the
   correct OATH account in the Vivokey or Yubikey NFC device and verify it
   against the hash calculated locally using the stored secret

The QR code may be saved into a PNG image file using -o <file>. This image may
then be mailed to the user.

However, by default, the QR code is rendered directly on the terminal using
ASCII art.

This is convenient if the user is around while doing the setup - particularly
since they'll have to type in their OATH password if they have one set up in
their Vivokey or Yubikey NFC device.

But more importantly, it avoids saving the secret to a file and mailing it,
and having to ask the user to carefully delete the image file and email after
they're done setting up the account in the Vivokey Authenticator or
Yubikey Authenticator app.

By default, the account name is <username>@<hostname>. However, this may be
overridden and set to anything using -a <name>. Care should be taken that the
account name be unique in the Vivokey or Yubikey NFC device, as the PAM module
relies on it to be uniquely distinguishable from all other OATH accounts stored
on the device.
"""

### Modules
import re
import os
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
cfgfile_chars_per_column = 20



### Defines
unicode_upper_half_block = "\u2580"
unicode_lower_half_block = "\u2584"
unicode_full_block = "\u2588"
ansi_white_on_black = "\033[97;40m"
ansi_black_on_white = "\033[30;107m"
ansi_reset = "\033[00m"



### Routines
def generate_bw_ascii_art(img, use_unicode = True,
				cols = None, max_trim_to_fit_cols = 0):
  """Generate a printable string containing a sequence of basic ANSI codes and
  block unicode characters to render a black and white image in ASCII art

  if max_trim_to_fit_cols > 0, the image will be trimmed by as many as this
  number of characters left and right to try to fit within cols columns - but
  only if it makes the image fit
  """

  data = np.array(img)
  aa_lines = []

  # Can we use unicode characters?
  if use_unicode:

    # Scan even and odd pairs of lines
    for upper_line, lower_line in zip(data[:-1:2, ...], data[1::2, ...]):

      l = ""

      # Scan all the pixels in that pair of lines
      for upper_pixel, lower_pixel in zip(upper_line, lower_line):

        l += (unicode_full_block if lower_pixel else unicode_upper_half_block) \
		if upper_pixel else \
		(unicode_lower_half_block if lower_pixel else " ")

      aa_lines.append(l)

  # Only use ANSI colors and the space character
  else:

    # Scan lines
    for line in data[::, ...]:

      l = ""

      # Scan all the pixels in that line
      for pixel in line:

        # Encode 1 vertical pixel
        l += "##" if pixel else "  "

      aa_lines.append(l)

  # Try to fit the lines within the number of colums by trimming them
  # left and right
  if cols and max_trim_to_fit_cols:
    nbcols = len(aa_lines[0])

    if cols < nbcols <= cols + max_trim_to_fit_cols:
      ltrim = (nbcols - cols) // 2
      aa_lines = [l[ltrim : cols + ltrim] for l in aa_lines]

  # Encoding the final ASCII art sequence
  if use_unicode:
    s = "\n".join([ansi_white_on_black + l + ansi_reset for l in aa_lines])

  else:
    s = "\n".join([re.sub("[# ]", " ",
			re.sub("(#+)", ansi_black_on_white + "\\1",
			re.sub("( +)", ansi_white_on_black + "\\1", l))) + \
			ansi_reset for l in aa_lines])

  return s



### Main routine
if __name__ == "__main__":

  padded = lambda s: ("{:" + str(cfgfile_chars_per_column) + "}").format(s)

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
	help = 'PNG image file to save the QR code in. Use "-" to render the '
		'QR code in the console in ASCII. Default: {}'.
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
  qrdata = "otpauth://totp/{}?secret={}".format(account, b32secret)

  # If we render the QR code directly in the terminal, generate it with a 1x1
  # block size, render it and print it - first in plain (but huge) plain ASCII,
  # then in more compact (but not necessarily well-rendered) ASCII with unicode
  # characters, so that at least one of them is shown properly.
  # If unicode isn't used, each QR code pixel is composed of 2 spaces, so we can
  # bend the rules a bit and shrink the rendering one character left and right
  # to fit a very common 33x33 QR code into an equally-common 80-column display.
  if args.output == "-":
    cols = os.get_terminal_size().columns
    print()
    for uu in (False, True):
      print(generate_bw_ascii_art(qrcode.make(qrdata, box_size = 1),
					cols = cols,
					max_trim_to_fit_cols = 0 if uu else 2,
					use_unicode = uu), end = "\n\n")

  # If we save the QR code into a file, generate it with the default block size
  # and save it
  else:
    img = qrcode.make(qrdata)

    try:
      img.save(args.output)

    except Exception as e:
      print("Error saving QR code image: {}".format(e))
      exit(-1)

    print("Saved PNG image of QR code into {}".format(args.output))

  # Prompt for the OATH password
  password = getpass("OATH password (leave blank for none): ")

  # Ask whether the secret should be saved (needed for PAM authentication,
  # forbidden to get hashes
  print()
  print("Save the secret? Hint: the secret must be saved to use the account " \
	"for PAM authentication but must not be saved to use it to get " \
	"hashes) [Y/N]? ", end = "")

  if input().upper() == "N":
    secret = None

  # Ask confirmation to save this new user account configuration into the
  # configuration file
  print()
  print("Save account {} for user {} into {} {}[Y/N]? ".
	format(account, args.user, args.cfgfile,
		"WITHOUT SECRET " if secret is None else ""), end = "")

  if input().upper() != "Y":
    print()
    print("Aborted")
    exit(0)

  # If the configuration file doesn't exist, ask if we should create it
  if not os.path.exists(args.cfgfile):
    print()
    print("{} doesn't exist. Create it? [Y/N] ".format(args.cfgfile), end = "")

    if input().upper() == "N":
      print()
      print("Aborted")
      exit(0)

    # Create an empty configuration file
    try:
      with open(args.cfgfile, "w") as f:
        print(padded("# Username") + padded("OATH account") + \
		padded("OATH password") + padded("OATH secret"), file = f)

    except Exception as e:
      print()
      print("Error creating configuration file {}: {}".format(args.cfgfile, e))
      exit(-1)

  print()

  # Read in the configuration file
  try:
    with open(args.cfgfile, "r") as f:
      lines = f.read().splitlines()

  except Exception as e:
    print("Error reading configuration file {}: {}".format(args.cfgfile, e))
    exit(-1)

  # Prune any existing configuration lines that concern this user
  lines = [l for l in lines if not l.lstrip().startswith(args.user)]

  # Add the new configuration line
  hexsecret = "-" if secret is None else \
		"".join([format(v, "02x") for v in secret])
  lines.append(padded(args.user) + padded(account) + \
		padded(password if password else "-") + padded(hexsecret))

  # Save the modified configuration back into the configuration file
  try:
    with open(args.cfgfile, "w") as f:
      for l in lines:
        print(l, file = f)

  except Exception as e:
    print("Error writing configuration file {}: {}".format(args.cfgfile, e))
    exit(-1)

  # All done
  print("Done")
  print()

  exit(0)
