#!/usr/bin/python3
"""PAM module to do user authentication using a Vivokey smartcard and the
Vivokey OTP applet.

This module is meant to be called by the pam_exec.so module to provide an
optional or a second authentication factor in the PAM stack.

However, it may also be used as a standalone utility: with the same arguments
as used in the PAM setup, it will behave exactly as it would when called by
pam_exec, and therefore may be used to troubleshoot a problem or validate
whether a user's OTP setup is correct.

When used with the "gethash" command, the utility doesn't perform any validation
but rather asks the token to calculate a hash from a user-supplied challenge.
The challenge is read on stdin has a 8- to 64-byte ASCII-encoded hex number,
and the hash is returned as a 20-, 32- or 64-byte ASCII-encoded hex number on
stdout.

PAM configuration
-----------------

For example, if your system uses libpam-runtime (i.e. you have a pam-auth-update
utility and config files /usr/share/pam-configs), you can configure Vivokey OTP
authentication as an alternative login method to the traditional Unix password
by adding a /usr/share/pam-config/vivokey-pam.config file with the following
content:

---8<---8<---8<---
Name: Vivokey OTP authentication (1FA: password or Vivokey)
Default: no
Priority: 128
Auth-Type: Primary
Auth:
    [success=end default=ignore]    pam_exec.so quiet /usr/bin/vivokey_pam.py
Auth-Initial:
    [success=end default=ignore]    pam_exec.so quiet /usr/bin/vivokey_pam.py
---8<---8<---8<---

then running pam-auth-update and enabling Vivokey authentication.

Then for subsequent logins, you can either type your regular password or present
your Vivokey transponder to the reader (within 2 seconds).

Or, for example, if your system's PAM stack must be configured manually and
you want to use Vivokey authentication as a second factor, you could define
the following PAM sequence in /etc/pam.d/common-auth (your exact configuration
files and sequences may vary depending on your particular system):

---8<---8<---8<---
auth  [success=1 default=ignore]  pam_unix.so nullok
auth  requisite                   pam_deny.so
auth  [success=1 default=ignore]  pam_exec.so quiet /usr/bin/vivokey_pam.py -au
auth  requisite                   pam_deny.so
auth  required                    pam_permit.so
---8<---8<---8<---

In this sequence, if the wrong Unix password is entered, the login fails on the
first pam_deny.so.

If the correct Unix password is entered, the first pam_deny.so is skipped,
then the vivokey_pam.py module waits for a successful read for 2 seconds.

If the Vivokey OTP authentication succeeds, the second pam_deny.so is skipped
and the login succeeds. If not, the login fails on the second pam_deny.so.

In this case, note the use of the -au flag: this tells vivokey_pam.py to let
users not listed in the /etc/users.vivokey "through" - instead of denying them
authentication by default. Without -au, users who don't have a Vivokey OTP
setup could not log in anymore. If it should be desirable that all the users
use a Vivokey device to login, all of them should be enrolled in
/etc/users.vivokey and the -au should then be dropped.

If the wait is not long enough to present the Vivokey device to the reader, use
-w <wait> or wait=<wait> as argument to vivokey_py to orverride the default
2-second wait.

If the reader isn't recognized, use -r <name> or reader=<name> to specifiy a
name matching the reader.

When using vivokey_pam.py as a standalone utility, you may use -u <user> or
user=<user> to specify another user. By default, the current username is used.
"""

### Modules
import re
import os
import sys
import hmac
import hashlib
from random import randint
from time import time, sleep
import smartcard.scard as sc



### Parameters
default_reader = "0"
default_wait = 2 #s
default_cfgfile = "/etc/users.vivokey"



### Classes
class oathcfg:
  acct = None
  pwd = None
  secret = None



### Classes
class pcsc_oath():
  """Class to get a full SHA hash for a given account from an OATH applet
  running on an ISO14443-4 smartcard using PC/SC
  """

  # Defines
  DEFAULT_OATH_AID = "a0000007470061fc54d5"	# Vivokey OTP applet
  DEFAULT_PERIOD = 30 #s

  INS_SELECT = 0xa4
  P1_SELECT = 0x04
  P2_SELECT = 0x00

  INS_VALIDATE = 0xa3

  INS_CALCULATE = 0xa2
  P2_CALCULATE_FULL = 0x00

  INS_SEND_REMAINING = 0xa5

  SW1_OK = 0x90
  SW2_OK = 0x00

  SW1_AUTH_ERROR = 0x69
  SW2_AUTH_REQUIRED = 0x82
  SW2_AUTH_FAILED = 0x84

  SW1_FAILED = 0x69
  SW2_NO_SUCH_OBJECT = 0x84

  SW1_WRONG_SYNTAX = 0x6a
  SW2_WRONG_SYNTAX = 0x80

  SW1_MORE_DATA = 0x61

  NAME_TAG = 0x71
  CHALLENGE_TAG = 0x74
  RESPONSE_TAG = 0x75
  FULL_TAG = 0x75



  def __init__(self, oath_aid = DEFAULT_OATH_AID, period = DEFAULT_PERIOD):
    """__init__ method
    """

    self.readers_regex = "^.*$"
    self.oath_aid = list(bytes.fromhex(oath_aid))
    self.period = period

    self.all_readers = []
    self.hcontext = None

    self.reader = None

    self.oath_pwd = None



  def set_readers_regex(self, reader):
    """Construct the readers regex from the string supplied by the user and
    force the reader to be updated
    """

    self.readers_regex = "^.*{}.*$".format(reader)
    self.all_readers = []



  def set_oath_pwd(self, oath_pwd):
    """Set the OATH password to use at the next get_hash()
    """

    self.oath_pwd = oath_pwd



  def _send_apdu(self, hcard, dwActiveProtocol, apdu):
    """Send an APDU command, get and collate the response.
    Returns (None, None, r, response) if no error,
    (errmsg, err_critical_flag, None, None) otherwise.
    """

    try:
      r, response = sc.SCardTransmit(hcard, dwActiveProtocol, apdu)

    except Exception as e:
      return (repr(e), True, None, None)

    if len(response) < 2:
      return ("APDU response too short", False, None, None)

    while response[-2] == self.SW1_MORE_DATA:

      try:
        r, chunk = sc.SCardTransmit(hcard, dwActiveProtocol,
					[0, self.INS_SEND_REMAINING, 0, 0])

      except Exception as e:
        return (repr(e), True, None, None)

      if len(chunk) < 2:
        return ("APDU response too short", False, None, None)

      response = response[:-2] + chunk

    return (None, None, r, response)



  def _tlv(self, tag, data):
    """Encapsulate data in a TLV structure
    """

    l = len(data)

    return [tag] + ([l] if l < 0xff else [0xff, l >> 8, l & 0xff]) + list(data)



  def _untlv(self, data, do_dict = False):
    """Extract TLV values into a list of [tag, value], or a tag_keyed dictionary
    if do_dict is asserted.
    If raw is asserted, the lengths of the TLVs are checked and the values are
    returned as-is. If not, the values too are checked and processed depending
    on certain tag types.
    Returns (None, list or dict) if no error, (errmsg, None) otherwise.
    """

    ld = {} if do_dict else []
    errmsg = None

    while data and not errmsg:

      # Check the overall length of the TLV
      if len(data) < 2 or (data[1] == 0xff and len(data) < 4):
        errmsg = "TLV too short in APDU response"
        break

      # Get the tag
      t = data[0]

      # Get the length of the TLV and remove the tag and length from the data
      l = data[1]

      if l == 0xff:
        l = (data[2] << 8) | data[3]
        data = data[4:]

      else:
        data = data[2:]

      # Get the value and check that it has the advertised length
      v = bytes(data[:l])

      if len(v) < l:
        errmsg = "TLV value too short in APDU response"
        break

      # Remove the value from the data
      data = data[l:]

      # Add the tag and value to our list or dictionary
      if do_dict:
        ld[t] = v

      else:
        ld.append([t, v])

    return (errmsg, None) if errmsg else (None, ld)



  def get_hash(self, acct, challenge):
    """Try to establish communication with the smartcard, select the OATH AID,
    validate the OATH password if needed, then ask the token to calculate the
    full hash for the account acct.
    Returns (None, None, token hash) if no error, (errmsg, err_critical_flag,
    None) otherwise.
    """

    hcard = None

    errmsg = None
    errcritical = True
    thash = None

    disconnect_card = False
    release_ctx = False

    while True:

      # If we arrive here needing to either disconnect the card or release the
      # PC/SC resource manager context, do so and break the loop
      if disconnect_card or release_ctx:

        if disconnect_card:
          try:
            sc.SCardDisconnect(hcard, sc.SCARD_UNPOWER_CARD)
          except:
            pass

        if release_ctx:
          try:
            sc.SCardReleaseContext(self.hcontext)
          except:
            pass
          del(self.hcontext)
          self.hcontext = None

        break

      # Get the PC/SC resource manager context
      if not self.hcontext:
        try:
          r, self.hcontext = sc.SCardEstablishContext(sc.SCARD_SCOPE_USER)

        except Exception as e:
          errmsg = "error getting PC/SC resource manager context: {}".format(e)
          break

        if r != sc.SCARD_S_SUCCESS:
          release_ctx = True
          errmsg = "cannot establish PC/SC resource manager context"
          continue

      # Get the current list of readers
      try:
        _, all_readers_new = sc.SCardListReaders(self.hcontext, [])

      except Exception as e:
        release_ctx = True
        errmsg = "error getting the list of readers: {}".format(e)
        continue

      if not all_readers_new:
        self.all_readers = []
        errmsg = "no readers"
        break

      # Get the first reader that matches the regex
      if all_readers_new != self.all_readers:
        self.all_readers = all_readers_new

        for r in self.all_readers:
          if re.match(self.readers_regex, r, re.I):
            self.reader = r
            break

        else:
          self.reader = None

      # Do we have a reader to read from?
      if self.reader is None:
        errmsg = "no matching readers"
        break

      # Connect to the smartcard
      try:
        r, hcard, dwActiveProtocol = sc.SCardConnect(self.hcontext,
							self.reader,
							sc.SCARD_SHARE_SHARED,
							sc.SCARD_PROTOCOL_T0 | \
							sc.SCARD_PROTOCOL_T1)

      except Exception as e:
        release_ctx = True
        errmsg = "error connecting to the smartcard: {}".format(e)
        continue

      if r != sc.SCARD_S_SUCCESS:
        errmsg = "error connecting to the smartcard"
        errcritical = False
        break

      # Whatever happens next, try to disconnect the card before returning
      disconnect_card = True

      # Select the OATH AID
      errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0, self.INS_SELECT, self.P1_SELECT,
					self.P2_SELECT,
					len(self.oath_aid)] + self.oath_aid)

      if errmsg or r != sc.SCARD_S_SUCCESS:
        release_ctx = True
        errmsg = "error transmitting OATH AID selection command{}".format(
			": {}".format(errmsg) if errmsg else "")
        errcritical = ec
        continue

      # Did we get a response error?
      if response[-2:] != [self.SW1_OK, self.SW2_OK]:
        errmsg = "error {:02X}{:02X} from OATH AID selection command".format(
			response[-2], response[-1])
        errcritical = False
        continue

      errmsg, tlvs = self._untlv(response[:-2], do_dict = True)
      if errmsg:
        continue

      # Did we get a name tag?
      if self.NAME_TAG not in tlvs:
        errmsg = "Malformed APDU response: missing name tag in " \
			"AID selection command response"
        continue

      salt = tlvs[self.NAME_TAG]
      chal = tlvs.get(self.CHALLENGE_TAG, None)

      # Do we have a password to validate?
      if self.oath_pwd:

        # If the token doesn't have a key, throw an error
        if chal is None:
          errmsg = "password set but no password required"
          continue

        # Calculate our response to the token's challenge
        key = hashlib.pbkdf2_hmac("sha1", self.oath_pwd.encode("ascii"),
					salt, 1000, 16)
        response = hmac.new(key, chal, "sha1").digest()
        data_tlv = self._tlv(self.RESPONSE_TAG, response)

        # Calculate our own challenge to the token
        chal = [randint(0, 255) for _ in range(8)]
        data_tlv += self._tlv(self.CHALLENGE_TAG, chal)

        # Validate the password
        errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0, self.INS_VALIDATE, 0, 0,
					len(data_tlv)] + data_tlv)

        if errmsg or r != sc.SCARD_S_SUCCESS:
          release_ctx = True
          errmsg = "error transmitting VALIDATE command{}".format(
			": {}".format(errmsg) if errmsg else "")
          errcritical = ec
          continue

        # Did we get a response error?
        if response[-2:] != [self.SW1_OK, self.SW2_OK]:

          # Did the authentication fail?
          if response[-2:] == [self.SW1_AUTH_ERROR, self.SW2_AUTH_FAILED] or \
		response[-2:] == [self.SW1_WRONG_SYNTAX, self.SW2_WRONG_SYNTAX]:
            errmsg = "authentication failed"

          else:
            errmsg = "error {:02X}{:02X} from VALIDATE selection command".\
			format(response[-2], response[-1])
          continue

        errmsg, tlvs = self._untlv(response[:-2], do_dict = True)
        if errmsg:
          continue

        response = tlvs.get(self.RESPONSE_TAG, None)

        # Did the token send a response to our challenge?
        if response is None:
          errmsg = "Malformed APDU response: missing response from "\
			"VALIDATE command response"
          continue

        # Verify the response
        verification = hmac.new(key, bytes(chal), "sha1").digest()
        if not hmac.compare_digest(response, verification):
          errmsg = "response from VALIDATE command does not match verification"
          continue

      else:

        # If the token has a key, throw an error
        if chal is not None:
          errmsg = "password required"
          continue

      # Request the full hash for the given account name
      challenge_tlv = self._tlv(self.CHALLENGE_TAG, challenge)
      acct_tlv = self._tlv(self.NAME_TAG, (acct).encode("ascii"))
      errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0, self.INS_CALCULATE, 0,
					self.P2_CALCULATE_FULL,
					len(acct_tlv) + len(challenge_tlv)] + \
					acct_tlv + challenge_tlv)

      if errmsg or r != sc.SCARD_S_SUCCESS:
        release_ctx = True
        errmsg = "error transmitting CALCULATE command{}".format(
			": {}".format(errmsg) if errmsg else "")
        errcritical = ec
        continue

      # Did we get a response error?
      if response[-2:] != [self.SW1_OK, self.SW2_OK]:

        # Is authentication required?
        if response[-2:] == [self.SW1_AUTH_ERROR, self.SW2_AUTH_REQUIRED]:
          errmsg = "authentication required"

        elif response[-2:] == [self.SW1_FAILED, self.SW2_NO_SUCH_OBJECT]:
          errmsg = "account not found"

        else:
          errmsg = "error {:02X}{:02X} from CALCULATE command".format(
			response[-2], response[-1])
          errcritical = False

        continue

      # Decode the response, which should be a full code response TLV
      errmsg, tlvs = self._untlv(response[:-2], do_dict = False)
      if errmsg:
        continue

      if len(tlvs) != 1:
        errmsg = "Malformed APDU response: expected 1 TLV, got {}".\
			format(len(tlvs_st))
        break

      if tlvs[0][0] != self.FULL_TAG:
        errmsg = "Malformed APDU response: unexpected tag"
        break

      thash = tlvs[0][1][1:]

      if len(thash) not in (20, 32, 64):
        errmsg = "invalid hash size {}".format(len(thash))
        break

      # All done
      break

    return (errmsg, errcritical, thash)



### routines
def parse_args(argv, user):
  """Parse the command line arguments
  Return (errmsg, reader, cfgfile, wait, user, authunknown), with
  errmsg being None if the arguments were parsed successfully
  """

  noargs = (None,) * 6

  reader = default_reader
  wait = default_wait
  cfgfile = default_cfgfile
  authunknown = False
  gethash = False

  next_arg_is_reader = False
  next_arg_is_wait = False
  next_arg_is_cfgfile = False
  next_arg_is_user = False

  for arg in argv[1:]:

    if arg in ("-h", "--help"):
      return ("\n".join([
	"",
	"Usage: {}".format(argv[0]),
	"",
	"       -r <reader> or   Name of the NFC reader to talk to the Vivokey",
	"       reader=<reader>  Default {}".format(default_reader),
	"",
	"       -c <path> or     Path to the configuration file",
	"       cfgfile=<path>   Default {}".format(default_cfgfile),
	"",
	"       -w <wait> or     Delay (s) to wait for a read",
	"       waitr=<wait>     Default {}".format(default_wait),
	"",
	"       -u <user> or     Username to override the PAM_USER environment",
	"       user=<user>      variable",
	"",
	"       -au              Authenticate users who are not listed in the",
	"                        configuration file",
	"                        Default: deny authentication to unknown users",
	"",
	"       gethash          Read an ASCII-encoded hex value or a UUID on",
	"                        stdin and ask the token to calculate a hash",
	"                        using the user's registered account.",
	"                        Return the hash as an ASCII-encoded hex value",
	"                        on stdout.",
	"",
	"                        This function is not PAM-related. It is used",
	"                        to test the token's hashing algorithm, and",
	"                        may also be used with other utilities like",
	"                        cryptsetup to use hashes as passphrases.",
	"",
	"       -h or --help     This help",
	""]),) + noargs

    elif arg == "-r":
      next_arg_is_reader = True

    elif arg == "-c":
      next_arg_is_cfgfile = True

    elif arg == "-w":
      next_arg_is_wait = True

    elif arg == "-u":
      next_arg_is_user = True

    elif arg == "-au":
      authunknown = True

    elif next_arg_is_reader:
      reader = arg
      next_arg_is_reader = False

    elif next_arg_is_cfgfile:
      cfgfile = arg
      next_arg_is_cfgfile = False

    elif next_arg_is_wait:
      wait = arg
      next_arg_is_wait = False

    elif next_arg_is_user:
      user = arg
      next_arg_is_user = False

    elif arg[:7] == "reader=":
      reader = arg[7:]

    elif arg[:8] == "cfgfile=":
      cfgfile = arg[8:]

    elif arg[:5] == "wait=":
      wait = arg[5:]

    elif arg[:5] == "user=":
      user = arg[5:]

    elif arg == "gethash":
      gethash = True

    else:
      return ("Error: unknown argument: {}".format(arg),) + noargs

  if next_arg_is_reader:
    return ("Error: missing -r value",) + noargs

  if next_arg_is_cfgfile:
    return ("Error: missing -c value",) + noargs

  if next_arg_is_wait:
    return ("Error: missing -w value",) + noargs

  if next_arg_is_user:
    return ("Error: missing -u value",) + noargs

  # Fail if we don't have a reader name
  if not reader:
    return ("Error: no reader name",) + noargs

  # Fail if we don't have a path to the configuration file
  if not cfgfile:
    return ("Error: no path to the configuration file",) + noargs

  # Fail if we don't have a wait time
  if not wait:
    return ("Error: no wait time",) + noargs

  # Fail if the wait time is invalid
  try:
    wait = float(wait)
  except:
    return ("Error: invalid wait time {}".format(wait),) + noargs

  # Fail if we don't have a user to authenticate
  if not user:
    return ("Error: no username to authenticate",) + noargs

  # Check that the username is valid
  if not all([" " <= c <= "~" for c in user]):
    return ("Error: invalid user {}".format(user),) + noargs

  # -au isn't valid with gethash are mutually exclusive
  if gethash and authunknown:
    return ("-au not valid with gethash",) + noargs

  return (None, reader, cfgfile, wait, user, authunknown, gethash)



def parse_cfgfile(cfgfile):
  """Parse the configuration file
  Return (errmsg, cfg), with errmsg being None if the configuration file was
  parsed successfully

  The configuration file has the following format
  # Optional comment line
  username1  oath_account  oath_password  oath_secret_in_hex  # Optional comment
  username2  oath_account  oath_password  oath_secret_in_hex  # Optional comment

  If any of the username, oath_account, oath_password, oath_secret_in_hex fields
  is set to "-", the value is considered omitted.

  If a line has fewer than 4 fields, the missing fields on the right are
  comsidered omitted.

  If a user is not mentioned in the configuration file, they're not considered
  enrolled. However, if their name is the first field on a line, they must have
  an account and secret associated or their authorization will be denied out
  of hand. This is useful if you want to disable a unix account entirely, due
  to a compromised secret for example.

  Example:

  # Username  OATH account         OATH password  OATH secret
  alice       alice@localhost      s00p3rs3cr3t   c440efbaba366a1b5e00 #Active
  bob         bob@server.acme.com  -              5af022b3fa747e125c1d #Active
  charlie     -                    -              -                    #Disabled
  dave                                                                 #Disabled
  """

  cfg = {}

  # Read the file's content
  try:
    with open(cfgfile, "r") as f:
      lines = f.read().splitlines()

  except Exception as e:
    return ("Error reading configuration file {}: {}".format(cfgfile, e), None)

  # Process the lines
  for l in lines:

    # Remove comments
    l = re.sub("#.*$", "", l)

    # Split the fields
    user, acct, pwd, secret = (l + " - - - -").split()[:4]

    # A valid user configuration line has at least a username
    if user == "-":
      continue

    # Record that user's configuration line
    cfg[user] = oathcfg()
    cfg[user].acct = acct if acct != "-" else None
    cfg[user].pwd = pwd if pwd != "-" else None
    cfg[user].secret = secret if secret != "-" else None

  return (None, cfg)



### Main routine for use when run from pam_exec.so or on the command line
def main():
  """Main routine
  """

  autherr = False
  errmsg = None

  # Get the PAM_USER environment variable. If we don't have it, we're
  # not being called by pam_exec.so, so get the USER environment variable
  # instead
  user = os.environ["PAM_USER"] if "PAM_USER" in os.environ else \
		os.environ["USER"] if "USER" in os.environ else None

  # Parse the command line arguments
  errmsg, reader, cfgfile, wait, user, authunknown, gethash = \
		parse_args(sys.argv, user)

  # Parse the configuration file
  if errmsg is None:
    errmsg, cfg = parse_cfgfile(cfgfile)

  # If we do the gethash command, get the challenge as space or hyphen-separated
  # ASCII-encoded 8-bit hex values. Otherwise, generate a challenge ourselves.
  if errmsg is None:

    if gethash:
      try:
        instr = input()

        try:
          challenge = bytes.fromhex(instr.replace("-", " "))

          if not challenge:
            errmsg = "no challenge"

          # If the challenge is too short, pad it with zeros
          elif len(challenge) < 8:
            challenge = (b"\x00" * 8 + challenge)[-8:]

          elif len(challenge) > 64:
            errmsg = "challenge too long - maximum 64 bytes"

        except:
          errmsg = "invalid hex value: {}".format(instr)

      except Exception as e:
        errmsg = "input error: {}".format(e)

    else:
      challenge = bytes([randint(0, 255) for _ in range(8)])

  if errmsg is None:
    autherr = True
    start_tstamp = time()

  while errmsg is None:

    # If the user isn't registered in the configuration file, deny them
    # authentication by default, unless we were asked to authenticated them
    if user not in cfg:
      errmsg = "" if authunknown else "{} is unknown".format(user)
      continue

    # If the user doesn't have an account or a secret, we can't do anything
    if not cfg[user].acct:
      errmsg = "{} has no OATH account".format(user)
      continue

    # Does the user have a secret?
    if cfg[user].secret:

      # If we do the gethash command, refuse to run
      if gethash:
        errmsg = "{} may not have a recorded OATH secret to get hashes".\
			format(user)
        continue

      # If the user's secret is invalid or otherwise non-convertible into bytes,
      # we can't authenticate them
      try:
        key = bytes.fromhex(cfg[user].secret)

      except:
        errmsg = "{} has an invalid OATH secret".format(user)
        continue

    # If the user doesn't have a secret, we can't authenticate them
    elif not gethash:
      errmsg = "{} has no OATH secret".format(user)
      continue

    # Create a PC/SC oath code reader instance
    po = pcsc_oath()

    # Set the PC/SC readers regex and the OATH password
    po.set_readers_regex(reader)
    po.set_oath_pwd(cfg[user].pwd)

    # Try reading until the waiting time to get a read is elapsed
    while errmsg is None and time() - start_tstamp < wait:

      em, errcritical, thash = po.get_hash(cfg[user].acct, challenge)

      # Did we get an error mesage?
      if em:

        # Is it a critical error?
        if errcritical:
          errmsg = em

        continue

      # If we do the gethash command, print the hash and stop
      if gethash:
        print("".join([format(b, "02X") for b in thash]), end = "")
        errmsg = ""
        continue

      # Recalculate the hash ourselves
      if len(key) > 64:
        key = hashlib.sha1(key).digest()
      key = key + b"\x00" * (64 - len(key))

      hashlen = len(thash)

      if hashlen == 20:		# The token returned a SHA1 hash
        inner = hashlib.sha1()
        outer = hashlib.sha1()

      elif hashlen == 32:	# The token returned a SHA256 hash
        inner = hashlib.sha256()
        outer = hashlib.sha256()

      elif hashlen == 64:	# The token returned a SHA512 hash
        inner = hashlib.sha512()
        outer = hashlib.sha512()

      inner.update(key.translate(bytes([b ^ 0x36 for b in range(256)])))
      outer.update(key.translate(bytes([b ^ 0x5c for b in range(256)])))

      inner.update(challenge)
      outer.update(inner.digest())
      verification = outer.digest()

      # Check that our hash matches the token's
      if thash == verification:
        errmsg = ""

      else:
        errmsg = "hash mismatch"

      continue

    if errmsg is not None:
      continue

    # If we arrive here, we waited too long for a read
    errmsg = "timeout"

  # If we do the gethash command, print any error message on stderr and stop
  if gethash:
    if errmsg:
      print("Error: " + errmsg, file = sys.stderr)

    return -1 if errmsg else 0

  # If we arrive here with a failed authentication, continue waiting until the
  # end of the wait time to throttle repeated login attempts and avoid giving
  # clues to the cause of the failed authentication
  if autherr and errmsg:
    sleep(max(0, wait - time() + start_tstamp))

  # Output the error message
  print((("NOAUTH: " if autherr else "") + errmsg) if errmsg else "AUTHOK")

  return 0 if not errmsg else 1 if autherr else -1



### Jump to the main routine - For use when run from pam_exec.so or on the
### command line
if __name__ == "__main__":
  exit(main())
