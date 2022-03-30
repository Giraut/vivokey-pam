#!/usr/bin/python3
"""PAM module to do user authentication using a Vivokey smartcard and the
Vivokey OTP applet.

This module is meant to be called by the pam_exec.so module to provide an
optional or a second authentication factor in the PAM stack. However, it may
also be called manually as a standalone utility to troubleshoot a problem or
validate whether a user's OTP setup is correct.

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

If the reader isn't recognized, use -r <name> or reader=<name> to specifiy the
name matching the reader. The reader's name is passed to vkman.

If the vkman executable isn't located in /usr/bin/vkman or the configuration
file isn't located in /etc/users.vivokey, use -v <path> / vkman=<path> or
-c <path> / cfgfile=<path> to override the default locations for those files.

When using vivokey_pam.py as a standalone utility, you may use -u <user> or
user=<user> to specify another user. By default, the current username is used.
"""

### Modules
import re
import os
import sys
import pyotp
from time import time, sleep
from base64 import b32encode
from subprocess import Popen, PIPE



### Parameters
default_reader = "0"
default_vkman = "/usr/bin/vkman"
default_wait = 2 #s
default_cfgfile = "/etc/users.vivokey"



### Classes
class oathcfg:
  acct = None
  pwd = None
  secret = None



### Common routines
def parse_args(argv, user):
  """Parse the command line arguments
  Return (errmsg, reader, vkman, cfgfile, wait, user, authunknown), with
  errmsg being None if the arguments were parsed successfully
  """

  reader = default_reader
  vkman = default_vkman
  wait = default_wait
  cfgfile = default_cfgfile
  authunknown = False

  next_arg_is_reader = False
  next_arg_is_vkman = False
  next_arg_is_wait = False
  next_arg_is_cfgfile = False
  next_arg_is_user = False

  for arg in argv[1:]:

    if arg in ("-h", "--help"):
      return ("\n".join([
	"",
	"Usage: {}".format(argv[0]),
	"",
	"       -r <reader> or	Name of the NFC reader to talk to the Vivokey",
	"       reader=<reader>	Default {}".format(default_reader),
	"",
	"       -v <path> or	Path to the vkman utility",
	"       vkman=<path>	Default {}".format(default_vkman),
	"",
	"       -c <path> or	Path to the configuration file",
	"       cfgfile=<path>	Default {}".format(default_cfgfile),
	"",
	"       -w <wait> or	Delay (s) to wait for a read",
	"       waitr=<wait>	Default {}".format(default_wait),
	"",
	"       -u <user> or	Username to override the PAM_USER environment",
	"       user=<user>	variable",
	"",
	"       -au		Authenticate users who are not listed in the",
	"			configuration file",
	"			Default: deny authentication to unknown users",
	"",
	"       -h or --help	This help",
	""]),) + (None,) * 6

    elif arg == "-r":
      next_arg_is_reader = True

    elif arg == "-v":
      next_arg_is_vkman = True

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

    elif next_arg_is_vkman:
      vkman = arg
      next_arg_is_vkman = False

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

    elif arg[:6] == "vkman=":
      vkman = arg[6:]

    elif arg[:8] == "cfgfile=":
      cfgfile = arg[8:]

    elif arg[:5] == "wait=":
      wait = arg[5:]

    elif arg[:5] == "user=":
      user = arg[5:]

    else:
      return ("Error: unknown argument: {}".format(arg),) + (None,) * 6

  if next_arg_is_reader:
    return ("Error: missing -r value",) + (None,) * 6

  if next_arg_is_vkman:
    return ("Error: missing -v value",) + (None,) * 6

  if next_arg_is_cfgfile:
    return ("Error: missing -c value",) + (None,) * 6

  if next_arg_is_wait:
    return ("Error: missing -w value",) + (None,) * 6

  if next_arg_is_user:
    return ("Error: missing -u value",) + (None,) * 6

  # Fail if we don't have a reader name
  if not reader:
    return ("Error: no reader name",) + (None,) * 6

  # Fail if we don't have a path to the vkman utility
  if not vkman:
    return ("Error: no path to the vkman utility",) + (None,) * 6

  # Fail if we don't have a path to the configuration file
  if not cfgfile:
    return ("Error: no path to the configuration file",) + (None,) * 6

  # Fail if we don't have a wait time
  if not wait:
    return ("Error: no wait time",) + (None,) * 6

  # Fail if the wait time is invalid
  try:
    wait = int(wait)
  except:
    return ("Error: invalid wait time {}".format(wait),) + (None,) * 6

  # Fail if we don't have a user to authenticate
  if not user:
    return ("Error: no username to authenticate",) + (None,) * 6

  # Check that the username is valid
  if not all([" " <= c <= "~" for c in user]):
    return ("Error: invalid user= value: {}".format(user),) + (None,) * 6

  return (None, reader, vkman, cfgfile, wait, user, authunknown)



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

  # Get the PAM_USER environment variable. If we don't have it, we're
  # not being called by pam_exec.so, so get the USER environment variable
  # instead
  user = os.environ["PAM_USER"] if "PAM_USER" in os.environ else \
		os.environ["USER"] if "USER" in os.environ else None

  # Parse the command line arguments
  errmsg, reader, vkman, cfgfile, wait, user, authunknown = parse_args(sys.argv,
									 user)
  if errmsg is not None:
    print(errmsg)
    return -1

  # Parse the configuration file
  errmsg, cfg = parse_cfgfile(cfgfile)
  if errmsg is not None:
    print(errmsg)
    return -1

  # If the user isn't registered in the configuration file, deny them
  # authentication by default, unless we were asked to authenticated them
  if user not in cfg:
    print("AUTHOK" if authunknown else "NOAUTH: {} is unknown".format(user))
    return 0 if authunknown else 1

  # If the user doesn't have an account or a secret, we can't authenticated them
  if not cfg[user].acct:
    print("NOAUTH: {} has no OATH account".format(user))
    return 1

  if not cfg[user].secret:
    print("NOAUTH: {} has no OATH secret".format(user))
    return 1

  # If the user's secret is invalid or otherwise non-convertible into a base32
  # string, we can't authenticate them
  try:
    b32secret = b32encode(bytes.fromhex(cfg[user].secret))

  except:
    print("NOAUTH: {} has an invalid OATH secret".format(user))
    return 1

  # Create a TOTP instance
  totp = pyotp.TOTP(b32secret)

  # Repeat until the waiting time to get a read is elapsed
  start_tstamp = time()
  while time() - start_tstamp < wait:

    # Try to get a code from the user's token
    cmd = [vkman, "-r", reader, "oath", "accounts", "code"]
    cmd += ["-p", cfg[user].pwd] if cfg[user].pwd else []
    cmd += ["-s", cfg[user].acct]
    try:
      p = Popen(cmd, stdout = PIPE, stderr = PIPE)
      stdout_lines = p.communicate()[0].decode("utf8").splitlines()
      stderr_lines = p.communicate()[1].decode("utf8").splitlines()
      errcode = p.returncode

    # Did we get an error trying to run the command?
    except Exception as e:
      print("NOAUTH: error running vkman: {}".format(e))
      return 1

    # Did the command return an error code?
    if errcode:

      # If the command couldn't connect, keep trying
      if "Failed to connect" in stderr_lines[0]:
        sleep(.1)
        continue

      # Any other error, we abort
      print("NOAUTH: error running vkman command {}".
		format("" if not stderr_lines else ": " + stderr_lines[0]))
      return 1

    # Did the command fail to return anything on stdout?
    if not stdout_lines:
      print("NOAUTH: nothing returned by vkman")
      return 1

    # Did the command return a malformed OTP code?
    code = stdout_lines[0]
    if not re.match("^[0-9]{6,10}$", code):
      print("NOAUTH: vkman returned malformed TOTP code {}".
		format(code))
      return 1

    # Verify the code
    if totp.verify(code):
      print("AUTHOK")
      return 0

    else:
      print("NOAUTH: invalid TOTP code")
      return 0

  # If we arrive here, we waited too long for a read
  print("NOAUTH: timeout")
  return 1



### Jump to the main routine - For use when run from pam_exec.so or on the
### command line
if __name__ == "__main__":
  exit(main())
