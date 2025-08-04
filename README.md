# nse-http-pna-detect
Detects if the server responds with Access-Control-Allow-Private-Network in response to a PNA preflight request.

This script sends an HTTP OPTIONS request with the Access-Control-Request-Private-Network header
to test for Private Network Access (PNA) misconfigurations. If the response contains the
Access-Control-Allow-Private-Network header, the target may be vulnerable.

Additionally, it prints the Server header and the HTML title of the response.

Usage:

```
nmap --script http-pna-detect -p80,443 <target>
```

This can be run on your internal networks or localhost as : 
```
nmap -Pn -n --open  --script http-pna-detect.nse -sV 127.0.0.1
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-01 01:00 UTC
Nmap scan report for 127.0.0.1
Host is up (0.0069s latency).
Not shown: 997 filtered ports, 1 closed port
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.7 (protocol 2.0)
80/tcp open  http    nginx
| http-pna-detect: VULNERABLE: Access-Control-Allow-Private-Network: true
| Server: nginx
| Origin: http://example.com
|_Title: Not found
```
