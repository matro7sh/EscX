# EscX 

The purpose of this tool is to analyze certificates that have been recovered through certipy to quickly see if they are vulnerable to various escX vulnerabilities.

# requirements 

Dump Certificate from certipy using the following command 

`certipy find -u 'jenaye'@'demo.lan' -p 'Gang!' -dc-ip 172.30.0.26` 

>for v3 of certipy use `certipy find -dc-ip '172.30.0.26' -scheme ldap 'demo.lan'/'jenaye':'Gang!'@'172.30.0.26' -debug -bloodhound`

# Usage


`python escx.py <jsonFile> esc1 esc4 -u <user> --vulnerable`
