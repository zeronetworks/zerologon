# Zerologon test for SMB & RPC
A python script based on [SecuraBV script](https://github.com/SecuraBV/CVE-2020-1472). 

Demonstrates that CVE-2020-1472 can be done via RPC/SMB, and not only over RPC/TCP.

Additionaly, there is a random byte in the final client challange & client credential - to test against trivial IDS signatures.
The RPC/SMB scan runs by default. Depending on the target server, some may require a valid authenticated user to get permission to the netlogon pipe.

# Execution
```python
zerologon_test.py [-h] [-u] [-p] [-t] dc_name dc_ip

Perform zerologon test over RPC/TCP or RPC/SMB

positional arguments:
  dc_name               NetBIOS name of the domain controller
  dc_ip                 ip address of the domain controller

optional arguments:
  -h, --help, /?, /h, /help
                        show this help message and exit
  -u , --user           authenticated domain user,may be required for SMB
  -p , --pass           authenticated domain user's password, may be required for SMB
  -t , --type           rpc or smb scan. choices: [smb, rpc], (default: 'smb').

```
