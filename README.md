# DNS Tunneling C2 Server
This project is a Command and Control server written in C, designed to establish communication through the DNS protocol. (DNS Tunneling)

Instead of traditional TCP/IP methods, the server uses raw socket manipulation to intercept what appears to be normal DNS traffic.
This way, it can bypass firewalls and network blocking, "Smuggeling" data in and out.

### C2 Implementation
The Listener (attacker) listens for DNS queries from the victim.
Sender (victim) sends queries periodically to check for instructions, when an instruction is detected,
the sender runs the code and makes another query with the data.

> This project is being worked on and is not a finished product.
