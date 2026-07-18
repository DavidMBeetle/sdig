 Secure version of the unix dig utility wrote in python. Uses DNS over TLS (DoT) using TLS 1.3. Full integrated proxy support. 

 This script is an equivalent to the unix utility dig. It has proxy support, but only for socks5 proxies.

 This script uses TLS 1.3 at the minimum, and will entirely refuse to downgrade. If a DNS tries to downgrade, it will drop it and then move to secondary server or another provider

 This will alow you to hide exactly what ur DNS searching up from your ISP. Keep in mind they can still see you're connecting to a DNS server.

 Additionally the original connection is not encrypted, it makes the TLS handshake after direct connection.

 All of it, obviously, runs on TCP instead of UDP.

 I hope this script is useful to you guys.
