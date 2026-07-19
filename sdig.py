#importing standard libraries
import argparse
import ssl
import socket #here to add support to other modules
import sys
import time
from pathlib import Path #to enable the finding of the config file.
import tomllib
#import external libraries
import socks
import dns.rdatatype
import dns.query #gives you manual dns querying similar to dns.message as well as network management which is useful.
#we're only importing recieve TCP to skip all the manual TCP tags and decodings.
import dns.message #to create the DNS query before sending

#classes
class Proxy():
    #using object oriented programming to natively handle the processing of the proxy.
    def __init__(self,proxy):
        if ("socks5://" in proxy):
            proxy_type = "socks5"
        else:
            sys.exit("Invalid proxy")
        self.address, self.port = proxy.replace("socks5://", "").split(":") #handling the splitting of port and address in one line.
        #we replace the socks5:// to get rid of the type, since we only need that to ensure it's a valid proxy.
        #It will also interfere if we try to split it along the colon to get port if we leave it there.
        self.port = int(self.port)
    
    def initilialise(self, socket): #using this as a function since we have to reinitiliase the proxy for each time we restart the socket
        #initialises the proxy
        socket.set_proxy(socks.SOCKS5, self.address, self.port)


#functions

#We're building it like this since you need too and DNS querry doesn't have native proxy support.
def make_DNS_Query(Domain_Name, rdQuery_type): #created function to create a DNS_Query for DNS over TCP with TLS
    query_message = dns.message.make_query(Domain_Name, rdtype=rdQuery_type)
    return query_message.to_wire(prepend_length=True)
    
#VERSION variable, change as you go:

sdig_version = "Version 1.1.0"

#parsers
#initialising the parser
parser = argparse.ArgumentParser(prog="sdig", description="A secure DNS look up alternative to the dig terminal utility. Uses DNS over TCP with TLS/SSH (DoT) and interacts with raw and encrypted sockets.", epilog="Happy hunting")

#making arguments
parser.add_argument("-d", "--domain", required=True, help="Required tag, tells the DNS server what domain to ask the DNS server t ofind", type=str, dest="Target_Domain")
parser.add_argument("-t", "--rdtype", default='A', dest="rd_type", help="The data type demanded in the DNS request, example MX server. Invalid responses will lead to an error.", type=str)
parser.add_argument("--proxy", required=False, dest="Proxy", type=str, help="Proxy argument to route your DNS querries through a proxy. Some DNS servers will reject the proxy.")
parser.add_argument("-v", "--version", help=f"Prints the current version, that being {sdig_version}", action="version", version=sdig_version)
parser.add_argument("--timeout", help="How long the program will wait in seconds before giving up on a connection. Default is 30. This is an integer, do not put in values with decimals.", type=int, default=30, required=False, dest="timeout")
parser.add_argument("--verbose", help="Makes the program a lot more expressive in terms of it's actions and tells you what's happening.", action='store_true', dest="verboseStatus")

args = parser.parse_args() #parsing it all

if args.Proxy != None:
    Main_proxy = Proxy(args.Proxy)

###loading toml file

#finding directory:
script_dir = Path(__file__).resolve().parent #finds the folder the script is in
config_path = Path(script_dir / "config.toml")
if (config_path.exists == False):
    sys.exit("Config file not detected, clean shut down. Please ensure the following:")
    print
#using with to automatically close the file immediately after
with open(config_path, "rb") as config_File:
    config = tomllib.load(config_File) #saves the entire toml file after loading it into memory

DNS_Servers = config["DNS_Servers"] #stores the DNS_Servers dictionary in this variable so the rest of everything will work.


#Creating raw socket
Raw_Socket = socks.socksocket()

#renaming variables from arguments, much easier and increased readability. Microscoping performance and memory usage increase is worth it
#readability across contributors is far more important
Target_Domain = args.Target_Domain
Targetted_Data_class = dns.rdatatype.from_text(args.rd_type)

#Preparations for TLS encryption:
TLS_settings = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
TLS_settings.load_default_certs()
TLS_settings.minimum_version = ssl.TLSVersion.TLSv1_3 #forcing TLS v1.3 for absolute security.

#trying to make proxy DNS connections:

DoT_Socket = None #declaring it but not giving it a value yet

TLSConnected = False #to ensure we are connected

for servers in DNS_Servers:
    try:
        Raw_Socket = socks.socksocket() #reinstating socket after each time in case of error, sockets cannot be reused and must be entirely restarted
        if (args.Proxy != None): #reinstating proxy connection on reset socket
            Main_proxy.initilialise(Raw_Socket)
    
        #NOTE: not using try: and except commands because i want to see the error message during development, I'll be using try later on
        Raw_Socket.connect((DNS_Servers[servers]["IP_List"][0], 853)) #port 853 is the port for TLS encrypted DNS connections
        if (args.verboseStatus):
            print("Successfully connected to DNS server")
        print(f"Using {DNS_Servers[servers]["CN"]}")
        DoT_Socket = TLS_settings.wrap_socket(Raw_Socket, server_hostname=DNS_Servers[servers]["CN"])
        TLSConnected = True
        if (args.verboseStatus):
            print("Successfully initialised TLS 1.3")
        break
    except:
        #trying everything again, this time switching the server to the second one
        print(f"Error: TLS handshake or original connection failed with {DNS_Servers[servers]}. Trying next option.")
        try:
            Raw_Socket = socks.socksocket() #reinstating socket after each time in case of error, sockets cannot be reused and must be entirely restarted
            if (args.Proxy != None): #reinstating proxy connection on reset socket
                Main_proxy.initilialise(Raw_Socket)
            #NOTE: not using try: and except commands because i want to see the error message during development, I'll be using try later on
            Raw_Socket.connect((DNS_Servers[servers]["IP_List"][1], 853)) #port 853 is the port for TLS encrypted DNS connections
            if (args.verboseStatus): #checking for verbose status before printing extra statements
                print("Successfully connected to DNS server")
            DoT_Socket = TLS_settings.wrap_socket(Raw_Socket, server_hostname=DNS_Servers[servers]["CN"])
            TLSConnected = True
            if (args.verboseStatus):
                print("Successfully initialised TLS 1.3")
            break
        except:
            print(f"An error occured on the secondary IP for {DNS_Servers[servers]}, switching provider.")

if (TLSConnected != True):
    sys.exit("Could not connect to ANY DNS servers in the lists. It is likely your ISP or firewall is blocking port 853 (the port used for DNS over TLS or DoT), check out your network configuration and search up if your ISP is blocking it. There is also the almost impossible situation where every single one of those DNS servers is down, but that's highly unlikely. Also check if your network is up.")

DoT_Socket.sendall(make_DNS_Query(Target_Domain, rdQuery_type=Targetted_Data_class)) #sending our dns.message based querry using the function we made before.
start_time = time.time()

try:
    DNS_Response, Response_Time = dns.query.receive_tcp(sock=DoT_Socket, expiration=args.timeout)
    end_time = time.time()
    DoT_Socket.close()
    Raw_Socket.close()
    if (args.verboseStatus):
        print("Successfully recieved response")
    print("Results:")
    print(DNS_Response)
    if (args.verboseStatus):
        print(f"Query time: {int((end_time - start_time) * 1000)} ms") #converts query time into milliseconds and then prints it.
except dns.exception.Timeout:
    print("Timeout error, try increasing timeout period.")
except:
    print("Uknown error.")
