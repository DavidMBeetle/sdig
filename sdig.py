#importing standard libraries
import argparse
import ssl
import socket #here to add support to other modules
import sys
import time
from pathlib import Path #to enable the finding of the config file.
import tomllib
import selectors
#import external libraries
import socks
import dns.rdatatype
import dns.query #gives you manual dns querying similar to dns.message as well as network management which is useful.
#we're only importing recieve TCP to skip all the manual TCP tags and decodings.
import dns.message #to create the DNS query before sending
import dns.reversename
import dns.name #gives compatability with dns.reversename.

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
    
    def initialilise(self, socket): #using this as a function since we have to reinitiliase the proxy for each time we restart the socket
        #initialises the proxy
        socket.set_proxy(socks.SOCKS5, self.address, self.port)

class Reverse_Name_Search():

    def __init__(self, IP):
        try:
            self.reverseAddress = str(dns.reversename.from_address(IP)) #converting to string to make it easier to save in here
        except dns.exception.SyntaxError:
            sys.exit("Malformed IP address based syntax error. Terminating program. Double check that what you put in with the domain flag is an IPV4 or IPV6 address.")
        except:
            sys.exit("An uknown error occured…")

    def ReverseQuery(self):
        return make_DNS_Query(self.reverseAddress, rdQuery_type=dns.rdatatype.PTR)

class DNS_Async_Sockets(socks.socksocket):

    def __init__(self, serverIP, hostname):
        #initiliasing socket from socks.socket parent class.
        super().__init__()
        #copying parameters into object memory
        self.serverIP = serverIP
        self.hostname = hostname

        #adding other paramaters for in the while loop
        self.TLS_Status = False
        self.isAlive = True
        self.QuerySent = False

        self.buffer = bytearray() #this is going to be for recieving messages later on
        self.expectedLength = None

        #initiliasing the asynchronous connection
        #Starting up the proxy based connection
        if (args.Proxy != None):
            Main_proxy.initialilise(self)
        self.setblocking(False)
        try:
            self.connect((self.serverIP, 853))
        except InterruptedError:
            print("Connection interrupted")
            self.isAlive = False
        except TimeoutError:
            print("Timeout occured on original connection. Please check if you have an internet connection or the server is up")
            self.isAlive = False
        self.encrypted = TLS_settings.wrap_socket(self, server_hostname=self.hostname, do_handshake_on_connect=False)
        sel.register(self.encrypted, events=selectors.EVENT_WRITE, data=self)

        #preparing space in memory for later
        self.Response = None

    def close(self):
        try:
            sel.unregister(self.encrypted) #unregistering before closing to prevent glitched in registration
        except (KeyError, ValueError):
            pass #already unregistered apparently
        try: #using a try in case self.encrypted hasn't even formed or exists yet when the socket dies
            self.encrypted.close()
        except:
            pass

        super().close()
        self.isAlive = False

    def GetStatus(self):
        self.CanRead = False #defaulting them both to false
        self.CanWrite = False
        global asynchronous_socket_Statuses
        SocketStatuses = asynchronous_socket_Statuses
        #must be used as seperate if statements since if i use an elif it won't register write if the read is on.
        for key, mask in SocketStatuses:
            if (key.data is self): #checking if it refers to the right socket. key.data is the data we put in originally when we registered it, which was self
                if (mask & selectors.EVENT_READ):
                    self.CanRead = True
                if (mask & selectors.EVENT_WRITE):
                    self.CanWrite = True
                break
            else:
                continue

    def TLS_Handshake(self):
        self.GetStatus()
        try:
            if (self.TLS_Status == False) and (self.isAlive == True):
                self.encrypted.do_handshake(block=False)
                self.TLS_Status = True
                print("Handshake successful")
        except ssl.SSLWantReadError:
            sel.modify(self.encrypted, events=selectors.EVENT_READ, data=self)
        except ssl.SSLWantWriteError:
            sel.modify(self.encrypted, events=selectors.EVENT_WRITE, data=self)
        except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
            # Server closed or reset connection—clean up dead socket
            print("Socket died, closing it.")
            self.close()






#Automating the DNS resposne part


#functions

#We're building it like this since you need too and DNS querry doesn't have native proxy support.
def make_DNS_Query(Domain_Name, rdQuery_type): #created function to create a DNS_Query for DNS over TCP with TLS
    query_message = dns.message.make_query(Domain_Name, rdtype=rdQuery_type)
    return query_message.to_wire(prepend_length=True)
    
#VERSION variable, change as you go:

sdig_version = "Version 1.2.3"

#parsers
#initialising the parser
parser = argparse.ArgumentParser(prog="sdig", description="A secure DNS look up alternative to the dig terminal utility. Uses DNS over TCP with TLS/SSH (DoT) and interacts with raw and encrypted sockets.", epilog="Happy hunting")


#making arguments
parser.add_argument("-d", "--domain", required=True, help="Required tag, tells the DNS server what domain to ask the DNS server to find. If you put -x then you can input an IP here for a revers search.", type=str, dest="Target_Domain")
parser.add_argument("-t", "--rdtype", default='A', dest="rd_type", help="The data type demanded in the DNS request, example MX server. Invalid responses will lead to an error.", type=str)
parser.add_argument("--proxy", required=False, dest="Proxy", type=str, help="Proxy argument to route your DNS querries through a proxy. Some DNS servers will reject the proxy.")
parser.add_argument("-v", "--version", help=f"Prints the current version, that being {sdig_version}", action="version", version=sdig_version)
parser.add_argument("--timeout", help="How long the program will wait in seconds before giving up on a connection. Default is 30. This is an integer, do not put in values with decimals.", type=int, default=30, required=False, dest="timeout")
parser.add_argument("--verbose", help="Makes the program a lot more expressive in terms of it's actions and tells you what's happening.", action='store_true', dest="verboseStatus")
parser.add_argument("-x", "--Reverse", help="Makes the DNS perform a reverse search, finding the domain linked to an IP address. This cannot be mixed with -t/--rdtype as in order to do this rd-type is forced into PTR (reverse DNS search). Put the IP after the -d flag.", required=False, action="store_true", dest="Reverse_DNS_LookUp")

args = parser.parse_args() #parsing it all

if args.Proxy != None:
    Main_proxy = Proxy(args.Proxy)

#checking if reverse search is being used wrong
if (args.Reverse_DNS_LookUp) and (args.rd_type != "A"): #checking if it was changed form default
    sys.exit("-x or --Reverse cannot be used with domain or rdtype flags. User error.")
elif (args.Reverse_DNS_LookUp):
    #instating Reverse search object
    reverseDNS_Object = Reverse_Name_Search(args.Target_Domain)

###loading toml file

#finding directory:
script_dir = Path(__file__).resolve().parent #finds the folder the script is in
config_path = Path(script_dir / "config.toml")
if not (config_path.exists()):
    sys.exit("Config file not detected, clean shut down. Please ensure the following:")
#using with to automatically close the file immediately after
with open(config_path, "rb") as config_File:
    config = tomllib.load(config_File) #saves the entire toml file after loading it into memory
del script_dir #clearing memory from no longer needed information
del config_path

DNS_Servers = config["DNS_Servers"] #stores the DNS_Servers dictionary in this variable so the rest of everything will work.

#Before creating any sockets, let's create the original asynchronous selector object

sel = selectors.DefaultSelector()

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

TLSConnected = False #false for now
for servers in DNS_Servers:
    try:
        Raw_Socket = socks.socksocket() #reinstating socket after each time in case of error, sockets cannot be reused and must be entirely restarted
        if (args.Proxy != None): #reinstating proxy connection on reset socket
            Main_proxy.initialilise(Raw_Socket)

        try:
            Raw_Socket.connect((DNS_Servers[servers]["IP_List"][0], 853)) #port 853 is the port for TLS encrypted DNS connections
            if (args.verboseStatus):
                print("Successfully connected to DNS server")
            print(f"Using {DNS_Servers[servers]['CN']}")
        except:
            continue

        try:
            DoT_Socket = TLS_settings.wrap_socket(Raw_Socket, server_hostname=DNS_Servers[servers]["CN"])
            TLSConnected = True
            if (args.verboseStatus):
                print("Successfully initialised TLS 1.3")
        except:
            continue
        break
    except:
        DoT_Socket.close()
        Raw_Socket.close()
        #trying everything again, this time switching the server to the second one
        print(f"Error: TLS handshake or original connection failed with {DNS_Servers[servers]}. Trying next option.")
        try:
            Raw_Socket = socks.socksocket() #reinstating socket after each time in case of error, sockets cannot be reused and must be entirely restarted
            if (args.Proxy != None): #reinstating proxy connection on reset socket
                Main_proxy.initialilise(Raw_Socket)
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
            DoT_Socket.close()
            Raw_Socket.close()

if (TLSConnected != True):
    sys.exit("Could not connect to ANY DNS servers in the lists. It is likely your ISP or firewall is blocking port 853 (the port used for DNS over TLS or DoT), check out your network configuration and search up if your ISP is blocking it. There is also the almost impossible situation where every single one of those DNS servers is down, but that's highly unlikely. Also check if your network is up.")

#initiliasing variables before the loop to create global constants that are necessary for safe guarding the loop
#Variable is needed in order to stop it from reinitiliasing query timer each time.

 #First go at this is done using the settings from the prior loop, only if it doesn't get an error, does it go through this one.
if (args.Reverse_DNS_LookUp):
    print(f"Using {DNS_Servers[servers]["CN"]}")
    #place holder to hold the DNS reverse query, makes it easier to read rather than a massive line.
    DNS_reverseQuerryHolder = reverseDNS_Object.ReverseQuery()
    try:
        DoT_Socket.sendall(DNS_reverseQuerryHolder)
        start_time = time.time()
    except:
        sys.exit("Failed to send dns Querry over socket. Error, quitting.")
    del DNS_reverseQuerryHolder #deleting the object to optimise memory usage.
else:
    try:
        DoT_Socket.sendall(make_DNS_Query(Target_Domain, rdQuery_type=Targetted_Data_class)) #sending our dns.message based querry using the function we made before.
    except:
        sys.exit("Failed to send dns Querry over socket. Error, quitting.")
    #making it check if it's already registered the start time. It's supposed to be a timer from the first querry.
    #By setting is as false first, and only setting it as true on the first loop, it will stop it from repeatedly restarting
    start_time = time.time()
try:
    DNS_Response, Response_Time = dns.query.receive_tcp(sock=DoT_Socket, expiration=args.timeout)
except dns.exception.Timeout:
    print("Timeout error, try increasing timeout period.")
    DNS_Response = None
except:
    print("Uknown error.")
    DNS_Response = None

    #Implementing a check to see if there is no answer, if so, it will switch providers.


Failed_Attempts = 0


if (DNS_Response is None) or (len(DNS_Response.answer) == 0):
    for servers in DNS_Servers:
        #creating socket's procedurally
        DNS_Servers[servers]["sock"] = DNS_Async_Sockets(serverIP=DNS_Servers[servers]["IP_List"][0], hostname=DNS_Servers[servers]["CN"])

    #everything goes in this if loop
    AsynchronusEngine = True #creating a worthless variable to continuously keep a while loop going on

    while AsynchronusEngine == True:
        asynchronous_socket_Statuses = sel.select(timeout=args.timeout) #putting it at top of loop so it can be reinstated each time

        for key, mask in asynchronous_socket_Statuses:
            if (key.data.isAlive != True):
                key.data.close()
                continue

            if (key.data.TLS_Status == False) and (key.data.isAlive == True): #this ensures that it's actually true and no glitched happened
                #can't be too careful with the TLS status
                key.data.TLS_Handshake()

        
        for key, mask in asynchronous_socket_Statuses: #sending out packets
            if (key.data.isAlive == True):
                key.data.GetStatus() #key.data is self, GetStatus() handles the bit masking for us, this is more for readability
                #it makes it easier for developpers without experience in bitmasking to contribute.
                if (key.data.TLS_Status == True) and (key.data.QuerySent == False): #can't be too careful about errors with TLS
                    #this is important to allowing us to recieve responses
                    try:
                        key.data.encrypted.sendall(make_DNS_Query(Domain_Name=Target_Domain, rdQuery_type=Targetted_Data_class))
                        key.data.QuerySent = True
                    except ssl.SSLWantWriteError:
                        sel.modify(key.data.encrypted, events=selectors.EVENT_WRITE, data=key.data)
                        continue
                    except ssl.SSLWantReadError:
                        sel.modify(key.data.encrypted, events=selectors.EVENT_READ, data=key.data)
                        continue
                    except (BrokenPipeError, ConnectionResetError, OSError, socket.error, OSError, socket.herror, socket.gaierror):
                        print("Network error")
                        key.data.isAlive = False
                    except socket.timeout:
                        print("Connection timed out")
                        key.data.isAlive = False
                    except:
                        print("Uknown error")
                        key.data.isAlive = False
                else:
                    continue

        
        for key, mask in asynchronous_socket_Statuses:
            if (key.data.isAlive != True):
                key.data.close()
                continue
            key.data.GetStatus()

            if (key.data.CanRead == True) and (key.data.TLS_Status == True):
                if (key.data.Response == None):
                    try:
                        raw_Data = key.data.encrypted.recv(65535) #using recieve with the longest possible TCP DNS solution
                        key.data.buffer.extend(raw_Data)
                        if (raw_Data == b""): #checking if it recieved empty response
                            #this means the socket is dead
                            key.data.isAlive = False
                    except ssl.SSLWantReadError:
                        raw_Data = None
                        sel.modify(key.data.encrypted, events=selectors.EVENT_READ, data=key.data)
                        continue
                    except ssl.SSLWantWriteError:
                        sel.modify(key.data.encrypted, events=selectors.EVENT_READ | selectors.EVENT_WRITE, data=key.data) #allows us to both read and write
                        continue
                    except (ConnectionResetError, BrokenPipeError, OSError) as error:
                        key.data.close()
                        print(f"Connection Error: {error}")
                    except:
                        print("Uknown error")


                    if (len(key.data.buffer) >= 2) and (key.data.expectedLength == None) and (key.data.Response == None):
                        key.data.expectedLength = int.from_bytes(key.data.buffer[:2], "big") #recieving the first 2 bytes to turn it into our extended length
                        del key.data.buffer[:2] #deleting the pre TCP connection prepended length now that we've used it
                    elif (len(key.data.buffer) < 2):
                        continue

                    if (key.data.expectedLength != None): #checking if it's registered the first 2 bits first
                        if (len(key.data.buffer) >= key.data.expectedLength):
                            key.data.Response = dns.message.from_wire(bytes(key.data.buffer[:key.data.expectedLength]))
                            if (key.data.Response != None):
                                if not (isinstance(key.data.Response, dns.message.Message)):
                                    key.data.Response = None #resetting response if it's not a valid dns message


                elif (key.data.CanRead == False):
                    continue

                if (key.data.Response != None):
                    if (len(key.data.Response.answer) > 0):
                        DNS_Response = key.data.Response
                        AsynchronusEngine = False
                        break
                    else:
                        continue


        for key in list(sel.get_map().values()): #checking if any of them are above 0, if all the sockets have recieved
            if (key.data.Response != None):
                if len(key.data.Response.answer) > 0:
                    DNS_Response = key.data.Response.answer
                    AsynchronusEngine = False
                    break
                else:
                    continue

        Failed_Attempts = 0 #resetting number of failed attempts for each loop
        
        #checking if the amount of failures is equal too the total length of it.
        for key in list(sel.get_map().values()):
            if (key.data.Response != None):
                if (len(key.data.Response.answer) == 0) and (key.data.isAlive == True):
                    Failed_Attempts = Failed_Attempts + 1
        if (Failed_Attempts >= len(list(sel.get_map().values()))):
            break


        #creating local variable for current time to ensure a hard limit on time
        current_time = time.time()

        if (int(current_time - start_time) >= args.timeout):
            raise TimeoutError("User specified timeout period reached")

        if (int(current_time - start_time) >= 15): #stops it from going above 15 seconds
            raise TimeoutError("Emergency hardcoded timeout triggered after 15 seconds")






end_time = time.time()

DoT_Socket.close()
Raw_Socket.close()
del DoT_Socket #clearing socket objects since they are no longer necessary, optimises memory usage.
del Raw_Socket
if (args.verboseStatus):
    print("Successfully recieved DNS response")
if (len(DNS_Response.answer) != 0):
    print("Results:")
    print(DNS_Response)
else:
    print("No results in DNS response. Domain is unknown or does not exist.")

if (args.verboseStatus):
    print(f"Query time: {int((end_time - start_time) * 1000)} ms") #converts query time into milliseconds and then prints it.
