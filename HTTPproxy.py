"""
Author: Ashton Foulger
Assignment: HTTP Proxy - CS 4480 - Spring 2022
Version: 2/17/22
"""

# Imports
import signal
import sys
import socket
import select
import re
import os
from _thread import *
from optparse import OptionParser
from urllib.parse import urlparse

# Global Variables
BUFFER_SIZE = 4096

# Cache Blocklist Variables
BLOCKLIST = set()
BLOCKLIST_ENABLED = False

# Cache Global Variables
CACHE_ENABLED = False
CACHE = dict()
CACHEDIR = None

# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)


"""
Opens and starts socket for accepting client connections to proxy.
Allowing the proxy to listen to connections on a given port and hostname.
"""
def StartSocket(hostname, port):
    _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        _socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _socket.bind((hostname, port))
    except Exception as e:
        print("Connection was unable to be made...")
        exit(1)

    _socket.listen(100)
    print("Listening on [" + str(hostname) + ":" + str(port) + "] \n")

    while True:
        # Allows for ctrl-c to end proxy connection and or keep the proxy open
        readable, writable, errors = select.select([_socket], [], [], 0.01)
        for s in readable:
            if s is _socket:
                client, addr = _socket.accept()
                try:
                    start_new_thread(AcceptConnection, (client,))
                    print("A client has connected...")
                except Exception as e:
                    SendBadRequest(client)
                    client.close()
                    continue


"""
Accepts connections from socket given a client socket,
and client address in order to receive data and decode the request.
"""
def AcceptConnection(client):
    try:
        request = ""
        while True:
            buffer = client.recv(BUFFER_SIZE)
            if buffer is None:
                client.close()
                return
            request += buffer.decode()
            if re.search('(\r\n\r\n|\n\n)$', request):
                break
    except Exception:
        SendBadRequest(client)
        client.close()
        return

    ProcessRequest(client, request)


"""
Process clients request data and ensures that any request is using the correct method,
HTTP version, and that the connection has no malformed header data.
"""
def ProcessRequest(client, request):
    global CACHE
    global CACHE_ENABLED

    # Check for malformed request
    if not(request.endswith("\r\n\r\n") or (request.endswith("\n\n"))):
        SendBadRequest(client)
        client.close()
        return

    # Split Tokens from request
    tokens = re.split('\r?\n', request)
    tokens.pop()
    tokens.pop()
    getRequestTokens = tokens[0].split(' ')
    method = getRequestTokens[0]

    # Check for correct HTTP request Method
    if(re.search("^POST", method) or (re.search("^HEAD", method))):
        SendNotImplemented(client)
        client.close()
        return
    elif not(re.search("^GET", method)):
        SendBadRequest(client)
        client.close()
        return

    # Ensure that the request has 3 objects
    if(len(getRequestTokens) != 3):
        SendBadRequest(client)
        client.close()
        return

    # Ensure that the correct HTTP version is requested
    try:
        url = urlparse(getRequestTokens[1])
        url.port
    except:
        SendBadRequest(client)
        client.close()
        return

    # Check URL Scheme
    if(url.scheme != "http" or re.search("^.+$", url.hostname) is None or re.search("^/.*$", url.path) is None):
        SendBadRequest(client)
        client.close()
        return

    # Ensure that we are using correct HTTP version
    httpVersion = getRequestTokens[2]
    if not re.search("^HTTP/1.0$", httpVersion):
        SendBadRequest(client)
        client.close()
        return

    # Check for cache options
    if SetCacheOptions(url.path):
        SendOkResponse(client)
        client.close()
        return

    # Check for blocklist options
    if SetBlocklistOptions(url.path):
        SendOkResponse(client)
        client.close()
        return
    
    # Check if hostname is in URL blocklist
    if(BLOCKLIST_ENABLED):
        hostWithPort = url.hostname
        if(url.port):
            hostWithPort += ":" + str(url.port)
        if(FilterURLs(hostWithPort)):
            SendForbiddenResponse(client)
            client.close()
            return

    # Replace host with just hostname
    getRequestTokens[2] = "HTTP/1.0"
    getRequestTokens[1] = url.path
    tokens[0] = ' '.join(getRequestTokens)

    # Check formatting of header tokens
    new_tokens = []
    new_tokens.append(tokens[0])
    new_tokens.append("Host: " + url.hostname)
    new_tokens.append("Connection: close")

    # Check if url exists in cache and add modified since tag
    if(CACHE_ENABLED and url.geturl() in CACHE):
        new_tokens.append("If-Modified-Since: " + CACHE[url.geturl()])

    # Check for bad HTTP header
    for i in range(1, len(tokens)):
        if not re.search("([a-z]|[A-Z]|-)+: .+$", tokens[i]):
            SendBadRequest(client)
            client.close()
            return
        if re.search("^(Proxy-)?connection:", tokens[i].lower()):
            SendBadRequest(client)
            client.close()
            continue
        if re.search("^host:", tokens[i].lower()):
            continue
        new_tokens.append(tokens[i])

    requestTokens = ("\r\n".join(new_tokens) + "\r\n\r\n")
    ProcessClientResponse(client, url, requestTokens)


"""
Send client proxy data response from clients request. If an error occurs,
send malformed request header.
"""
def ProcessClientResponse(client, url, request):
    # Default port to 80 unless otherwise needed
    port = 80
    if not url.port is None:
        port = url.port

    # Start response socket
    _httpSocket = socket.socket(socket.AF_INET, socket. SOCK_STREAM)
    try:
        _httpSocket.connect((url.hostname, port))
        _httpSocket.sendall(bytes(request, 'utf-8'))
    except Exception as e:
        SendBadRequest(client)
        _httpSocket.close()
        client.close()
        return

    # Check for successful response from the client
    response = bytes()
    try:
        while True:
            res = _httpSocket.recv(BUFFER_SIZE)
            response += res
            if not res:
                _httpSocket.close()
                break
        
        # If cache is enabled retreive or save cache items
        if(CACHE_ENABLED):
            if(url.geturl() not in CACHE):
                SaveToCache(url.geturl(), response)
            else:
                responseHeader = ParseResponseHeader(response)
                if (GetStatusCode(responseHeader) == 304):
                    response = LoadFromCache(url.geturl())

        client.sendall(response)
        client.close()
    except Exception as e:
        print("Error:", e)
        _httpSocket.close()
        SendBadRequest(client)
        client.close()


"""
Sends 200 OK HTTP header to client.
"""
def SendOkResponse(client):
    client.sendall(bytes(
        "HTTP/1.0 200 OK\r\n", 'utf-8'))
    return


"""
Sends 403 Forbidden HTTP header to client.
"""
def SendForbiddenResponse(client):
    client.sendall(bytes(
        "HTTP/1.0 403 Forbidden\r\n", 'utf-8'))
    return


"""
Sends Bad request HTTP header to client.
"""
def SendBadRequest(client):
    client.sendall(bytes(
        "HTTP/1.0 400 Bad Request\r\n", 'utf-8'))
    return


"""
Sends Bad request HTTP header to client.
"""
def SendNotImplemented(client):
    client.sendall(bytes(
        "HTTP/1.0 501 Not Implemented\r\n", 'utf-8'))
    return


"""
Checks for valid proxy cache options and preforms options functions.
"""
def SetCacheOptions(path):
    # Brings Cache into scope
    global CACHE_ENABLED
    global CACHE
    
    # Checks various proxy settings and preforms operations accordingly
    if re.search("^/proxy/cache/enable$", path):
        CACHE_ENABLED = True
        print("Cache enabled...")
    elif re.search("^/proxy/cache/disable$", path):
        CACHE_ENABLED = False
        print("Cache disabled...")
    elif re.search("^/proxy/cache/flush$", path):
        CACHE.clear()
        print("Flushing cache...")
    else:
        return False

    return True


"""
Checks for valid proxy blocklist options and preforms option functions.
"""
def SetBlocklistOptions(path):
    # Brings Blocklist globals into scope
    global BLOCKLIST
    global BLOCKLIST_ENABLED

    # Checks various blocklist settings and preforms blocklist functions
    if re.search("^/proxy/blocklist/enable$", path):
        BLOCKLIST_ENABLED = True
        print("Blocking enabled...")
    elif re.search("^/proxy/blocklist/disable$", path):
        BLOCKLIST_ENABLED = False
        print("Blocking disabled...")
    elif re.search("^/proxy/blocklist/flush$", path):
        BLOCKLIST.clear()
        print("Flushing blocklist...")
    elif re.search("^/proxy/blocklist/add/.+$", path):
        addBlockItem = path.replace("/proxy/blocklist/add/", "")
        if(addBlockItem not in BLOCKLIST):
            BLOCKLIST.add(addBlockItem)
        print("Adding [" + addBlockItem + "] to Blocklist...")     
    elif re.search("^/proxy/blocklist/remove/.+$", path):
        removeBlockItem = path.replace("/proxy/blocklist/remove/", "")
        if(removeBlockItem in BLOCKLIST):
            BLOCKLIST.remove(removeBlockItem)
        print("Removing [" + removeBlockItem + "] from Blocklist...")
    else:
        return False
    
    return True


"""
Parses response header into header tokens insuring that we are able to get the current status,
and date modified and make sure we get whole response.
"""
def ParseResponseHeader(response):
    # Check if response does not have enough data
    if (len(response) < 4):
        return []
    
    # Loop through header till we reach end of header objects
    headerEnd = -1
    for i in range(0, len(response) - 3):
        if(response[i:i+4].decode() == '\r\n\r\n'):
            headerEnd = i
            break

    # Check if the header was empty then return empty array
    if(headerEnd == -1):
        return []

    # Split header into tokens to which we then place data into our cache array
    return re.split('\r\n', response[:headerEnd].decode())


"""
Checks the current status code of response.
"""
def GetStatusCode(header):
    status = header[0].split(" ")
    return int(status[1])


"""
Checks when the response is data was last modified from response header
"""
def GetLastModified(header):
    timeHeader = header[1:]

    date = ''
    for i in timeHeader:
        # Split header into header : value and return date object
        (fieldname, fieldvalue) = re.split(': ', i)
        if(fieldname.lower() == "last-modified"):
            return fieldvalue
        elif(fieldvalue.lower() == "date"):
            date = fieldvalue

    return date


"""
Saves URL cache entry if response has not already saved before.
Writing a new file with byte data received by the server.
"""
def SaveToCache(url, response):
    global CACHE
    global CACHEDIR

    # Parse Response to get header and date info
    header = ParseResponseHeader(response)
    date = GetLastModified(header)

    # Check to make sure cache directory exists
    if not os.path.isdir(CACHEDIR):
        os.mkdir(CACHEDIR)
    
    # Create filename and write response to file
    filename = os.path.join(CACHEDIR, str(hash(url)))
    with open(filename, 'wb') as cacheEntry:
        cacheEntry.write(response)
        CACHE[url] = date


"""
Loads URL cache data to be sent to the client.
"""
def LoadFromCache(url):
    global CACHEDIR

    # Get filename
    filename = os.path.join(CACHEDIR, str(hash(url)))

    # Check if file exists otherwise return empty bytes
    if os.path.isfile(filename):
        data = bytes()
        with open(filename, 'rb') as cacheEntry:
            data = cacheEntry.read()
        return data
    else:
        return bytes()


"""
Blocks URL connection if hostname address is found in blocklist.
"""
def FilterURLs(host):
    global BLOCKLIST
    return any(map(host.__contains__, BLOCKLIST))


"""
Starts proxy and takes in commandline options
"""
def main():
    parser = OptionParser()
    parser.add_option('-p', type='int', dest='serverPort')
    parser.add_option('-a', type='string', dest='serverAddress')
    (options, args) = parser.parse_args()
    port = options.serverPort
    address = options.serverAddress
    if address is None:
        address = 'localhost'
    if port is None:
        port = 2100

    # Set up signal handling (ctrl-c)
    signal.signal(signal.SIGINT, ctrl_c_pressed)

    # Create cache file directory
    global CACHEDIR
    filepath = os.path.realpath(__file__)
    currentDirectory = os.path.dirname(filepath)
    CACHEDIR = os.path.join(currentDirectory, "cache")

    # Start Accepting Clients
    StartSocket(address, port)


# Runs main
if __name__ == "__main__":
    main()
