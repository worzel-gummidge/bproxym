#! /usr/bin/python

import sys
import socket
import threading
import re
import getopt

REQUEST = False
RESPONSE = False
OUTFILE = False
INTERCEPT = False

def main():
    global REQUEST
    global RESPONSE
    global OUTFILE
    global INTERCEPT
    local_address = False

    if len(sys.argv[1:]) < 1:
        usage()
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hl:q:s:o:i', ['help', 'listener_address', 'request', 'response', 'output', 'intercept'])
    except getopt.GetoptError as err:
        print str(err)
        usage()
    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
        elif o in ('-l', '--listener-address'):
            local_address = a.split(':')
            local_host = local_address[0]
            local_port = int(local_address[1])
        elif o in ('-q', '--request'):
            REQUEST = a
        elif o in ('-s', '--response'):
            RESPONSE = a
        elif o in ('-o', '--output'):
            OUTFILE = a
        elif o in ('-i', '--intercept'):
            INTERCEPT = True
        else:
            assert False,'Unhandled Option'
    if local_address == False:
        print "Please specify the -l option"
        usage()
    try:
        server_loop(local_host, local_port)
    except KeyboardInterrupt:
        print "[!!] Exiting.."
        exit(0)

def usage():
    print "BHP Proxy Modified"
    print
    print "Usage: ./bproxym.py -l listener_address [options]"
    print "-h --help                        - displays this usage text"
    print "-l --listener-address            - listen on host:port for incoming connections"
    print "-q --request                     - use this to specify http request options. supported arguments are: hex(displays the http request headers in hexadecimal), show(displays the http request headers), edit(gives the user an opportunity to edit the http request before the request is forwarded)"
    print "-s --response                    - use this to specify http response options. supported arguments are: hex(displays the http response headers bytes in hexadecimal), show(displays the http response headers), edit(gives the user an opportunity to edit the http response before the response is forwarded)"
    print "-o --output                      - write the request headers to a file. the argument is the name of the file to save to"
    print "-i --intercept                   - intercept the http request/response. to specify an output file for a single request/response enter '-o/--output test.txt' into the prompt"
    print
    print
    print "Examples: "
    print "./bproxym -l 127.0.0.1:9000 (listens on local port 9000 and forwards http traffic)"
    print "./bproxym -l 127.0.0.1:9000 -q edit (listens on local port 9000 and gives the user an opportunity to edit the http request before forwarding the traffic)"
    print "./bproxym -l 127.0.0.1:9000 -q edit -s show (listens on local port 9000, gives the user an opportunity to edit the http request before forwarding the traffic and then displays the http response)"
    print "./bproxym -l 127.0.0.1:8000 -i (listens on local port 8000, intercepts all http requests/responses and waits for user input. hitting the return key forwards the http request/response)"
    sys.exit(0)

def server_loop(local_host, local_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((local_host, local_port))
    except:
        print "[!!] Failed to listen on %s:%d" % (local_host, local_port)
        print "[!!] Check for other listening sockets or correct permissions."
        sys.exit(0)
    print "[*] Listening on %s:%d" % (local_host, local_port)
    server.listen(5)
    while True:
        client_socket, addr = server.accept()
        print "[==>] Received incoming connection from %s:%d" % (addr[0], addr[1])
        proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, addr))
        proxy_thread.start()

def proxy_handler(client_socket, addr):
    global RESPONSE_HEADERS
    global OUTFILE
    global INTERCEPT
    file_name = OUTFILE
    remote_port = 80
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        data = receive_from(client_socket)
        if data:
            remote_host, remote_port = get_remote(data)
        try:
            remote_socket.connect((remote_host, remote_port))
        except:
            pass
        local_buffer = data
        if len(local_buffer):
            print "[==>] Received %d bytes from %s(localhost).\n" % (len(local_buffer), addr[0])
            local_buffer = request_handler(local_buffer)
            if file_name:
                write_file(file_name, local_buffer)
            try:
                remote_socket.send(local_buffer)
            except Exception as ex:          # ignore background traffic
                print ex
            print "[==>] Sent to %s(remote)." % remote_host
        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print "[<==] Received %d bytes from %s(remote).\n" % (len(remote_buffer), remote_host)
            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print "[<==] Sent to %s(localhost)." % addr[0]
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print "[*] No more data. Closing connections."
            break

def receive_from(connection):
    buffer = ""
    connection.settimeout(2)
    try:
        while True:
            data = connection.recv(8192)
            if not data:
                break
            buffer += data
    except:
        pass
    return buffer

def request_handler(buffer):
    if REQUEST:
        if REQUEST == 'hex':
            hexdump(buffer)
        elif REQUEST == 'show':
            show_request_headers(buffer)
    if INTERCEPT:
        intercept(buffer)
    return buffer

def response_handler(buffer):
    if RESPONSE:
        if RESPONSE == 'hex':
            hexdump(buffer)
        elif RESPONSE == 'show':
            show_response_headers(buffer)
    if INTERCEPT:
        intercept(buffer)
    return buffer

def get_headers(buffer):
    try:
        headers_raw = buffer[:buffer.index("\r\n\r\n")+2]
#        headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", headers_raw))
    except:
        return None
    return headers_raw

def get_remote(buffer):
    remote_port = 80
    try:
        headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", get_headers(buffer)))
    except:
        return None
    if headers:
        host_addr = headers['Host'].split(':')
        remote_host = host_addr[0]
        if len(host_addr) > 1:
            remote_port = int(host_addr[1])
    return remote_host, remote_port

def write_file(outfile, buffer):
    global OUTFILE
    headers = get_headers(buffer)
    try:
        file_descriptor = open(outfile, 'a')
        file_descriptor.write(headers + '\n')
        file_descriptor.close()
        OUTFILE = False
    except OSError as err:
        print err

def hexdump(src, length=16):
    result = []
    digits = 4 if isinstance(src, unicode) else 2
    for i in xrange(0, len(src), length):
        s = src[i:i+length]
        hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7f else b'.' for x in s])
        result.append(b"      %04X %-*s %s" % (i, length*(digits + 1), hexa, text))
    print b'\n'.join(result) + '\n'
    return src

def intercept(src):
    while True:
        command = raw_input('>>> ').split()
        if command == []:
            break
        elif command[0] == '-o' or command[0] == '--output':
            try:
                file_descriptor = open(command[1], 'w')
                file_descriptor.write(src)
                file_descriptor.close()
                break
            except Exception as ex:
                print ex
                break
        else:
            print "[!!] Unsupported/unknown command. Commands currently supported are:\n     -o/--output <file name>"
    return src

def show_response_headers(src):
    headers = get_headers(src).split('\r\n')
    for header in headers:
        print "      " + header
    return src

def show_request_headers(src):
    headers = get_headers(src).split('\r\n')
    for header in headers:
        print "      " + header
    return src

main()
