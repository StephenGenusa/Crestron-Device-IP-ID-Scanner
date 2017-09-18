#!/usr/bin/env python

"""
IP ID Scanner and CIP Signal Modifier by Stephen Genusa
September 2017
  
Some code translated from CommandFusion's Javascript

  
Copyright (c) 2017 by Stephen Genusa

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
"""

import argparse
import socket
import time
#
import hexdump


def send_data(sock, msg, note):
    #print "data event is", note, "msg to send is:"
    #print hexdump.hexdump(msg)
    sock.sendall(msg)


def receive_data(sock, join, type):
    try:
        print "hello"
        data = sock.recv(4)
        if len(data) == 300:
            print "*** Your receive buffer is too small ***"
        #print "receive data is:"
        #print hexdump.hexdump(data)
        #print "valid", type, "join is", join
        return
    except Exception, e:
        #print ("The exception was: %s" % e)
        pass


def digital_send(sock, join, value):
    """
    BUG: This is going to handle joins 1-255 but nothing else. Code needs to be fixed
    """
    rawJoin = join - 1
    if value == 1:
        msg = b"\x05\x00\x06\x00\x00\x03\x27" + chr(rawJoin & 0xFF) + chr(rawJoin >> 8)
    else:
        msg = b"\x05\x00\x06\x00\x00\x03\x27" + chr(rawJoin & 0xFF) + chr((rawJoin >> 8) | 0x0080)
    send_data(sock, msg, "digital_send")
    receive_data(sock, join, "digital")


def analog_send(sock, join, value):
    """
    BUG: This is going to handle joins 1-255 but nothing else. Code needs to be fixed
    """
    rawJoin = join - 1
    rawValue = int(value)

    joinUpper = chr(rawJoin >> 8)
    joinLower = chr(rawJoin & 0xff)
    valUpper = chr(rawValue >> 8)
    valLower = chr(rawValue & 0xff)
    msg = b"\x05\x00\x08\x00\x00\x05\x14"+ joinUpper + joinLower + valUpper + valLower
    send_data(sock, msg, "analog send")
    receive_data(sock, join, "analog")


def serial_send(sock, join, value):
    """
    BUG: This is going to handle joins 1-255 but nothing else. Code needs to be fixed
    """
    rawJoin = join - 1
    payload = b"\x00\x00" + chr(len(value) + 2) + "\x12" + chr(rawJoin) + value;
    msg = b"\x05\x00" + chr(len(payload)) + payload
    send_data(sock, msg, "serial send")
    receive_data(sock, join, "serial")


def send_update_request(sock):
    #msg = "\x05\x00\x42\x00\x00\x3F\x03\x30\x01\x01\x3A"
    msg = b"\x05\x00\x05\x00\x00\x02\x03\x00" # Update Request
    send_data(sock, msg, "update request")
    receive_data(sock, -1, "ur")


def test_ipid(sock, ipid, num_retries):
    for _unused in range(0, num_retries):
        msg = b"\x0a\x00\x0b\x00" + chr(ipid) + "\xa3\x42\x40\x02\x00\x00\xd1\x01\x00"
        try:
            sock.sendall(msg)
            data = sock.recv(100)
            #if data == b"\x02\x00\x03\xFF\xFF\x02":
            #   "  IP ID {0:#0{1}x}".format(ipid, 4), "was not accepted"
            if data == b"\x02\x00\x04\x00\x00\x00\x1F":
                print "  IP ID {0:#0{1}x}".format(ipid, 4), "is open for business"
                #if ipid == 0x25:
                    #send_update_request(sock)
                    #receive_data(sock)
                    #serial_send(sock, 8, "I'm going to push digital 4 high")
                    #digital_send(sock, 4, 1)
                    #serial_send(sock, 8, "I'm going to set digital 6 to 5123")
                    #analog_send(sock, 6, 5123)
                    #serial_send(sock, 8, "I'm going to set digital 6 to 65535")
                    #analog_send(sock, 6, 65535)
                    #serial_send(sock, 8, "Of course this is setting a serial signal")
 
                    # Hmmm. What can we do? There's no protection or security or bad actor code to prevent
                    #   something like this:
                    # Send a variety of serial signals to turn devices on or off or modify panel text
                    #for join_num in range(1, 65535):
                    #    serial_send(sock, join_num, "\x02PON\x03")
                    #    serial_send(sock, join_num, "\xFA\x91\xCA")

                    # Now set all the analog joins in the program to 65535/100%
                    #for join_num in range(1, 65353):
                    #    analog_send(sock, join_num, 65535)
                    
                    # Now pulse all digital joins high
                    #for join_num in range(1, 65535):
                    #    digital_send(sock, join_num, 1)

                return # success so return
        except Exception, e:
            print ("The exception was: %s" % e)

def test_ip_for_ids(iptocheck):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (iptocheck, 41794)
    sock.settimeout(.5)
    sock.connect(server_address)
    data = sock.recv(100)
    if data == b"\x0f\x00\x01\x02":
        print "CIP connection accepted on device at IP {0}".format(iptocheck)
        
    for ipid in range(0,256):
        test_ipid(sock, ipid, 2)
    sock.close()


if __name__ == "__main__":
    # pylint: disable-msg=C0103
    print("\nStephen Genusa's Crestron Device IP ID Scanner 1.0\n")
    parser = argparse.ArgumentParser()
    parser.add_argument("-ip", "--iptocheck", help="A single Crestron IP address to test for open IP ID's on.")
    parser_args = parser.parse_args()
    if not parser_args.iptocheck:
        parser.print_help()
        exit()
    test_ip_for_ids(parser_args.iptocheck)
