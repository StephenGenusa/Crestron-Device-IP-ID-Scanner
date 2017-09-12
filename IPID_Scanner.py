#!/usr/bin/env python

"""
Copyright © 2017 by Stephen Genusa

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
#
import hexdump

def test_ipid(sock, ipid, num_retries):
    for _unused in range(0, num_retries):
        msg = b"\x0a\x00\x0b\x00" + chr(ipid) + "\xa3\x42\x40\x02\x00\x00\xd1\x01\x00"
        sock.sendall(msg)
        data = sock.recv(100)
        #if data == b"\x02\x00\x03\xFF\xFF\x02":
        #   "  IP ID {0:#0{1}x}".format(ipid, 4), "was not accepted"
        if data == b"\x02\x00\x04\x00\x00\x00\x1F":
            print "  IP ID {0:#0{1}x}".format(ipid, 4), "is open for business"
            return


def test_ip_for_ids(iptocheck):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (iptocheck, 41794)
    sock.settimeout(2.0)
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
