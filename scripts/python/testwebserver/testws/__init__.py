from http.server import HTTPServer, SimpleHTTPRequestHandler

import multiprocessing
import os
import ssl
import time

SCRIPT_DIR = os.path.dirname(__file__)

KEY_PATH = os.path.abspath(os.path.realpath(
    os.path.join(SCRIPT_DIR, '..', 'key.pem')))
CERT_PATH = os.path.abspath(os.path.realpath(
    os.path.join(SCRIPT_DIR, '..', 'cert.pem')))


def run_http_server():
    print('Starting HTTP Server')
    httpd = HTTPServer(('', 8080), SimpleHTTPRequestHandler)
    httpd.serve_forever()


def run_https_server():
    print('Starting HTTPS Server')
    httpd = HTTPServer(('', 8443), SimpleHTTPRequestHandler)

    httpd.socket = ssl.wrap_socket(httpd.socket,
                                   keyfile=KEY_PATH,
                                   certfile=CERT_PATH, server_side=True)

    httpd.serve_forever()


def main(argv=None):
    phttp = multiprocessing.Process(target=run_http_server, args=())
    phttp.daemon = True
    phttp.start()

    phttps = multiprocessing.Process(target=run_https_server, args=())
    phttps.daemon = True
    phttps.start()

    # time.sleep(5)
    # phttp.kill()
    # phttps.kill()
    phttp.join()
    phttps.join()
    print('GOODBYE')
