from __future__ import (absolute_import, print_function, division)
import threading
import traceback
from mitmproxy.exceptions import ReplayException
from netlib.exceptions import HttpException, TcpException, NetlibException
from netlib.http import http1

from ..controller import Channel
from ..models import Error, HTTPResponse, ServerConnection, make_connect_request, make_connect_response
from .base import Kill
import time
import socket
from urllib2 import quote

# TODO: Doesn't really belong into mitmproxy.protocol...


class RequestReplayThread(threading.Thread):
    name = "RequestReplayThread"

    def __init__(self, config, flow, masterq, should_exit):
        """
            masterqueue can be a queue or None, if no scripthooks should be
            processed.
        """
        self.config, self.flow = config, flow
        if masterq:
            self.channel = Channel(masterq, should_exit)
        else:
            self.channel = None
        super(RequestReplayThread, self).__init__()

    def run(self):
        r = self.flow.request
        form_out_backup = r.form_out
        try:
            self.flow.response = None

            # If we have a channel, run script hooks.
            #if self.channel:
            #    request_reply = self.channel.ask("request", self.flow)
            #    if request_reply == Kill:
            #        raise Kill()
            #    elif isinstance(request_reply, HTTPResponse):
            #        self.flow.response = request_reply

            if not self.flow.response:
                # In all modes, we directly connect to the server displayed
                if self.config.mode == "upstream":
                    print("In upstream replay")
                    print(r.scheme)
                    print(r.method)
                    print("host [%s] port [%d]" % (r.host, r.port))
                    print(self.flow.server_conn.address)
                    server = ServerConnection(self.flow.server_conn.address, (self.config.host, 0))
                    server.connect()
                    print("connected")
                    #print(r)
                    if (r.method == "CONNECT"):
                        print('HTTPS replay')
                        connect_request = make_connect_request((r.host, r.port))
                        print(r)
                        server.wfile.write(http1.assemble_request(r))
                        server.wfile.flush()
                        resp = http1.read_response(
                            server.rfile,
                            connect_request,
                            body_size_limit=self.config.body_size_limit
                        )
                        self.flow.response = HTTPResponse.wrap(resp)
                        print ('https resp: %s' % self.flow.response)
                        if resp.status_code != 200:
                            raise ReplayException("Upstream server refuses CONNECT request")
                        server.establish_ssl(
                            self.config.clientcerts,
                            sni=self.flow.server_conn.sni
                        )
                        r.form_out = "relative"
                        return
                    else:
                        if (r.scheme == 'https'):
                        #need to resend CONNECT request and establish before GET
                            print('GET in HTTPS')
                            r.form_out = "authority"
                            connect_request = make_connect_request((r.host, r.port))
                            oldmethod = r.method
                            r.method = 'CONNECT'
                            oldpath = r.path
                            r.path = None
                            server.wfile.write(http1.assemble_request(r))
                            server.wfile.flush()
                            resp = http1.read_response(
                                server.rfile,
                                connect_request,
                                body_size_limit=self.config.body_size_limit
                            )
                            self.flow.response = HTTPResponse.wrap(resp)
                            print ('https resp: %s' % self.flow.response)
                            if resp.status_code != 200:
                                raise ReplayException("Upstream server refuses CONNECT request")
                            #set the old request and change to relative to keep
                            #it under the same host
                            r.method = oldmethod
                            r.path = oldpath
                            r.form_out = 'relative'
                            server.establish_ssl(
                                self.config.clientcerts,
                                sni=self.flow.server_conn.sni
                            )
                            print(r)
                        else:
                            r.form_out = 'absolute'
                else:
                    print("in NOT upstream replay")
                    server_address = (r.host, r.port)
                    server = ServerConnection(server_address, (self.config.host, 0))
                    server.connect()
                    if r.scheme == "https":
                        server.establish_ssl(
                            self.config.clientcerts,
                            sni=self.flow.server_conn.sni
                        )
                    r.form_out = "relative"
                msg = http1.assemble_request(r)
                print('msg: %s' % msg)
                server.wfile.write(msg)
                #print("set current server to flush")
                server.wfile.flush()
                print("set current server to main server_conn")
                print(server)
                self.flow.server_conn = server
                myResponse = http1.read_response(
                    server.rfile,
                    r,
                    body_size_limit=self.config.body_size_limit
                )
                self.flow.response = HTTPResponse.wrap(myResponse)
                print('myresp: %s' % self.flow.response)
                #self.flow.client_conn.send(http1.assemble_response(myResponse))
            if self.channel:
                response_reply = self.channel.ask("response", self.flow)
                if response_reply == Kill:
                    print("raise kill")
                    raise Kill()
        except (ReplayException, HttpException, TcpException) as e:
            self.flow.error = Error(str(e))
            if self.channel:
                self.channel.ask("error", self.flow)
        except Kill:
            # Kill should only be raised if there's a channel in the
            # first place.
            from ..proxy.root_context import Log
            self.channel.tell("log", Log("Connection killed", "info"))
        except Exception as e:
            from ..proxy.root_context import Log
            print(e)
            #self.channel.tell("log", Log(traceback.format_exc(), "error"))
        finally:
            r.form_out = form_out_backup
            print("End Replay Thread")
