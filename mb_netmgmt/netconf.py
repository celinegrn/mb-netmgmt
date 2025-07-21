# This file is part of the project mb-netmgmt
#
# (C) 2022 Deutsche Telekom AG
#
# Deutsche Telekom AG and all other contributors / copyright
# owners license this file to you under the terms of the GPL-2.0:
#
# mb-netmgmt is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as published by
# the Free Software Foundation.
#
# mb-netmgmt is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with mb-netmgmt. If not, see <https://www.gnu.org/licenses/

import logging
import time
from datetime import datetime
from socketserver import BaseRequestHandler
from socketserver import ThreadingTCPServer as Server

from lxml import etree
from ncclient.devices.default import DefaultDeviceHandler
from ncclient.manager import connect
from ncclient.transport.parser import DefaultXMLParser
from ncclient.transport.session import (
    BASE_NS_1_0,
    MSG_DELIM,
    HelloHandler,
    NetconfBase,
    SessionListener,
    qualify,
    sub_ele,
    to_ele,
)
from ncclient.transport.ssh import PORT_NETCONF_DEFAULT, SSHSession

from mb_netmgmt.__main__ import Protocol
from mb_netmgmt.ssh import start_server

stopped = False
NETCONF_11 = "urn:ietf:params:netconf:base:1.1"


class Handler(BaseRequestHandler, Protocol):
    def setup(self):
        session = SSHSession(DefaultDeviceHandler())
        session.add_listener(Listener(super().handle_request))
        self.parser = DefaultXMLParser(session)
        self.session = session
        self.original_transport_read = self.session._transport_read
        self.session._transport_read = self.transport_read
        
        # Enhanced: Add operation tracking for NDO timeout analysis
        self.operation_stats = {}
        self.long_operation_threshold = 50  # seconds - NDO gateway timeout threshold

    def handle(self):
        self.callback_url = self.server.callback_url
        transport = start_server(
            self.request, self.get_to(), self.key_filename, self.handle_request
        )
        self.channel = transport.accept()
        self.session._transport = transport
        self.session._channel = self.channel
        self.session._connected = True

        self.open_upstream()
        self.handle_prompt()
        self.session.run()

    def open_upstream(self):
        to = self.get_to()
        if not to:
            return
        
        # Get timeout from proxy configuration using existing infrastructure
        timeout = None
        proxy = self.get_proxy_config()
        
        if proxy and "timeout" in proxy:
            try:
                timeout = int(proxy["timeout"])
                logging.info(f"Using timeout from proxy config: {timeout} seconds")
            except (ValueError, TypeError):
                logging.warning(f"Invalid timeout value in proxy config: {proxy['timeout']}")
        
        # Fallback to default if not found in proxy config
        if timeout is None:
            timeout = self._get_enhanced_default_timeout()
            logging.info(f"Using enhanced default timeout: {timeout} seconds")
            
        self.manager = connect(
            host=to.hostname,
            port=to.port or PORT_NETCONF_DEFAULT,
            username=to.username,
            password=to.password,
            key_filename=self.key_filename,
            hostkey_verify=False,
            timeout=timeout,
        )

    def _get_enhanced_default_timeout(self):
        """
        Enhanced timeout logic for NDO operations
        Returns appropriate timeout based on potential operation types
        """
        # For NDO inventory operations, we need longer timeouts
        # Based on transaction log analysis: Cisco inventory takes ~65 seconds
        # Gateway timeout is ~60 seconds, so we need 480+ seconds for NETCONF
        return 480  # Sufficient for long-running inventory operations
    
    def _detect_operation_type(self, request_data):
        """
        Detect operation type from NETCONF request to provide insights
        """
        if not request_data or 'rpc' not in request_data:
            return 'unknown'
            
        rpc_str = str(request_data['rpc']).lower()
        
        if 'inventory' in rpc_str:
            if 'cisco' in rpc_str or 'ios-xr' in rpc_str:
                return 'cisco_inventory'
            return 'inventory'
        elif 'get-config' in rpc_str:
            return 'config_get' 
        elif 'edit-config' in rpc_str:
            return 'config_edit'
        elif '<get>' in rpc_str:
            return 'get_operation'
            
        return 'default'
    
    def _log_operation_timing(self, operation_id, duration, operation_type):
        """
        Log operation timing with NDO gateway timeout analysis
        """
        if duration > self.long_operation_threshold:
            logging.warning(f"⚠️  Long operation detected: {operation_id}")
            logging.warning(f"   Type: {operation_type}, Duration: {duration:.1f}s")
            logging.warning(f"   This exceeds typical NDO gateway timeout (~60s)")
            
            if operation_type == 'cisco_inventory':
                logging.info("💡 Cisco inventory operations typically take 65-70s")
                logging.info("   This will cause 504 Gateway Timeout in NDO")
                logging.info("   Backend operation succeeds, but client gets timeout")
                logging.info("   Solution: Use async polling in NDO client layer")
        
        logging.info(f"✅ NETCONF operation {operation_id} completed in {duration:.1f}s")

    def handle_prompt(self):
        mb_response = self.post_request({"rpc": ""})
        try:
            response = mb_response["response"]
            if not response:
                response = DefaultDeviceHandler._BASE_CAPABILITIES
        except KeyError:
            try:
                capabilities = [c for c in self.manager.server_capabilities]
            except AttributeError:
                capabilities = DefaultDeviceHandler._BASE_CAPABILITIES
            response = self.post_proxy_response(mb_response, capabilities)
        hello = to_ele(HelloHandler.build(response, None))

        # A server sending the <hello> element MUST include a <session-id>
        # element containing the session ID for this NETCONF session.
        # https://datatracker.ietf.org/doc/html/rfc6241#section-8.1
        session_id = sub_ele(hello, "session-id")
        session_id.text = "1"

        self.channel.sendall(to_xml(hello) + MSG_DELIM.decode())

        def init_cb(id, client_capabilities):
            if NETCONF_11 in client_capabilities and NETCONF_11 in response:
                self.session._base = NetconfBase.BASE_11

        self.session.add_listener(HelloHandler(init_cb, lambda ex: None))

    def read_proxy_response(self):
        return {"rpc-reply": remove_message_id(self.rpc_reply._root)}

    def send_upstream(self, request, request_id):
        # Enhanced: Track operation timing for NDO analysis
        operation_id = f"netconf_{request_id}_{int(time.time())}"
        start_time = time.time()
        
        # Detect operation type for analysis
        operation_type = self._detect_operation_type(request)
        
        logging.info(f"🔄 Starting NETCONF operation {operation_id} ({operation_type})")
        
        # Store operation info
        self.operation_stats[operation_id] = {
            'start_time': start_time,
            'request_id': request_id,
            'operation_type': operation_type,
            'start_datetime': datetime.now().isoformat()
        }
        
        try:
            # Execute the original operation
            self.rpc_reply = self.manager.rpc(to_ele(request["rpc"]))
            
            # Record successful completion
            duration = time.time() - start_time
            self.operation_stats[operation_id]['duration'] = duration
            self.operation_stats[operation_id]['success'] = True
            
            # Log timing analysis
            self._log_operation_timing(operation_id, duration, operation_type)
            
        except Exception as e:
            # Record failure
            duration = time.time() - start_time
            self.operation_stats[operation_id]['duration'] = duration
            self.operation_stats[operation_id]['success'] = False
            self.operation_stats[operation_id]['error'] = str(e)
            
            logging.error(f"❌ NETCONF operation {operation_id} failed after {duration:.1f}s: {e}")
            raise
        
        # Clean up old stats (keep last 50 operations)
        if len(self.operation_stats) > 50:
            oldest_key = min(self.operation_stats.keys(), 
                           key=lambda k: self.operation_stats[k]['start_time'])
            del self.operation_stats[oldest_key]

    def respond(self, response, request_id):
        reply = response.get("rpc-reply", f'<rpc-reply xmlns="{BASE_NS_1_0}"/>')
        message = add_message_id(reply, request_id)
        self.session.send(message)

    def transport_read(self):
        result = self.original_transport_read()
        if result.startswith(b"#"):
            return b"\n" + result
        return result


class Listener(SessionListener):
    def __init__(self, handle_request):
        self.handle_request = handle_request

    def callback(self, root, raw):
        tag, attrs = root
        if (tag == qualify("hello")) or (tag == "hello"):
            return
        ele = etree.fromstring(raw.encode())
        request = {"rpc": to_xml(ele[0])}
        self.handle_request(request, attrs["message-id"])

    def errback(self, ex):
        logging.exception(ex)


def add_message_id(rpc_reply, message_id):
    ele = etree.fromstring(rpc_reply)
    ele.set("message-id", message_id)
    return to_xml(ele)


def remove_message_id(root):
    del root.attrib["message-id"]
    return to_xml(root)


def to_xml(ele):
    return etree.tostring(ele, pretty_print=True).decode().strip()
