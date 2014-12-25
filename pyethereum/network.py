#!/usr/bin/env python
"""
Services:

    P2PManager

Reactive:
    Peer
    protocol



"""
import sys
import time
import signal
import gevent
import socket
import struct
import json
from gevent.server import StreamServer
from gevent.event import Event
from gevent import Greenlet
from gevent.socket import create_connection, gethostbyname
from gevent.backdoor import BackdoorServer
import slogging
log = slogging.get_logger().warn

def on_exit_signals(thread_method, *args):
    gevent.signal(signal.SIGQUIT,thread_method, *args)
    gevent.signal(signal.SIGTERM, thread_method, *args)
    gevent.signal(signal.SIGINT, thread_method, *args)

# packetize

header_length = 5

def decode_packet_header(message):
    header = message[:header_length]
    payload_len, cmd_id = struct.unpack('>BL', header)
    return payload_len, cmd_id

def encode_packet(cmd_id, data):
    payload = json.dumps(data)
    header = struct.pack('>BL', len(payload), cmd_id)
    assert len(header) == header_length
    return header + payload


class BaseProtocol(object):
    """
    Component which translates between
        messages from the p2p wire
        and services

    Keeps necessary state for the peer
        e.g. last ping, sent/received hashes, ...


    """
    name = ''
    cmd_map = {} # cmd_name: cmd_id

    def __init__(self, peer, cmd_offset=0):
        self.peer = peer
        self.cmd_offset = cmd_offset
        self.cmd_map = dict((k, v + cmd_offset) for k,v in self.cmd_map.items())
        self.rev_cmd_map = dict((v,k) for k,v in self.cmd_map.items())

    def handle_message(self, cmd_id, payload):
        data = json.loads(payload)
        cmd_name = 'receive_%s' % self.rev_cmd_map[cmd_id]
        cmd = getattr(self, cmd_name)
        cmd(json.loads(payload))

    def stop(self):
        "called when peer disconnects, use to cleanup"
        pass


class ETHProtocol(BaseProtocol):
    name = 'eth'
    cmd_map = dict(status=0)
    status_sent = False
    status_received = False

    def send_status(self):
        data = dict(head_number=1,
                    eth_version=49)
        packet = encode_packet(self.cmd_map['status'], data)
        self.peer.send_packet(packet)
        self.status_sent = True

    def receive_status(self, data):
        # tell p2pmanager about spoken protocols
        if not self.status_sent:
            self.send_status()
        self.status_received = True


class SHHProtocol(BaseProtocol):
    name = 'shh'
    cmd_map = dict(gossip=0)

    def send_gossip(self, gossip=''):
        data = dict(gossip=gossip)
        packet = encode_packet(self.cmd_map['gossip'], data)
        self.peer.send_packet(packet)

    def receive_gossip(self, data):
        pass


class ConnectionMonitor(Greenlet):
    ping_interval = 1.
    response_delay_threshold = 2.
    max_samples = 10

    def __init__(self, p2pprotocol):
        Greenlet.__init__(self)
        self.p2pprotocol = p2pprotocol
        self.samples = []
        self.last_request = time.time()
        self.last_response = time.time()
        on_exit_signals(self.stop)

    def __repr__(self):
        return '<ConnectionMonitor(r)>'

    def track_request(self):
        self.last_request = time.time()

    def track_response(self):
        self.last_response = time.time()
        dt = self.last_response - self.last_request
        self.samples.append(dt)
        if len(self.samples) > self.max_samples:
            self.samples.pop(0)

    @property
    def last_response_elapsed(self):
        return time.time() - self.last_response

    @property
    def latency(self, num_samples=0):
        if not self.samples:
            return None
        num_samples = min(num_samples or self.max_samples, len(self.samples))
        return sum(self.samples[:num_samples])/num_samples

    def _run(self):
        log('p2p.peer.monitor.started', monitor=self)
        while True:
            log('p2p.peer.monitor.pinging', monitor=self)
            self.p2pprotocol.send_ping()
            gevent.sleep(self.ping_interval)
            log('p2p.peer.monitor.latency', monitor=self, latency=self.latency)
            if self.last_response_elapsed > self.response_delay_threshold:
                log('p2p.peer.monitor.unresponsive_peer', monitor=self)
                self.stop()

    def stop(self):
        self.kill()

class P2PProtocol(BaseProtocol):
    name = 'p2p'
    cmd_map = dict(hello=0, ping=1, pong=2, disconnect=3)

    def __init__(self, peer, cmd_offset, is_inititator=False):
        super(P2PProtocol, self).__init__(peer, cmd_offset)
        self.is_inititator = is_inititator
        self.connection_monitor = ConnectionMonitor(self)
        self._handshake()

    def stop(self):
        self.connection_monitor.stop()

    def _handshake(self):
        if self.is_inititator:
            self.send_hello()

    def send_hello(self):
        log('p2p.send_hello', peer=self.peer)
        capabilities = [p.name for p in self.peer.protocols]
        data = dict(capabilities=capabilities,
                    version=1)
        packet = encode_packet(self.cmd_map['hello'], data)
        self.peer.send_packet(packet)

    def receive_hello(self, data):
        log('p2p.receive_hello', peer=self.peer)
        # tell p2pmanager about spoken protocols
        self.peer.p2pmanager.on_hello_received(self, data)
        if not self.is_inititator:
            self.send_hello()
        self.connection_monitor.start()

    def send_ping(self):
        log('p2p.send_ping', peer=self.peer)
        packet = encode_packet(self.cmd_map['ping'], dict())
        self.peer.send_packet(packet)
        self.connection_monitor.track_request()

    def receive_ping(self, data):
        log('p2p.receive_ping', peer=self.peer)
        self.send_pong()

    def send_pong(self):
        log('p2p.send_pong', peer=self.peer)
        packet = encode_packet(self.cmd_map['pong'], dict())
        self.peer.send_packet(packet)

    def receive_pong(self, data):
        log('p2p.receive_pong', peer=self.peer)
        self.connection_monitor.track_response()


    def send_disconnect(self, reason=''):
        log('p2p.send_disconnect', peer=self.peer, reason=reason)
        packet = encode_packet(self.cmd_map['disconnect'], dict(reason=reason))
        self.peer.send_packet(packet)
        self.peer.stop()

    def receive_disconnect(self, data):
        log('p2p.receive_disconnect', peer=self.peer, reason=data.get('reason'))
        self.peer.stop()


class Peer(object):
    """
    After creation:
        register peer protocol
        send hello & encryption
        receive hello & derive session key
        register in common protocols

        receive data
            decrypt, check auth
            decode packet id
            lookup handling protocol
            pass packet to protocol

        send packet
            encrypt
    """
    known_protocols = [P2PProtocol, ETHProtocol]

    def __init__(self, p2pmanager, connection):
        self.p2pmanager = p2pmanager
        self.connection = connection
        self.protocols = []
        self._buffer = ''
        log('peer init', peer=self)

    def __repr__(self):
        return '<Peer(%r) thread=%r>' % (self.connection.getpeername(), id(gevent.getcurrent()))

    # protocols

    def register_protocol(self, protocol):
        """
        registeres protocol with peer, which will be accessible as
        peer.<protocol.name> (e.g. peer.p2p or peer.eth)
        """
        log('registering protocol', protocol=protocol.name, peer=self)
        self.protocols.append(protocol)
        setattr(self, protocol.name, protocol)

    def protocol_by_cmd_id(self, cmd_id):
        max_id = 0
        for p in self.protocols:
            max_id += len(p.cmd_map)
            if cmd_id < max_id:
                return p
        raise Exception('no protocol for id %s' % cmd_id)

    def has_protocol(self, name):
        return hasattr(self, name)


    # receiving p2p mesages

    def _handle_packet(self, cmd_id, payload):
        log('handling packet', cmd_id=cmd_id, peer=self)
        protocol = self.protocol_by_cmd_id(cmd_id)
        protocol.handle_message(cmd_id, payload)


    def _data_received(self, data):
        self._buffer += data
        while len(self._buffer):
            # read packets from buffer
            payload_len, cmd_id = decode_packet_header(self._buffer)
            # check if we have a complete message
            if len(self._buffer) >= payload_len + header_length:
                payload = self._buffer[header_length:payload_len + header_length]
                self._buffer = self._buffer[payload_len + header_length:]
                self._handle_packet(cmd_id, payload)
            else:
                break

    def send_packet(self, data):
        log('peer.send_packet', size=len(data))
        self.connection.sendall(data)
        log('peer.send_packet sent', size=len(data))

    def loop_socket(self):
        while True:
            log('peer.loop_socket.wait', peer=self)
            data = self.connection.recv(4096)
            log('peer.loop_socket.received', size=len(data), peer=self)
            if not data:
                log('peer.loop_socket.not_data', peer=self)
                self.stop()
                break
            self._data_received(data)

    def stop(self):
        log('stopped', thread=gevent.getcurrent())
        for p in self.protocols:
            p.stop()
        self.p2pmanager.peers.remove(self)


class P2PManager(object):
    """
    spawns listening server
        on connect spawns new peer
            on peer Hello adds services to peer

    keeps track of peers
    connects new peers if there are too few
    selects peers based on a DHT
    keeps track of peer reputation
    saves/loads peers to disc

    protocols handling:
        peer manager

    """
    def __init__(self, config=dict()):
        log('P2PManager init', config=config)

        # peers
        self.peers = []

        # start a listening server
        host, port = config.get('listen_address')
        while True:
            try:
                server = StreamServer((host,port), self._handle_new_connection)
                server.start()
            except socket.error:
                port+=1
            finally:
                break
        log('server setup', server=server)

        self.server = server
        log('server started', server=server)
        on_exit_signals(server.stop)

    def __repr__(self):
        return '<P2PManager>'

    def on_hello_received(self, p2pprotocol, data):
        log('p2p.manager.hello_reveived', peer=p2pprotocol.peer)
        # register more protocols


    def _handle_new_connection(self, connection, address, is_inititator=False):
        log('p2p.manager.handle_connect', connection=connection)
        # register exit
        on_exit_signals(gevent.getcurrent().kill)
        # create peer
        peer = Peer(self, connection)
        log('p2p.manager.handle_connect.created peer', peer=peer)
        # register p2p protocol
        p2pprotocol = P2PProtocol(peer, cmd_offset=0, is_inititator=is_inititator)
        log('p2p.manager.handle_connect.created protocol', protocol=p2pprotocol)
        peer.register_protocol(p2pprotocol)
        log('p2p.manager.handle_connect.registered protocol')
        self.peers.append(peer)
        log('p2p.manager.handle_connect.added peer to list')
        # loop
        peer.loop_socket()
        log('p2p.manager.handle_connect.looped socket')

    def connect(self, address):
        log('p2p.manager.connect', address=address)
        """
        gevent.socket.create_connection(address, timeout=Timeout, source_address=None)
        Connect to address (a 2-tuple (host, port)) and return the socket object.
        Passing the optional timeout parameter will set the timeout
        getdefaulttimeout() is default
        """
        connection = create_connection(address)
        gevent.spawn(self._handle_new_connection, connection, address, is_inititator=True)

def main():
    import sys
    config = dict(listen_address=('localhost', 30303))
    if len(sys.argv) > 1:
        h, p = sys.argv[1].split(':')
        config.update(dict(remote_endpoint=(h, int(p))))

    p2pmanager = P2PManager(config=config)

    # connect remote
    if 'remote_endpoint' in config:
        p2pmanager.connect(config.get('remote_endpoint'))

    if False:
        backdoor = BackdoorServer('127.0.0.1:40404', locals=locals())
        on_exit_signals(backdoor.close)
        backdoor.start()

    gevent.wait()

if __name__ == '__main__':
    main()

