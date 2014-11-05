from . import AuthChannel, _messages, send as _send, hkdf_expand, mac, Message, ascii_bin

import json
import os
import quopri
import socket
from functools import partial


class NUTSClient(object):

    def __init__(self, shared_key):
        self.shared_key = shared_key
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


    def send(self, msg):
        _send(self.id_b, self.id_a, msg)
        #conn.receive(_messages[-1])
        sent = self.socket.sendto(msg, self.server)

        print 'Sent to server:', sent

        # Receive response
        data, server = self.socket.recvfrom(10240)
        return data


    def connect(self, server):
        """ Establish a connection to the server. `server` should be a (ip, port) tuple. """
        self.id_a = '%s:%d' % server
        self.server = server
        self.auth_channel = AuthChannel(self.id_a, shared_key)
        self.send_client_hello()


    def send_client_hello(self):

        # Initialize R_b
        self.R_b = os.urandom(8)

        m0 = '\x00' + self.R_b
        m0_digest = mac(shared_key, id_a + id_b + m0)
        response = self.send(m0 + m0_digest)

        # First message from sat should be 128 bits + 1 byte msg type, and should verify the identify of the sat
        assert response[0] == '\x80'
        assert len(response) == 17
        #assert _messages[-1].dest == id_b

        m1_mac_input = id_a + id_b + response[:-8] + self.R_b
        expected_m1_digest = self.mac(shared_key, m1_mac_input)

        # Message digest should be correct
        assert _messages[-1].msg[-8:] == expected_m1_digest

        # Prove our knowledge of shared_key, and send a SA proposal
        R_a = _messages[-1].msg[1:9]

        sa_proposal = {
            'macs': ['sha3_512'],
            'mac_len': 8,
        }

        m2 = '\x01' + json.dumps(sa_proposal)
        m2_mac_input = id_a + id_b + m2 + _messages[-1].msg[1:9]
        m2_digest = mac(shared_key, m2_mac_input)
        send(m2 + m2_digest)

        # SA response
        proposal_response_raw, sig = _messages[-1].msg[:-8], _messages[-1].msg[-8:]

        # Verify sig
        assert sig == mac(shared_key, id_a + id_b + proposal_response_raw + R_a + R_b)

        proposal_response = json.loads(proposal_response_raw[1:])


        # Should agree on sha3_512
        assert proposal_response['mac'] == 'sha3_512'

        # Should agree on 8 byte sigs
        assert proposal_response['mac_len'] == 8

        session_key = hkdf_expand(shared_key + R_a + R_b, length=16)
        s_seq = c_seq = 1

def conn_mac(message):
    return mac(session_key, id_a + id_b + message + str(c_seq),
        algo=proposal_response['mac'],
        mac_len=proposal_response['mac_len'])

# Send first actual command
cmd = {'cmd': 'TakePicture'}
cmd_msg = '\x02' + json.dumps(cmd)
send(cmd_msg + conn_mac(cmd_msg))

# Expect ACK
ack, sig = _messages[-1].msg[-8:], _messages[-1].msg[-8:]


c_seq += 1
