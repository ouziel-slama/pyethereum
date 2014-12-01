#!/usr/bin/python
import pyelliptic
from utils import sha3

def privkey(passphrase):
    return sha3(passphrase)[:40] # DONT!

class Peer(object):

    curve = 'sect571r1'
    ciphername = 'aes-256-cbc'

    def __init__(self, privkey):
        # local key set
        self.ecc = pyelliptic.ECC(privkey=privkey, curve=self.curve)

        # persisted peer data. keys are the peer address/id
        self.pubkey_by_peer = dict()
        self.token_by_peer = dict()

        # session data
        self.ephemeral_ecc_by_peer = dict()
        self.shared_secret_by_peer = dict()
        self.acknowledged_peers = set()

    @property
    def pubkey(self):
        return self.ecc.get_pubkey()

    @property
    def address(self):
        "A node's address is right160(sha3(public-key))"
        return sha3(self.pubkey)[-20:]

    def connect(self, other):
        self.present_authentication(other)

    def disconnect(self, other):
        self.acknowledged_peers.remove(other)
        del self.ephemeral_ecc_by_peer[other]
        del self.shared_secret_by_peer[other]

    def send(self, other, data):
        self.other.recv(data)

    def present_authentication(self, other, seed=None):
        """
        PresentAuthentication (frame):
        E(pubk, addr || sign(privkey, sha3(token || addr^addrRemote)) || ecdhe-pubk)

        previously-known peer
        token = knownPeers.find(remoteAddress).token
        introduced peer or peer from DHT:
        token = ecdhe-pubk
        """
        remote_pubkey = other.pubkey # from DHT or introduced or web
        if seed:
            seed = privkey(seed)
        ephemeral_ecc = pyelliptic.ECC(curve=self.curve, privkey=seed)
        ecdhe_pubkey = ephemeral_ecc.get_pubkey()
        self.ephemeral_ecc_by_peer[remote_pubkey] = ephemeral_ecc
        address = self.address
        remote_address = other.address

        token = self.token_by_peer.get(other.pubkey, ecdhe_pubkey)
        #  (addr || sign(privkey, sha3(token || addr^addrRemote)) || ecdhe-pubk)
        data = address + self.ecc.sign(sha3(token + address + remote_address)) + ecdhe_pubkey
        ciphertext = encrypt(data, remote_pubkey, ephemcurve=self.curve, ciphername=self.ciphername)

        # send data
        self.send(other, data)


    def verify_authentication(self, other, ciphertext):
        """
        Verification (function, upon receive of PresetAuthentication):
        - If address is known, lookup token and public key to be authenticated
        - else, token is remote-ecdhe-pubk and extracted public will be used
        - derive signature-message = sha3(token || addr^addrRemote)
        - verify auth addr == address(extracted public key), else disconnect
        - success -> AcknowledgeAuthentication
        """
        data = decrypt(ciphertext ciphername=self.ciphername):
        remote_address = data[:20]
        signature = data[20:20+32]
        remote_ecdhe_pubkey = data[20+32:]


        if remote_address in self.token_by_peer:
            # - If address is known, lookup token and public key to be authenticated
            token = self.token_by_peer[remote_address]
            remote_pubkey = pubkey_by_peer[remote_address]
        else:
            # - else, token is remote-ecdhe-pubk and extracted public will be used
            token = remote_ecdhe_pubkey
            remote_pubkey = other.pubkey # FIXME: how to extract remote_publickey ???

        # - derive signature-message = sha3(token || addr^addrRemote)
        signed_data = sha3(token + remote_address + address)
        # - verify auth addr == address(extracted public key), else disconnect
        # translation:
        #   verify that the signed address matches the address we extracted
        #       and that the address belongs to the extracted (FIXME!) pub_key
        if not pyelliptic.ECC(pubkey=remote_pubkey).verify(signature, signed_data):
            self.disconnect(other)

        # - success -> AcknowledgeAuthentication
        self.acknowledge_authentication(other, remote_pubkey, remote_ecdhe_pubkey)

    def acknowledge_authentication(self, other, remote_pubkey, remote_ecdhe_pubkey):
        """
        AcknowledgeAuthentication (frame):
            E(pubk, addr || sign(privkey, sha3(token || addr^addrRemote)) || ecdhe-pubk)

        SYNACK (function, upon tx or rx of AcknowledgeAuthentication):
            shared-secret = ecdh.agree(pubkey,pubkey-remote)
            shared-secret = sha3(shared-secret || ecdhe.agree(ecdhe-pubk,echde-pubk-remote))
            token = sha3(shared-secret || sha3(ecdhe-pubk)^sha3(ecdhe-pubk-remote))
            knownPeers.update(addr, token)
            aes-encrypt-secret = shared-secert[0..127]
            aes-mac-secret = shared-secret[128..255]
            first-message = sha3(ecdhe-pubk^echde-pubk-remote)
        """
        # new ephemeral
        ephemeral_ecc = pyelliptic.ECC(curve=self.curve, privkey=None)
        self.ephemeral_ecc_by_peer[other.address] = ephemeral_ecc
        ephemeral_pubkey = ephemeral_ecc.get_pubkey()

        # shared secret
        # Q: Why is this better than just hashing the mixed ephemerals?
        shared_secret = self.ecc.get_ecdh_key(self.pubkey, remote_pubkey)
        shared_secret = sha3(shared_secret + self.ecc.get_ecdh_key(ephemeral_pubkey, remote_ecdhe_pubkey))
        assert len(shared_secret) == 256
        aes_encrypt_secret = shared_secret[:128]
        aes_mac_secret = shared_secret[128:]
        # new token
        token = sha3(shared_secret + sha3(ephemeral_pubkey) + sha3(remote_ecdhe_pubkey))
        self.token_by_peer[remote_address] = token

        # TBC TBC TBC


        """
        As soon as Auth, Verification, and AckAuth are received by either side, 
        that side will immediately send up to 64 kilobytes of raw (wireline) data and will not wait for the other side. 
        As soon as each side successfully decrypts and authenticates the first message 
        they will update token to sha3(token || first-message). 
        A connection must not send more than 64 kilobytes of data until the first message passes authentication.
        """


    def recv(self, other, data):
        if other not in acknowledged_peers:
            self.verify_authentication(other, data)
        else:
            # decrypt data
            pass


