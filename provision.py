#!/usr/bin/python -u

from bluepy import btle
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

found = { "a4:c1:38:8a:5c:52" }

service_uuid = "0000fe95-0000-1000-8000-00805f9b34fb"
step1        = "00000019-0000-1000-8000-00805f9b34fb" # AVDTP
step1plus    = "00000010-0000-1000-8000-00805f9b34fb" # UPNP

def scan():
    scanner = btle.Scanner()

    while True:
      for dev in scanner.scan(1.0):
        if dev.addr not in found:
            continue
        print "Device %s (%s), RSSI=%d dB" % (dev.addr, dev.getValueText(9), dev.rssi)
        if True:
            rawval = ""
            for (adtype, desc, value) in dev.getScanData():
                if desc == "16b Service Data":
                    print "  %s = %s, %s" % ( desc, value, rawval)

setup_data = "\x01\x00"
CMD_GET_INFO = "\xa2\x00\x00\x00"
CMD_SET_KEY  = "\x15\x00\x00\x00"
CMD_SEND_DATA = "\x00\x00\x00\x03\x04\x00"
CMD_WR_DID = "\x00\x00\x00\x00\x02\x00"

RCV_RDY = "\x00\x00\x01\x01"
RCV_OK  = "\x00\x00\x01\x00"
RCV_TOUT= "\x00\x00\x01\x05\x01\x00"

GET_INFO_STATE = 0
SEND_KEY_STATE = 1
RECV_KEY_STATE = 2
WR_DID_STATE = 3
CONFIRM_STATE = 4
FINISHED_STATE = 99

class MiProvision(btle.DefaultDelegate):
    def __init__(self, mac):
        btle.DefaultDelegate.__init__(self)
        self.p = btle.Peripheral(mac)
        self.p.setDelegate(self)
        self.frames = 0
        self.state = GET_INFO_STATE
        self.remote_key_data = None

    def handleNotification(self, cHandle, data):
        # ... perhaps check cHandle
        # ... process 'data'
        frm = ord(data[0]) + 0x100 * ord(data[1])
        print("<-", data.encode("hex"), frm)
        if self.state == GET_INFO_STATE:
            self.info_state_hdlr(frm, data)
        elif self.state == SEND_KEY_STATE:
            self.send_key_hdlr(frm, data)
        elif self.state == RECV_KEY_STATE:
            self.recv_key_hdlr(frm, data)
        elif self.state == WR_DID_STATE:
            self.write_did_hdlr(frm, data)
        elif self.state == CONFIRM_STATE:
            self.confirm_hdlr(frm, data)

    def info_state_hdlr(self, frm, data):
        if frm == 0:
            self.frames = ord(data[4]) + 0x100 * ord(data[5])
            print("expecting",self.frames,"frames")
            self.remote_info_data = ""
            self.bt_write(service_uuid, step1, False, RCV_RDY)
        else:
            self.remote_info_data += data[2:]
        if frm == self.frames:
            print("All frames received")
            print(self.remote_info_data)
            self.bt_write(service_uuid, step1, False, RCV_OK)
            self.state = SEND_KEY_STATE
            self.bt_write(service_uuid, step1plus, False, CMD_SET_KEY)
            self.bt_write(service_uuid, step1, False, CMD_SEND_DATA)

    def send_key_hdlr(self, frm, data):
        if frm == 0:
            if data == RCV_RDY:
                print("Mi ready to receive key")
                self.bt_write_parcel(service_uuid, step1, False, self.my_pub_key_data)
            if data == RCV_TOUT:
                print("Key send timeout")
            if data == RCV_OK:
                print("Mi confirmed key receive")
                self.state = RECV_KEY_STATE

    def recv_key_hdlr(self, frm, data):
        if frm == 0:
            self.frames = ord(data[4]) + 0x100 * ord(data[5])
            print("expecting",self.frames,"frames")
            self.remote_key_data = ""
            self.bt_write(service_uuid, step1, False, RCV_RDY)
        else:
            self.remote_key_data += data[2:]
        if frm == self.frames:
            print("All frames received")
            print(self.remote_key_data.encode("hex"))
            self.bt_write(service_uuid, step1, False, RCV_OK)
            self.state = WR_DID_STATE

    def write_did_hdlr(self, frm, data):
        if frm == 0:
            if data == RCV_RDY:
                print("Mi ready to receive did")
                self.bt_write_parcel(service_uuid, step1, False, self.did_ct)
            if data == RCV_TOUT:
                print("Did send timeout")
            if data == RCV_OK:
                print("Mi confirmed did receive")
                self.state = CONFIRM_STATE
                self.bt_write(service_uuid, step1plus, False, "\x13\x00\x00\x00")

    def confirm_hdlr(self, frm, data):
        if frm == 17:
            print("Mi auth confirmed")
        else:
            print("Mi auth FAILED!")
        self.state = FINISHED_STATE

    def bt_write(self, serv, char, resp, data):
        print("->", data.encode("hex"))
        svc = self.p.getServiceByUUID(serv)
        ch = svc.getCharacteristics(char)[0]
        #time.sleep(3)
        ch.write(data, resp)
    
    def bt_write_parcel(self, serv, char, resp, data):
        chunk_size = 18
        chunks = len(data)
        chunks = [ data[i:i+chunk_size] for i in range(0, chunks, chunk_size) ]

        i = 1
        for chunk in chunks:
            chunk = chr(i) + "\00" + chunk
            self.bt_write(serv, char, resp, chunk)
            i += 1

    def generate_private_key(self):
        #my_private_key = ec.derive_private_key(
        #    92,
        #    ec.SECP256R1(), 
        #    default_backend())
        my_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        #x = 0x77c5c00b90468cdc1ff7aff9e32c98b359742cfa773accf4cb085ebe52e5ac28
        #y = 0x2b1be2fd1b413a2747797e96b95bf080839c39424688190c4ebe78605ad9e2dc
        #private_value = 0x8D99937D1DD07BAB12CD2C02F4BC08F30A8B30E0D9E17050D7EEF3DC4654A538
        #public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        #ecprn = ec.EllipticCurvePrivateNumbers(private_value, public_numbers)
        #my_private_key = ecprn.private_key(default_backend())
        print(my_private_key)
        return my_private_key

    def encode_pub_key(self, pub_key):
        xy = pub_key.public_numbers()
        hex_x = hex(xy.x)[2:-1]
        hex_y = hex(xy.y)[2:-1]
        print(xy.x, hex_x)
        print(xy.y, hex_y)

        pub_key_data = (64-len(hex_x))*'0' + hex_x + (64-len(hex_y))*'0' + hex_y
        print(pub_key_data)
        return pub_key_data

    def decode_pub_key(self, data):
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), chr(0x04)+data)

    def create_e_share_key(self, pub_key, private_key):
        return private_key.exchange(ec.ECDH(), pub_key)


    def configure(self):
        my_private_key = self.generate_private_key()
        self.my_pub_key_data = self.encode_pub_key(my_private_key.public_key())
    
        self.bt_write(service_uuid, step1, True, "\x01\x00")
        self.bt_write(service_uuid, step1plus, True, "\x01\x00")
        self.bt_write(service_uuid, step1plus, False, CMD_GET_INFO)

        while self.state != WR_DID_STATE:
            if self.p.waitForNotifications(1.0):
                # handleNotification() was called
                continue
    
            print "Waiting..."
            # Perhaps do something else here
        remote_key = self.decode_pub_key(self.remote_key_data)
        e_share_key = self.create_e_share_key(remote_key, my_private_key)
        print("eShareKey:", e_share_key.encode("hex"))

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'mible-setup-info',
            backend=default_backend()
            ).derive(e_share_key)
        print("HKDF result:", derived_key.encode("hex"))
        token = derived_key[0:12]
        bind_key = derived_key[12:28]
        A = derived_key[28:44]
        print("token:", token.encode("hex"))
        print("bind_key:", bind_key.encode("hex"))
        print("A:", A.encode("hex"))

        aesccm = AESCCM(A)
        nonce = bytearray([16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27])
        did = "blt.3.129vl4ap05o01".encode()
        aad = "devID".encode()
        self.did_ct = aesccm.encrypt(nonce, did, aad)

        print("AES did CT:", self.did_ct.encode("hex"))

        self.bt_write(service_uuid, step1, False, CMD_WR_DID)

        while self.state != FINISHED_STATE:
            if self.p.waitForNotifications(1.0):
                # handleNotification() was called
                continue
    
            print "Waiting..."
            # Perhaps do something else here


#scan()
mp = MiProvision("a4:c1:38:8a:5c:52")
mp.configure()

