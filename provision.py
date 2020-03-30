#!/usr/bin/python -u

from bluepy import btle
import time

found = {}

service_uuid = "0000fe95-0000-1000-8000-00805f9b34fb"
step1        = "00000019-0000-1000-8000-00805f9b34fb" # AVDTP
step1plus    = "00000010-0000-1000-8000-00805f9b34fb" # UPNP

def scan():
    scanner = btle.Scanner()

    while True:
	devices = scanner.scan(1.0)	
	for dev in devices:
            if dev.addr in found:
                continue
            found[dev.addr] = dev
	    print "Device %s (%s), RSSI=%d dB" % (dev.addr, dev.getValueText(9), dev.rssi)
	    if True:
		    for (adtype, desc, value) in dev.getScanData():
			rawval = ""
		        #print "  %s = %s, %s" % ( desc, value, rawval)

setup_data = "\x01\x00"
CMD_GET_INFO = "\xa2\x00\x00\x00"
CMD_SET_KEY  = "\x15\x00\x00\x00"
CMD_SEND_DATA = "\x00\x00\x00\x03\x04\x00"
RCV_RDY = "\x00\x00\x01\x01"
RCV_OK  = "\x00\x00\x01\x00"
RCV_TOUT= "\x00\x00\x01\x05\x01\x00"

TEST_PUB_KEY="F99DC8A7D6660E40D2171BDA2D7DD7D86613F13FFAE9FAAD27067D1631098FA86EA12F57842DBFF9248CAF9A7CCC3C4EFADBB79203C55F4D4247499FFD910FF6".decode("hex")

GET_INFO_STATE = 0
SEND_KEY_STATE = 1
RECV_KEY_STATE = 2
FINISHED_STATE = 99

class MiProvision(btle.DefaultDelegate):
    def __init__(self, mac):
        btle.DefaultDelegate.__init__(self)
        self.p = btle.Peripheral(mac)
        self.p.setDelegate(self)
        self.frames = 0
        self.state = GET_INFO_STATE
        self.remote_key = None

    def handleNotification(self, cHandle, data):
        # ... perhaps check cHandle
        # ... process 'data'
        frm = ord(data[0]) + 0x100 * ord(data[1])
        print("frm", frm)
        print(data.encode("hex"))
        if self.state == GET_INFO_STATE:
            self.info_state_hdlr(frm, data)
        elif self.state == SEND_KEY_STATE:
            self.send_key_hdlr(frm, data)
        elif self.state == RECV_KEY_STATE:
            self.recv_key_hdlr(frm, data)

    def info_state_hdlr(self, frm, data):
        if frm == 0:
            self.frames = ord(data[4]) + 0x100 * ord(data[5])
            print("expecting",self.frames,"frames")
            self.bt_write(service_uuid, step1, False, RCV_RDY)
        if frm == self.frames:
            print("All frames received")
            self.bt_write(service_uuid, step1, False, RCV_OK)
            self.state = SEND_KEY_STATE
            self.bt_write(service_uuid, step1plus, False, CMD_SET_KEY)
            self.bt_write(service_uuid, step1, False, CMD_SEND_DATA)

    def send_key_hdlr(self, frm, data):
        if frm == 0:
            if data == RCV_RDY:
                print("Mi ready to receive key")
                self.bt_write_parcel(service_uuid, step1, False, TEST_PUB_KEY)
            if data == RCV_TOUT:
                print("Key send timeout")
            if data == RCV_OK:
                print("Mi confirmed key receive")
                self.state = RECV_KEY_STATE

    def recv_key_hdlr(self, frm, data):
        if frm == 0:
            self.frames = ord(data[4]) + 0x100 * ord(data[5])
            print("expecting",self.frames,"frames")
            self.remote_key = ""
            self.bt_write(service_uuid, step1, False, RCV_RDY)
        else:
            self.remote_key += data[2:]
        if frm == self.frames:
            print("All frames received")
            print(self.remote_key.encode("hex"))
            self.bt_write(service_uuid, step1, False, RCV_OK)
            self.state = FINISHED_STATE

    def bt_write(self, serv, char, resp, data):
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
            print(chunk.encode("hex"))
            self.bt_write(serv, char, resp, chunk)
            i += 1


    def configure(self):
    
        self.bt_write(service_uuid, step1, True, "\x01\x00")
        self.bt_write(service_uuid, step1plus, True, "\x01\x00")
        self.bt_write(service_uuid, step1plus, False, CMD_GET_INFO)

        while self.state != FINISHED_STATE:
            if self.p.waitForNotifications(1.0):
                # handleNotification() was called
                continue
    
            print "Waiting..."
            # Perhaps do something else here
    
#scan()
mp = MiProvision("a4:c1:38:8a:5c:52")
mp.configure()

