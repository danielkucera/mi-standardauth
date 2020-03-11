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
RCV_RDY = "\x00\x00\x01\x01"
RCV_OK  = "\x00\x00\x01\x00"
RCV_TOUT= "\x00\x00\x01\x05\x01\x00"

GET_INFO_STATE = 0
SET_KEY_STATE = 1

class MiProvision(btle.DefaultDelegate):
    def __init__(self, mac):
        btle.DefaultDelegate.__init__(self)
        self.p = btle.Peripheral(mac)
        self.p.setDelegate(self)
        self.frames = 0
        self.state = GET_INFO_STATE

    def handleNotification(self, cHandle, data):
        # ... perhaps check cHandle
        # ... process 'data'
        frm = ord(data[0]) + 0x100 * ord(data[1])
        print("frm", frm)
        print(data.encode("hex"))
        if self.state == GET_INFO_STATE:
            self.info_state_hdlr(frm, data)
        if self.state == SET_KEY_STATE:
            self.set_key_hdlr(frm, data)

    def info_state_hdlr(self, frm, data):
        if frm == 0:
            self.frames = ord(data[4]) + 0x100 * ord(data[5])
            print("expecting",self.frames,"frames")
            self.bt_write(service_uuid, step1, False, RCV_RDY)
        if frm == self.frames:
            print("All frames received")
            self.bt_write(service_uuid, step1, False, RCV_OK)
            self.state = SET_KEY_STATE
            self.bt_write(service_uuid, step1plus, False, CMD_SET_KEY)
            self.bt_write(service_uuid, step1, False, "\x00\x00\x00\x03\x04\x00")

    def set_key_hdlr(self, frm, data):
        if frm == 0:
            if data == RCV_RDY:
                print("Mi ready to receive key")
            if data == RCV_TOUT:
                print("Key send timeout")

    def bt_write(self, serv, char, resp, data):
        svc = self.p.getServiceByUUID(serv)
        ch = svc.getCharacteristics(char)[0]
        #time.sleep(3)
        ch.write(data, resp)
    

    def configure(self):
    
        self.bt_write(service_uuid, step1, True, "\x01\x00")
        self.bt_write(service_uuid, step1plus, True, "\x01\x00")
        self.bt_write(service_uuid, step1plus, False, CMD_GET_INFO)
    
        while True:
            if self.p.waitForNotifications(1.0):
                # handleNotification() was called
                continue
    
            print "Waiting..."
            # Perhaps do something else here
    
#scan()
mp = MiProvision("a4:c1:38:8a:5c:52")
mp.configure()

