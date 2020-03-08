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

p = btle.Peripheral("a4:c1:38:8a:5c:52")

class MyDelegate(btle.DefaultDelegate):
    def __init__(self):
        btle.DefaultDelegate.__init__(self)
        # ... initialise here

    def handleNotification(self, cHandle, data):
        # ... perhaps check cHandle
        # ... process 'data'
        if data == "\x00\x00\x00\x00\x02\x00":
            bt_write(service_uuid, step1, False, "\x00\x00\x01\x01")
        print(data.encode("hex"))

def bt_write(serv, char, resp, data):
    svc = p.getServiceByUUID(serv)
    ch = svc.getCharacteristics(char)[0]
    #time.sleep(3)
    ch.write(data, resp)

p.setDelegate( MyDelegate() )

def configure():

    bt_write(service_uuid, step1, True, "\x01\x00")
    bt_write(service_uuid, step1plus, True, "\x01\x00")
    bt_write(service_uuid, step1plus, False, "\xa2\x00\x00\x00")

    while True:
        if p.waitForNotifications(1.0):
            # handleNotification() was called
            continue

        print "Waiting..."
        # Perhaps do something else here

#scan()
configure()
