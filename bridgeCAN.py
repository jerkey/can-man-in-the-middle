#!/bin/env python3
import socket
import struct
import os
import curses
import time

XaltVoltage = 6 # placeholder for voltage reported by Xalt battery
XaltHeartbeatCounter = 0 # gets incremented with each message, rolls over after 7

canstarttime = 0.0 # this gets set to present time upon the first CAN message arrival

last1Hz = 0.0
last2Hz = 0.0
last10Hz = 0.0

screen = curses.initscr()
screen.addstr(0,10,"Hit 'z' to quit")
screen.refresh()
screen.nodelay(1)  # https://stackoverflow.com/questions/14004835/nodelay-causes-python-curses-program-to-exit
screen.scrollok(True) # allow gcode to scroll screen

BMSrequest = False          # what the bus is asking for
ContactorsState = False     # whether we've ordered the contactors closed/true/hot/powered or not
ContactorOrderedTrueTime = 0# what time we told them to close (so we know how long to wait

def sprnt(texttoprnt):
    screen.addstr(texttoprnt+'\n\r')
    screen.refresh()

canformat = '<IB3x8s'
can_frame_fmt = "=IB3x8s" # from https://python-can.readthedocs.io/en/1.5.2/_modules/can/interfaces/socketcan_native.html

#From https://github.com/torvalds/linux/blob/master/include/uapi/linux/can.h
#special address description flags for the CAN_ID
CAN_EFF_FLAG = 0x80000000 #EFF/SFF is set in the MSB
CAN_RTR_FLAG = 0x40000000 #remote transmission request
CAN_ERR_FLAG = 0x20000000 #error message frame

#valid bits in CAN ID for frame formats
CAN_SFF_MASK = 0x000007FF # /* standard frame format (SFF) */
CAN_EFF_MASK = 0x1FFFFFFF # /* extended frame format (EFF) */
CAN_ERR_MASK = 0x1FFFFFFF # /* omit EFF, RTR, ERR flags */

#
# Controller Area Network Identifier structure
#
# bit 0-28 : CAN identifier (11/29 bit)
# bit 29   : error message frame flag (0 = data frame, 1 = error message)
# bit 30   : remote transmission request flag (1 = rtr frame)
# bit 31   : frame format flag (0 = standard 11 bit, 1 = extended 29 bit)
#

#
# Controller Area Network Error Message Frame Mask structure
#
# bit 0-28 : error class mask (see include/linux/can/error.h)
# bit 29-31    : set to zero
#


#
# struct can_frame - basic CAN frame structure
# @can_id:  CAN ID of the frame and CAN_*_FLAG flags, see canid_t definition
# @can_dlc: frame payload length in byte (0 .. 8) aka data length code
          # N.B. the DLC field from ISO 11898-1 Chapter 8.4.2.3 has a 1:1
          # mapping of the 'data length code' to the real payload length
# @__pad:   padding
# @__res0:  reserved / padding
# @__res1:  reserved / padding
# @data:    CAN frame payload (up to 8 byte)
#

# /* particular protocols of the protocol family PF_CAN */
# CAN_RAW     1 /* RAW sockets */
# CAN_BCM     2 /* Broadcast Manager */
# CAN_TP16    3 /* VAG Transport Protocol v1.6 */
# CAN_TP20    4 /* VAG Transport Protocol v2.0 */
# CAN_MCNET   5 /* Bosch MCNet */
# CAN_ISOTP   6 /* ISO 15765-2 Transport Protocol */
# CAN_NPROTO  7


class CanBridge():
    def __init__(self, interface_vehicle, interface_BMS,bitrate_to,bitrate_from):
        #set CAN bit rates. Must have super user privilages.
        #os.system('sudo ip link set {} down'.format(interface_vehicle))
        #os.system('sudo ip link set {} type can bitrate {}'.format(interface_vehicle, bitrate_from))
        #os.system('sudo ip link set {} up'.format(interface_vehicle))
        #os.system('sudo ip link set {} down'.format(interface_BMS))
        #os.system('sudo ip link set {} type can bitrate {}'.format(interface_BMS, bitrate_to))
        #os.system('sudo ip link set {} up'.format(interface_BMS))
        # os.system('can.sh pass') # open relay for mitm

        self.canSocket_BMS = socket.socket(socket.PF_CAN,
                                          socket.SOCK_RAW,
                                          socket.CAN_RAW)
        self.canSocket_vehicle = socket.socket(socket.PF_CAN,
                                            socket.SOCK_RAW,
                                            socket.CAN_RAW)
        # Following the RAW Socket Options at
        # https://github.com/torvalds/linux/blob/master/Documentation/networking/can.rst
        # Set receive filters
        # filter passes when <received_can_id> & mask == can_id & mask
        # by setting the mask to zero, all messages pass.
        can_id = 0
        can_mask = 0
        # Alternatively, to filter out J1939 Cruise Control/Vehicle Speed messages
        # can_id = 0x00FEF100
        # can_mask = 0x00FFFF00 #Just looks at the PGN of 0xFEF1 = 65265
        can_filter = struct.pack('LL',can_id,can_mask)

        self.canSocket_BMS.setsockopt(socket.SOL_CAN_RAW,
                                     socket.CAN_RAW_FILTER,
                                     can_filter)
        ret_val = self.canSocket_BMS.getsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FILTER)
        sprnt("Socket Option for CAN_RAW_FILTER is set to {}".format(ret_val))
        self.canSocket_vehicle.setsockopt(socket.SOL_CAN_RAW,
                                     socket.CAN_RAW_FILTER,
                                     can_filter)
        ret_val = self.canSocket_vehicle.getsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FILTER)
        sprnt("Socket Option for CAN_RAW_FILTER is set to {}".format(ret_val))

        # Set the system to receive every possible error
        can_error_filter = struct.pack('L',CAN_ERR_MASK)
        # Alternatively, we can set specific errors where the errors are enumerated
        # in the defines of /linux/can/error.h
        # can_error_filter = CAN_ERR_TX_TIMEOUT | CAN_ERR_BUSOFF
        self.canSocket_BMS.setsockopt(socket.SOL_CAN_RAW,
                                     socket.CAN_RAW_ERR_FILTER,
                                     can_error_filter)
        ret_val = self.canSocket_BMS.getsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_ERR_FILTER)
        sprnt("Socket Option for CAN_RAW_ERR_FILTER is set to {}".format(ret_val))

        self.canSocket_vehicle.setsockopt(socket.SOL_CAN_RAW,
                                     socket.CAN_RAW_ERR_FILTER,
                                     can_error_filter)
        ret_val = self.canSocket_vehicle.getsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_ERR_FILTER)
        sprnt("Socket Option for CAN_RAW_ERR_FILTER is set to {}".format(ret_val))

        self.interface_vehicle = interface_vehicle
        self.interface_BMS = interface_BMS
        try:
            self.canSocket_BMS.bind((interface_BMS,))
        except OSError:
            sprnt("Could not bind to interface_BMS")
            exit(8)
        try:
            self.canSocket_vehicle.bind((interface_vehicle,))
        except OSError:
            sprnt("Could not bind to interface_vehicle")
            exit(9)
        # https://stackoverflow.com/questions/34371096/how-to-use-python-socket-settimeout-properly
        self.canSocket_BMS.settimeout(None) # would be blocking with None
        self.canSocket_vehicle.settimeout(None) # non-blocking with 0.0 timeout

    def handleVehicleMessages(self):
        global BMSrequest, ContactorsState, ContactorOrderedTrueTime, canstarttime
        raw_bytes_vehicle = self.canSocket_vehicle.recv(16)
        if raw_bytes_vehicle != None: # if a CAN message was waiting
            screen.addstr('v')
            if canstarttime == 0:
                canstarttime = time.time() # INITIALIZE WHEN THE FIRST CAN MESSAGE ARRIVES
                sprnt("canstarttime at {}".format(time.time()))
            rawID,DLC,candata = struct.unpack(canformat,raw_bytes_vehicle)
            canID = rawID & 0x1FFFFFFF
            if canID == 0x14FF4049:
                if candata[1] > 0:
                    if BMSrequest == False: # we need to start the transition to ON
                        self.contactorControl(8675309) # engage contactors
                        sprnt("Contactors START Precharging")
                        ContactorOrderedTrueTime = int(time.time())
                        candata_string = ""
                        for b in range(DLC):
                            candata_string += " {:02X}".format(candata[b])
                        logfile.write("{} {} {:08X} {} ".format(int(time.time()), ContactorOrderedTrueTime, canID, candata_string)+'\n')
                        logfile.flush()
                    BMSrequest = True
                    if int(time.time()) - ContactorOrderedTrueTime > 3:
                        #sprnt("ContactorOrderedTrueTime = {}".format(ContactorOrderedTrueTime))
                        if ContactorsState == False:
                            sprnt("Contactors Probably Finished Precharging")
                        ContactorsState = True
                else:
                    if BMSrequest == True:
                        self.contactorControl(123123) # disengage contactors
                        sprnt("Contactors DISENGAGED")
                    BMSrequest = False
                    ContactorsState = False
                #sprnt("14FF4049[1]="+str(candata[1]))
            #if time.time() % 1.0 > 0.2: return # ONLY RUN THIS STUFF 20% OF THE TIME
            #if BMSrequest == True and ContactorsState == False: # waiting for precharge to happen
            if canID == 0x440:
                screen.addstr(8,0," motor voltage: {} ".format(str(((candata[2] & 7) << 8) + candata[1]))+'         ')
                #logfile.write("{} voltage: {} ".format(int(time.time()), str(((candata[2] & 7) << 8) + candata[1]))+'\n')
                #logfile.flush()

    def handleBMSMessages(self): # watch for voltage reported by Xalt battery
        global XaltVoltage
        raw_bytes_BMS = self.canSocket_BMS.recv(16) # receive message from BMS
        if raw_bytes_BMS != None: # if a CAN message was waiting
            rawID,DLC,candata = struct.unpack(canformat,raw_bytes_BMS)
            canID = rawID & 0x1FFFFFFF
            if canID == 0x14FF4364: # packet with front, rear, average voltages
                #XaltVoltage = candata[0] + ((candata[1] & 0x07) << 8) # front voltage
                XaltVoltage = candata[2] + ((candata[3] & 0x07) << 8) # rear voltage
                #XaltVoltage = candata[5] + ((candata[6] & 0x07) << 8) # average voltage
                screen.addstr('                    ') # spaces after v's after voltage
                screen.addstr(9,0,"battery voltage: "+str(XaltVoltage)+'	')

    def contactorControl(self, instruction):
        os.system('/home/debian/bin/contactorcontrol {}'.format(str(instruction))) # tell the laptop to activate the contactor override hack

    def fakeXaltBMS(self):
        global XaltHeartbeatCounter, last10Hz, last2Hz, last1Hz
        timenow = time.time() # only call time.time() once to save time
        uptime = timenow - canstarttime  # how long since the first CAN message

        if timenow - last10Hz > 0.1:
            last10Hz  = timenow

            rawID = 0x14FF4064 | CAN_EFF_FLAG # A heartbeat CANmessage 10Hz
            XaltHeartbeatCounter = (XaltHeartbeatCounter + 1) % 8
            candatalist = [0,0,0,0,0,0,0,XaltHeartbeatCounter] # init list
            if uptime > 1.2:
                candatalist[2] = 0x01
            if uptime > 2.3:
                candatalist[2] = 0x02
            if uptime > 2.9:
                candatalist[7] |= 0b00001000
            if uptime > 3.1:
                candatalist[3] = 0x02
            if ContactorsState == True:
                candatalist[1] = 0x02
                candatalist[7] |= 0b00011000
            candata = bytes(candatalist)
            self.canSocket_vehicle.send(struct.pack(canformat, rawID, 8, candata))

            rawID = 0x14FF4264 | CAN_EFF_FLAG # C efficiency meter 10Hz
            if uptime > 2.2:
                candata = bytes([0x00,0x7D,0xF4,0x05,0xF4,0x05,0x00,0x00])
            else:
                candata = bytes([0x00,0x7D,0xF4,0x01,0xF4,0x01,0x00,0x00])
            self.canSocket_vehicle.send(struct.pack(canformat, rawID, 8, candata))

            rawID = 0x14FF4364 | CAN_EFF_FLAG # D voltage 10Hz
            candatalist = [XaltVoltage & 0xFF, XaltVoltage >> 8, XaltVoltage & 0xFF, XaltVoltage >> 8, 0, XaltVoltage & 0xFF, XaltVoltage >> 8, 0] # init list
            candatalist[1] |= 0x08
            candatalist[3] |= 0x08
            candata = bytes(candatalist)
            self.canSocket_vehicle.send(struct.pack(canformat, rawID, 8, candata))

            rawID = 0x14FF4464 | CAN_EFF_FLAG # E 10Hz
            if uptime > 1.0:
                candata = bytes([0x2B,0x87,0x05,0x2A,0x87,0x06,0x2A,0x03])
            else: # at startup
                candata = bytes([0,0,0,0,0,0,0,0x54])
            self.canSocket_vehicle.send(struct.pack(canformat, rawID, 8, candata))

            rawID = 0x14FF5264 | CAN_EFF_FLAG # M 10Hz
            candata = bytes([0xA9,0x02,0xA9,0x02,0x00,0xA9,0x02,0x00])
            self.canSocket_vehicle.send(struct.pack(canformat, rawID, 8, candata))

            rawID = 0x14FF5664 | CAN_EFF_FLAG # Q highest and lowest cell voltages 10Hz
            candata = bytes([0xBC,0x82,0x04,0xBC,0x82,0x05,0xBC,0x02]) # 595/168=3.54v
            self.canSocket_vehicle.send(struct.pack(canformat, rawID, 8, candata))

        if timenow - last2Hz > 0.5:
            last2Hz  = timenow

            rawID = 0x14FF4564 | CAN_EFF_FLAG # F SOC 2Hz
            candata = bytes([0x80,0x80,0x01,0x80,0x01,0x18,0x3D,0x00])
            self.canSocket_vehicle.send(struct.pack(canformat, rawID, 8, candata))

            rawID = 0x14FF4664 | CAN_EFF_FLAG # G 2Hz
            candata = bytes([0xE3,0xE3,0x01,0xE3,0x01,0x18,0x3D,0x00])
            self.canSocket_vehicle.send(struct.pack(canformat, rawID, 8, candata))

        if timenow - last1Hz > 1.0:
            last1Hz  = timenow

            rawID = 0x14FF4164 | CAN_EFF_FLAG # B high, low, and average cell temperature 1Hz
            if uptime > 1.2:
                candata = bytes([0x00,0x00,0x10,0xA0,0x00,0x10,0x28,0x01])
            else:
                candata = bytes([0x28,0x00,0x10,0x28,0x00,0x10,0x28,0x01])
            if uptime > 2.0:
                candata = bytes([0x00,0x60,0x15,0xA0,0x00,0x14,0x28,0x01])
            if uptime > 10.0:
                candata = bytes([0x3E,0xE1,0x04,0x3D,0x01,0x04,0x3D,0x00])
            self.canSocket_vehicle.send(struct.pack(canformat, rawID, 8, candata))

            rawID = 0x14FF4764 | CAN_EFF_FLAG # H 1Hz
            candata = bytes([0x3E,0xE1,0x04,0x3D,0x01,0x04,0x3D,0x00])
            self.canSocket_vehicle.send(struct.pack(canformat, rawID, 8, candata))

            rawID = 0x14FF4864 | CAN_EFF_FLAG # I 1Hz
            candata = bytes([0xB0,0x04,0x88,0x01,0x83,0x01,0x7F,0x01])
            self.canSocket_vehicle.send(struct.pack(canformat, rawID, 8, candata))

            rawID = 0x14FF4964 | CAN_EFF_FLAG # J 1Hz
            candata = bytes([0xCB,0x00,0x45,0x00,0x45,0x00,0x42,0x00])
            self.canSocket_vehicle.send(struct.pack(canformat, rawID, 8, candata))

            # rawID = 0x14FF5164 | CAN_EFF_FLAG # skipped 5064, no changes needed, it's ids[0x11]
            # candata = bytes([0x91,0x00,0xCA,0x30,0x01,0x93,0x00,0x00])

            # rawID = 0x14FF5364 | CAN_EFF_FLAG
            # candata = bytes([0xB1,0x07,0x00,0xB1,0x07,0x00,0xB1,0x03])

            # rawID = 0x14FF5464 | CAN_EFF_FLAG # this one alternates between two messages
            # candatalist = list(candata) # get a list that we can tamper with
            # candatalist[5] = 0

            # rawID = 0x14FF5864 | CAN_EFF_FLAG # 5764 doesn't exist
            # if uptime > 0.2:
            #     candata = bytes([0,3,0,0,0,0,0,0])
            # else: # at startup
            #     candata = bytes([0,0,0,0,0,0,0,0])
            # if uptime > 2.3:
            #     candata = bytes([0x00,0x03,0x00,0x17,0x00,0x00,0x00,0x00])

            # rawID = 0x18FF5764 | CAN_EFF_FLAG # 5564 doesn't need changed
            # candatalist = list(candata) # get a list that we can tamper with
            # if candatalist[0] == 0x66:
            #     candatalist[5] = 0x00
            #     candatalist[6] = 0xE3
            # candata = bytes(candatalist)

            # rawID = 0x18FF5964 | CAN_EFF_FLAG
            # candata = bytes([0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00])

            # rawID = 0x18FF9FF3 | CAN_EFF_FLAG
            # candata = bytes([0xDC,0x8D,0x32,0xFA,0xE3,0xD5,0x7D,0x01])

    def run(self, display=True):
        while True:
            self.handleVehicleMessages() # if messages heading from vehicle, check them
            self.handleBMSMessages() # if messages heading from BMS, check them
            self.fakeXaltBMS() # send messages pretending to be a happy Xalt BMS to please EDI
            key = screen.getch() # this is blocking unless you do .nodelay(1)
            if key == ord('z'):
                self.contactorControl(123123) # disengage contactors
                curses.endwin()
                exit()
            if key != -1: # a key was pressed
                if key & 0b11011111 >= ord('A') and key & 0b11011111 <= ord('Z'):
                    if key & 0b00100000 > 0: # lowercase
                        sprnt("pass {:08X}".format(ids[(key & 0b11011111) - 65 ]))
                        logfile.write("pass {:08X} ".format(ids[(key & 0b11011111) - 65 ]))
                        #fuckwith[(key & 0b11011111) - 65 ] = False;
                    else: # uppercase
                        sprnt("FORCE {:08X}".format(ids[(key & 0b11011111) - 65 ]))
                        logfile.write("FORCE {:08X} ".format(ids[(key & 0b11011111) - 65 ]))
                        #fuckwith[(key & 0b11011111) - 65 ] = True;
                    self.logsettings(int(time.time()))
                elif key > 47 and key < 58: # key is a number
                    startupstate = key - 48
                    sprnt("startupstate = {}".format(startupstate))
                    logfile.write("startupstate = {} ".format(startupstate))
                    self.logsettings(int(time.time()))

if __name__ == '__main__': #           vehicle                 BMS
    bridge = CanBridge(interface_vehicle='can1',interface_BMS='can0',bitrate_from=0,bitrate_to=0) # bitrates are not implemented
    starttime = time.time() # when we actually began
    logfilename = str(int(starttime))+'.mitmlog'
    logfile = open(logfilename,'w')
    logfile.write('logfile starting at '+str(time.time())+'\n')
    sprnt('logfile: '+logfilename)
    logfile.flush()
    os.system('kill $(pgrep -f \'tail.*mitmlog\')') # restart mitmlogwatch with the new file
    bridge.run()
'''
https://github.com/torvalds/linux/blob/master/include/uapi/linux/can/error.h
/*
 * linux/can/error.h
 *
 * Definitions of the CAN error frame to be filtered and passed to the user.
 *
 * Author: Oliver Hartkopp <oliver.hartkopp@volkswagen.de>
 * Copyright (c) 2002-2007 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 */

#ifndef CAN_ERROR_H
#define CAN_ERROR_H

#define CAN_ERR_DLC 8 /* dlc for error frames */

/* error class (mask) in can_id */
#define CAN_ERR_TX_TIMEOUT   0x00000001U /* TX timeout (by netdevice driver) */
#define CAN_ERR_LOSTARB      0x00000002U /* lost arbitration    / data[0]    */
#define CAN_ERR_CRTL         0x00000004U /* controller problems / data[1]    */
#define CAN_ERR_PROT         0x00000008U /* protocol violations / data[2..3] */
#define CAN_ERR_TRX          0x00000010U /* transceiver status  / data[4]    */
#define CAN_ERR_ACK          0x00000020U /* received no ACK on transmission */
#define CAN_ERR_BUSOFF       0x00000040U /* bus off */
#define CAN_ERR_BUSERROR     0x00000080U /* bus error (may flood!) */
#define CAN_ERR_RESTARTED    0x00000100U /* controller restarted */

/* arbitration lost in bit ... / data[0] */
#define CAN_ERR_LOSTARB_UNSPEC   0x00 /* unspecified */
                      /* else bit number in bitstream */

/* error status of CAN-controller / data[1] */
#define CAN_ERR_CRTL_UNSPEC      0x00 /* unspecified */
#define CAN_ERR_CRTL_RX_OVERFLOW 0x01 /* RX buffer overflow */
#define CAN_ERR_CRTL_TX_OVERFLOW 0x02 /* TX buffer overflow */
#define CAN_ERR_CRTL_RX_WARNING  0x04 /* reached warning level for RX errors */
#define CAN_ERR_CRTL_TX_WARNING  0x08 /* reached warning level for TX errors */
#define CAN_ERR_CRTL_RX_PASSIVE  0x10 /* reached error passive status RX */
#define CAN_ERR_CRTL_TX_PASSIVE  0x20 /* reached error passive status TX */
                      /* (at least one error counter exceeds */
                      /* the protocol-defined level of 127)  */

/* error in CAN protocol (type) / data[2] */
#define CAN_ERR_PROT_UNSPEC      0x00 /* unspecified */
#define CAN_ERR_PROT_BIT         0x01 /* single bit error */
#define CAN_ERR_PROT_FORM        0x02 /* frame format error */
#define CAN_ERR_PROT_STUFF       0x04 /* bit stuffing error */
#define CAN_ERR_PROT_BIT0        0x08 /* unable to send dominant bit */
#define CAN_ERR_PROT_BIT1        0x10 /* unable to send recessive bit */
#define CAN_ERR_PROT_OVERLOAD    0x20 /* bus overload */
#define CAN_ERR_PROT_ACTIVE      0x40 /* active error announcement */
#define CAN_ERR_PROT_TX          0x80 /* error occurred on transmission */

/* error in CAN protocol (location) / data[3] */
#define CAN_ERR_PROT_LOC_UNSPEC  0x00 /* unspecified */
#define CAN_ERR_PROT_LOC_SOF     0x03 /* start of frame */
#define CAN_ERR_PROT_LOC_ID28_21 0x02 /* ID bits 28 - 21 (SFF: 10 - 3) */
#define CAN_ERR_PROT_LOC_ID20_18 0x06 /* ID bits 20 - 18 (SFF: 2 - 0 )*/
#define CAN_ERR_PROT_LOC_SRTR    0x04 /* substitute RTR (SFF: RTR) */
#define CAN_ERR_PROT_LOC_IDE     0x05 /* identifier extension */
#define CAN_ERR_PROT_LOC_ID17_13 0x07 /* ID bits 17-13 */
#define CAN_ERR_PROT_LOC_ID12_05 0x0F /* ID bits 12-5 */
#define CAN_ERR_PROT_LOC_ID04_00 0x0E /* ID bits 4-0 */
#define CAN_ERR_PROT_LOC_RTR     0x0C /* RTR */
#define CAN_ERR_PROT_LOC_RES1    0x0D /* reserved bit 1 */
#define CAN_ERR_PROT_LOC_RES0    0x09 /* reserved bit 0 */
#define CAN_ERR_PROT_LOC_DLC     0x0B /* data length code */
#define CAN_ERR_PROT_LOC_DATA    0x0A /* data section */
#define CAN_ERR_PROT_LOC_CRC_SEQ 0x08 /* CRC sequence */
#define CAN_ERR_PROT_LOC_CRC_DEL 0x18 /* CRC delimiter */
#define CAN_ERR_PROT_LOC_ACK     0x19 /* ACK slot */
#define CAN_ERR_PROT_LOC_ACK_DEL 0x1B /* ACK delimiter */
#define CAN_ERR_PROT_LOC_EOF     0x1A /* end of frame */
#define CAN_ERR_PROT_LOC_INTERM  0x12 /* intermission */

/* error status of CAN-transceiver / data[4] */
/*                                             CANH CANL */
#define CAN_ERR_TRX_UNSPEC             0x00 /* 0000 0000 */
#define CAN_ERR_TRX_CANH_NO_WIRE       0x04 /* 0000 0100 */
#define CAN_ERR_TRX_CANH_SHORT_TO_BAT  0x05 /* 0000 0101 */
#define CAN_ERR_TRX_CANH_SHORT_TO_VCC  0x06 /* 0000 0110 */
#define CAN_ERR_TRX_CANH_SHORT_TO_GND  0x07 /* 0000 0111 */
#define CAN_ERR_TRX_CANL_NO_WIRE       0x40 /* 0100 0000 */
#define CAN_ERR_TRX_CANL_SHORT_TO_BAT  0x50 /* 0101 0000 */
#define CAN_ERR_TRX_CANL_SHORT_TO_VCC  0x60 /* 0110 0000 */
#define CAN_ERR_TRX_CANL_SHORT_TO_GND  0x70 /* 0111 0000 */
#define CAN_ERR_TRX_CANL_SHORT_TO_CANH 0x80 /* 1000 0000 */

/* controller specific additional information / data[5..7] */

#endif /* CAN_ERROR_H */
'''
