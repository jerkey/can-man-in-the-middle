#!/bin/env python3
import socket
import struct
import os
import curses
import time

screen = curses.initscr()
screen.addstr(0,10,"Hit 'q' to quit")
screen.refresh()
screen.nodelay(1)  # https://stackoverflow.com/questions/14004835/nodelay-causes-python-curses-program-to-exit
screen.scrollok(True) # allow gcode to scroll screen

# letter a          b          c          d          e          f          g          h          i          j          k          l          m          n          o          p          q          r          s          t          u          v          w          x          y
ids = [0x14FF4064,0x14FF4164,0x14FF4264,0x14FF4364,0x14FF4464,0x14FF4564,0x14FF4664,0x14FF4764,0x14FF4864,0x14FF4964,0x14FF5064,0x14FF5164,0x14FF5264,0x14FF5364,0x14FF5464,0x14FF5564,0x14FF5664,0x14FF5864,0x18EEFF64,0x18FECA64,0x18FF5764,0x18FF5964,0x18FF9FF3,0x1CEBFF64,0x1CECFF64]
fuckwith = [ True,      True,      True,     False,      True,      True,      True,      True,      True,      True,      True,     False,      True,      True,      True,     False,      True,      True,      True,      True,      True,      True,      True,     False,     False]

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
    def __init__(self, interface_from, interface_to,bitrate_to,bitrate_from):
        #set CAN bit rates. Must have super user privilages.
        #os.system('sudo ip link set {} down'.format(interface_from))
        #os.system('sudo ip link set {} type can bitrate {}'.format(interface_from, bitrate_from))
        #os.system('sudo ip link set {} up'.format(interface_from))
        #os.system('sudo ip link set {} down'.format(interface_to))
        #os.system('sudo ip link set {} type can bitrate {}'.format(interface_to, bitrate_to))
        #os.system('sudo ip link set {} up'.format(interface_to))
        # os.system('can.sh pass') # open relay for mitm

        self.canSocket_to = socket.socket(socket.PF_CAN, 
                                          socket.SOCK_RAW, 
                                          socket.CAN_RAW)
        self.canSocket_from = socket.socket(socket.PF_CAN, 
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
        
        self.canSocket_to.setsockopt(socket.SOL_CAN_RAW, 
                                     socket.CAN_RAW_FILTER,
                                     can_filter)
        ret_val = self.canSocket_to.getsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FILTER)
        sprnt("Socket Option for CAN_RAW_FILTER is set to {}".format(ret_val))
        self.canSocket_from.setsockopt(socket.SOL_CAN_RAW, 
                                     socket.CAN_RAW_FILTER,
                                     can_filter)
        ret_val = self.canSocket_from.getsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FILTER)
        sprnt("Socket Option for CAN_RAW_FILTER is set to {}".format(ret_val))
        
        # Set the system to receive every possible error
        can_error_filter = struct.pack('L',CAN_ERR_MASK)
        # Alternatively, we can set specific errors where the errors are enumerated
        # in the defines of /linux/can/error.h
        # can_error_filter = CAN_ERR_TX_TIMEOUT | CAN_ERR_BUSOFF
        self.canSocket_to.setsockopt(socket.SOL_CAN_RAW, 
                                     socket.CAN_RAW_ERR_FILTER,
                                     can_error_filter)
        ret_val = self.canSocket_to.getsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_ERR_FILTER)
        sprnt("Socket Option for CAN_RAW_ERR_FILTER is set to {}".format(ret_val))
        
        self.canSocket_from.setsockopt(socket.SOL_CAN_RAW, 
                                     socket.CAN_RAW_ERR_FILTER,
                                     can_error_filter)
        ret_val = self.canSocket_from.getsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_ERR_FILTER)
        sprnt("Socket Option for CAN_RAW_ERR_FILTER is set to {}".format(ret_val))
        
        self.interface_from = interface_from
        self.interface_to = interface_to
        try: 
            self.canSocket_to.bind((interface_to,))
            self.canSocket_from.bind((interface_from,))
        except OSError: 
            sprnt("Could not bind to SocketCAN interfaces")
        #put the sockets in blocking mode.
        self.canSocket_to.settimeout(None)
        self.canSocket_from.settimeout(0.0) # non-blocking with 0.0 timeout

    def checkMotorSignals(self):
        raw_bytes_to = self.canSocket_from.recv(16)
        if raw_bytes_to != None: # if a CAN message was waiting
            self.canSocket_to.send(raw_bytes_to)
            if time.time() % 0.01 > 0.002: return # ONLY RUN THIS STUFF 20% OF THE TIME
            rawID,DLC,candata = struct.unpack(canformat,raw_bytes_to)
            canID = rawID & 0x1FFFFFFF
            candata_string = ""
            if canID == 0x040:
                if candata[0] + (candata[1] & 0b10111111) + candata[2] + candata[3] > 0:
                    for b in range(DLC):
                        candata_string += " {:02X}".format(candata[b])
                    logfile.write("{} {:08X} {} ".format(int(time.time()), canID, candata_string)+'\n')
                    logfile.flush()
            if canID == 0x041:
                if candata[0] != 0x08:
                    for b in range(DLC):
                        candata_string += " {:02X}".format(candata[b])
                    logfile.write("{} {:08X} {} ".format(int(time.time()), canID, candata_string)+'\n')
                    logfile.flush()
            #if timestamp % 10 == 0: # every 20 seconds, just for troubleshooting
            #        for b in range(DLC):
            #            candata_string += " {:02X}".format(candata[b])
            #        logfile.write("{} {:08X} {} modfying {:08X} by {:b}".format(int(time.time()), canID, candata_string, ids[((timestamp >> 6) & 31) % 25], timestamp)+'\n')
            #        logfile.flush()

    def logsettings(self,timestamp):
        for i in range(len(fuckwith)):
            if fuckwith[i]:
                logfile.write("1")
            else:
                logfile.write("0")
        logfile.write(" "+str(timestamp)+'\n\r')
        logfile.flush()

    def run(self, display=True):
        global fuckwith, canstarttime # access the message filter array
        while True:
            self.checkMotorSignals() # if messages heading from vehicle, check them
            key = screen.getch() # this is blocking unless you do .nodelay(1)
            if key != -1: # a key was pressed
                if key & 0b11011111 >= ord('A') and key & 0b11011111 <= ord('Z'):
                    if key & 0b00100000 > 0: # lowercase
                        sprnt("pass {:08X}".format(ids[(key & 0b11011111) - 65 ]))
                        logfile.write("pass {:08X} ".format(ids[(key & 0b11011111) - 65 ]))
                        fuckwith[(key & 0b11011111) - 65 ] = False;
                    else: # uppercase
                        sprnt("FORCE {:08X}".format(ids[(key & 0b11011111) - 65 ]))
                        logfile.write("FORCE {:08X} ".format(ids[(key & 0b11011111) - 65 ]))
                        fuckwith[(key & 0b11011111) - 65 ] = True;
                    self.logsettings(int(time.time()))

            raw_bytes_from = self.canSocket_to.recv(16) # receive message from can0
            if canstarttime == 0: canstarttime = time.time() # INITIALIZE WHEN THE FIRST CAN MESSAGE ARRIVES
            rawID,DLC,candata = struct.unpack(canformat,raw_bytes_from)
            canID = rawID & 0x1FFFFFFF
            if (rawID & CAN_ERR_FLAG) == CAN_ERR_FLAG:
                sprnt("Found Error Frame.")
                sprnt("RawID: {:08X}, data: {}".format(rawID,candata))

                if canID == 1:
                    sprnt("TX timeout")
                elif canID == 2:
                    sprnt ("Lost arbitration")
                elif canID == 4:
                    sprnt("Controller problems")
                elif canID == 8:
                    sprnt("Protocol violations")
                elif canID == 16:
                    sprnt("Transceiver status") 
                elif canID == 32:
                    sprnt("No Acknkowlegement on transmission")
                elif canID == 64:
                    sprnt("Bus off")
                elif canID == 128:
                    sprnt("{:03X}: Bus error. {}".format(canID,candata))
                elif canID == 0x100:
                    sprnt("Controller restarted")
            elif rawID & CAN_RTR_FLAG == CAN_RTR_FLAG:
                sprnt("Received RTR frame.")
            else: #Normal data frame
                canID = rawID & 0x1FFFFFFF
                # https://python-can.readthedocs.io/en/1.5.2/_modules/can/interfaces/socketcan_native.html
                if canID in ids:
                    if fuckwith[ids.index(canID)]: # if we're supposed to be fucking with this message
                        uptime = time.time() - canstarttime  # how long since the first CAN message
                        if canID == 0x14FF4064: # heartbeat CANmessage
                            candatalist = list(candata) # get a list that we can tamper with
                            if uptime > 1.2:
                                candatalist[2] = 0x01
                            else: # at startup
                                candata = bytes([0,0,0,0,0,0,0,0])
                            if uptime > 2.3:
                                candatalist[2] = 0x02
                            if uptime > 2.9:
                                candatalist[7] |= 0b00001000
                            if uptime > 3.1:
                                candatalist[3] = 0x02
                            if uptime > 10: # actually it's 70.2 seconds in 20200831.171* and like 4.5 seconds in 20200831.173*
                                candatalist[1] = 0x02
                                candatalist[7] |= 0b00011000
                            candata = bytes(candatalist)

                        if canID == 0x14FF4164: #  high, low, and average cell temperature
                            candata = bytes([0x3E,0xE1,0x04,0x3D,0x01,0x04,0x3D,0x00])

                        if canID == 0x14FF4264: #  efficiency meter
                            candata = bytes([0x00,0x7D,0xF4,0x05,0xF4,0x05,0x00,0x00])

                        if canID == 0x14FF4364: #  voltage (we want to pass this through mostly)
                            candatalist = list(candata) # get a list that we can tamper with
                            candatalist[1] |= 0x08
                            candatalist[3] |= 0x08
                            candata = bytes(candatalist)

                        if canID == 0x14FF4464:
                            if uptime > 1.0:
                                candata = bytes([0x2B,0x87,0x05,0x2A,0x87,0x06,0x2A,0x03])
                            else: # at startup
                                candata = bytes([0,0,0,0,0,0,0,0x54])

                        if canID == 0x14FF4564:
                            candata = bytes([0x80,0x80,0x01,0x80,0x01,0x18,0x3D,0x00])

                        if canID == 0x14FF4664:
                            candata = bytes([0xE3,0xE3,0x01,0xE3,0x01,0x18,0x3D,0x00])

                        if canID == 0x14FF4764:
                            candata = bytes([0x3E,0xE1,0x04,0x3D,0x01,0x04,0x3D,0x00])

                        if canID == 0x14FF4864:
                            candata = bytes([0xB0,0x04,0x88,0x01,0x83,0x01,0x7F,0x01])

                        if canID == 0x14FF4964:
                            candata = bytes([0xCB,0x00,0x45,0x00,0x45,0x00,0x42,0x00])

                        if canID == 0x14FF5164: # skipped 5064, no changes needed, it's ids[0x11]
                            candata = bytes([0x91,0x00,0xCA,0x30,0x01,0x93,0x00,0x00])

                        if canID == 0x14FF5264:
                            candata = bytes([0xA9,0x02,0xA9,0x02,0x00,0xA9,0x02,0x00])

                        if canID == 0x14FF5364:
                            candata = bytes([0xB1,0x07,0x00,0xB1,0x07,0x00,0xB1,0x03])

                        if canID == 0x14FF5464: # this one alternates between two messages
                            candatalist = list(candata) # get a list that we can tamper with
                            candatalist[5] = 0
                            candata = bytes(candatalist)

                        if canID == 0x14FF5664: # 5564 doesn't need changed
                            candata = bytes([0xBC,0x82,0x04,0xBC,0x82,0x05,0xBC,0x02]) # 595/168=3.54v

                        if canID == 0x14FF5864: # 5764 doesn't exist
                            if uptime > 0.2:
                                candata = bytes([0,3,0,0,0,0,0,0])
                            else: # at startup
                                candata = bytes([0,0,0,0,0,0,0,0])
                            if uptime > 2.3:
                                candata = bytes([0x00,0x03,0x00,0x17,0x00,0x00,0x00,0x00])

                        if canID == 0x18FF5764: # 5564 doesn't need changed
                            candatalist = list(candata) # get a list that we can tamper with
                            if candatalist[0] == 0x66:
                                candatalist[5] = 0x00
                                candatalist[6] = 0xE3
                            candata = bytes(candatalist)

                        if canID == 0x18FF5964:
                            candata = bytes([0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00])

                        if canID == 0x18FF9FF3:
                            candata = bytes([0xDC,0x8D,0x32,0xFA,0xE3,0xD5,0x7D,0x01])

            self.canSocket_from.send(struct.pack(canformat, rawID, DLC, candata))
            # self.canSocket_from.send(raw_bytes_from)

canstarttime = 0 # this gets set to present time upon the first CAN message arrival
if __name__ == '__main__': #       can1=vehicle         can0=BMS
    bridge = CanBridge(interface_from='can0',interface_to='can1',bitrate_from=0,bitrate_to=0) # bitrates are not implemented
    starttime = time.time() # when we actually began
    logfile = open(str(int(starttime))+'.mitmlog','w')
    logfile.write('logfile starting at '+str(time.time())+'\n')
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
