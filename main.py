#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2021/7/3 11:52 AM
# @Author  : Uji Zou
# @Site    : 
# @File    : main.py
# @Software: PyCharm

from scapy.all import *
from binascii import hexlify
from collections import OrderedDict
import sys
import os

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print("-----系统输入参数个数有误，请重新执行文件-------")
        print ("-----请输入源文件路径与目的文件路径------------")
        print("-----python main.py /Users/zouyuchi/Desktop/ ./OutputStatics.csv ./DropPacketStatics.csv")
        print ("-----python main.py /Users/zouyuchi/Desktop/1.pcapng ./OutputStatics.csv ./DropPacketStatics.csv")
        exit(0)

    #filename = "/Users/zouyuchi/Desktop/selected1.pcapng"
    #filename_input = "/Users/zouyuchi/Desktop/1.pcapng"
    #filename_output = ""
    filename_input = sys.argv[1]
    filename_output = sys.argv[2]
    filename_drop = sys.argv[3]

    isfile = os.path.isfile(filename_input)
    isdir = os.path.isdir(filename_input)
    if isdir:
        names = [(os.path.join(filename_input,name)) for name in os.listdir(filename_input)
                 if os.path.isfile(os.path.join(filename_input,name))]
    if isfile:
        names = filename_input


    #print names


    trdp_packet_count = 0

    comid_seq_dict = OrderedDict()

    if type(names) == str:
        filename = names
        PCAPS = rdpcap(filename)
        for pcap in PCAPS:
            if pcap.haslayer(IP):
                ip = pcap.getlayer(IP)
                sip = ip.src
                dip = ip.dst

            if pcap.haslayer(UDP):
                udp = pcap.getlayer(UDP)
                dport = udp.dport
                sport = udp.sport
                if dport != 17224:
                    print("%s->%s is not TRDP Packet，continue" % (sip, dip))
                    continue

                if pcap.haslayer(Raw):
                    trdp_packet_count += 1
                    praw = pcap.getlayer(Raw)
                    payload = hexlify(praw.load)
                    sequenceCounter = payload[0:8]
                    comId = payload[16:24]
                    comId_str = str(int(comId, 16))
                    sequenceCounter_int = int(sequenceCounter, 16)
                    sequenceCounter_str = str(int(sequenceCounter, 16))
                    arrivalTime_str = str(str(pcap.time))
                    # print str(pcap.time)+","+str(int(sequenceCounter,16))+","+str(int(comId,16))
                    if comId_str not in comid_seq_dict:
                        comid_seq_dict[comId_str] = [[], []]
                        comid_seq_dict[comId_str][0].append(sequenceCounter_int)
                        comid_seq_dict[comId_str][1].append(arrivalTime_str)
                    else:
                        comid_seq_dict[comId_str][0].append(sequenceCounter_int)
                        comid_seq_dict[comId_str][1].append(arrivalTime_str)

    if type(names) == list:
        for filename in names:
            PCAPS = rdpcap(filename)
            for pcap in PCAPS:
                if pcap.haslayer(IP):
                    ip = pcap.getlayer(IP)
                    sip = ip.src
                    dip = ip.dst

                if pcap.haslayer(UDP):
                    udp = pcap.getlayer(UDP)
                    dport = udp.dport
                    sport = udp.sport
                    if dport != 17224:
                        print("%s->%s is not TRDP Packet，continue"%(sip,dip))
                        continue

                    if pcap.haslayer(Raw):
                        trdp_packet_count += 1
                        praw = pcap.getlayer(Raw)
                        payload = hexlify(praw.load)
                        sequenceCounter = payload[0:8]
                        comId = payload[16:24]
                        comId_str = str(int(comId,16))
                        sequenceCounter_int = int(sequenceCounter, 16)
                        sequenceCounter_str = str(int(sequenceCounter,16))
                        arrivalTime_str = str(str(pcap.time))
                        #print str(pcap.time)+","+str(int(sequenceCounter,16))+","+str(int(comId,16))
                        if comId_str not in comid_seq_dict:
                            comid_seq_dict[comId_str] = [[],[]]
                            comid_seq_dict[comId_str][0].append(sequenceCounter_int)
                            comid_seq_dict[comId_str][1].append(arrivalTime_str)
                        else:
                            comid_seq_dict[comId_str][0].append(sequenceCounter_int)
                            comid_seq_dict[comId_str][1].append(arrivalTime_str)


    for key in comid_seq_dict:
        tmp_zip_list = list(zip(comid_seq_dict[key][0], comid_seq_dict[key][1]))
        tmp_zip_list.sort()
        comid_seq_dict[key][0][:], comid_seq_dict[key][1][:] = zip(*tmp_zip_list)


    with open(filename_output, "w") as f:
        f.write("comId"+","+"SequenceCounter"+","+"ArrivalTime\n")
        for key,value in comid_seq_dict.items():
            for i in range(0,len(value[0])):
                f.write(str(key)+","+str(value[0][i])+","+str(value[1][i]))
                f.write("\n")


    with open(filename_drop, "w") as f:
        f.write("comId,TRDP Sum,Drop Sum,Drop Rate,Start Seq,End Seq,Start ArrivalTime,End ArrivalTime,MaxInterval,MinInterval\n")
        for key, value in comid_seq_dict.items():
            trdp_drop_count = 0
            max_interval = 0
            min_interval = 0
            packet_interval = []
            for i in range(1, len(value[0])):
                if abs(int(value[0][i]) - int(value[0][i-1])) >=2:
                    trdp_drop_count = trdp_drop_count + abs(int(value[0][i]) - int(value[0][i-1]) - 1)
                    
                    #f.write("Error: comId:%s pre Seq:%d->Seq:%d\r\n"%(key,value[0][i-1],value[0][i]))
                    #print "Error: comId:%s pre Seq:%d->Seq:%d"%(key,value[0][i-1],value[0][i])
            #if trdp_drop_count == 0:
                #continue

            for j in range(1,len(value[1])):
                #print((float)(value[1][j-1]),(float)(value[1][j]),abs((float)(value[1][j-1])-(float)(value[1][j])))
                packet_interval.append(abs((float)(value[1][j-1])-(float)(value[1][j])))
            max_interval = max(packet_interval)
            min_interval = min(packet_interval)
            #print(max_interval,min_interval)
                
                
            f.write(str(key)+","+str(len(value[0]))+","+str(trdp_drop_count)+","+
            str((float)(trdp_drop_count)/len(value[0]))+","+str(value[0][0])+","+
            str(value[0][-1])+","+str(value[1][0])+","+str(value[1][-1])+","+str(max_interval)+","+str(min_interval))
            f.write("\n")
            #f.write("Comid:%s TRDP Packet Sum:%d, Drop Packet Sum:%d, Drop Rate:%.5f，Start Seq:%s, End Seq:%s, Start ArrivalTime:%s, End ArrivalTime:%s\r\n"
            #    %(key, len(value[0]),trdp_drop_count,(float)(trdp_drop_count)/len(value[0]),str(value[0][0]),str(value[0][-1]),str(value[1][0]),str(value[1][-1])))





