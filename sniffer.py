# coding: UTF-8
# !/usr/bin/env python
# -------------------------------------------------------------------------------
# Name:        python_sniffer.py
#
# Author:      liushuai 01111149
#
# Created:     12/25/2014
#-------------------------------------------------------------------------------

from winpcapy import *
from Tkinter import  *
import sys
import string
import platform


if platform.python_version()[0] == "3":
    raw_input = input
LINE_LEN = 16
alldevs = POINTER(pcap_if_t)()
d = POINTER(pcap_if_t)
fp = pcap_t
errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
header = POINTER(pcap_pkthdr)()
pkt_data = POINTER(c_ubyte)()

interface=[]
if len(sys.argv) < 3:
    ## The user didn't provide a packet source: Retrieve the local device list
    if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
        print ("Error in pcap_findalldevs: %s\n", errbuf.value)
        sys.exit(1)
    ## Print the list
    i = 0
    d = alldevs.contents
    while d:
        i = i + 1
        print ("%d. %s" % (i, d.name))
        if (d.description):
            print (" (%s)\n" % (d.description))
            interface.append( str(i)+'. '+d.name+' '+d.description)
        else:
            print (" (No description available)\n")
        if d.next:
            d = d.next.contents
        else:
            d = False
    if (i == 0):
        print ("\nNo interfaces found! Make sure WinPcap is installed.\n")
        sys.exit(-1)


    selected = '2'
    def radioPress(selecting) :
        selected = selecting
        print selected
        root.quit()


    root = Tk()
    root.title('Select Interface')
    r = StringVar()
    r.set('1')
    radio = Radiobutton(root, variable=r, value='1', text=interface[0])
    radio.pack()

    radio = Radiobutton(root, variable=r, value='2', text=interface[1])
    radio.pack()

    radio = Radiobutton(root, variable=r, value='3', text=interface[2])
    radio.pack()

    radio = Radiobutton(root, variable=r, value='4', text=interface[3])
    radio.pack()


    btn = Button(root, text='OK',command = (lambda :radioPress(r.get())),bg='GREEN', width=14, height=1)
    btn.pack()

    mainloop()

    inum = selected
    if inum in string.digits:
        inum = int(inum)
    else:
        inum = 0
    if ((inum < 1) | (inum > i)):
        print ("\nInterface number out of range.\n")
        # Free the device list
        pcap_freealldevs(alldevs)
        sys.exit(-1)

    d = alldevs
    for i in range(0, inum - 1):
        d = d.contents.next
    fp = pcap_open_live(d.contents.name, 65536, 1, 1000, errbuf)
    if (fp == None):
        print ("\nError opening adapter\n")
        ## Free the device list
        pcap_freealldevs(alldevs)
        sys.exit(-1)
else:
    ## Do not check for the switch type ('-s')
    fp = pcap_open_live(sys.argv[2], 65536, 1, 1000, errbuf)
    if (fp == None):
        print ("\nError opening adapter\n")
        ## Free the device list
        pcap_freealldevs(alldevs)
        sys.exit(-1)

class Content:
    def __int__(self,no,time,source,des,pro,len):
        self.no=no
        self.time=time
        self.source=source
        self.des=des
        self.pro=pro
        self.len=len

show = []

## Read the packets
res = pcap_next_ex(fp, byref(header), byref(pkt_data))
no=1
while (res >= 0):
    if (res == 0):
        ## Timeout elapsed
        break
    ##  Print the packet
    # 设置过滤条件 为TCP
    if(pkt_data[31]==6) :
        source=str(pkt_data[34])+'.'+str(pkt_data[35])+'.'+str(pkt_data[36])+'.'+str(pkt_data[37])
        des = str(pkt_data[38])+'.'+str(pkt_data[39])+'.'+str(pkt_data[40])+'.'+str(pkt_data[41])
        cols = [str(no),str(header.contents.ts.tv_usec),source,des,'tcp',str(header.contents.len)]
        show.append(cols)
        print ("\n\n")
    res = pcap_next_ex(fp, byref(header), byref(pkt_data))
    no+=1
if (res == -1):
    print ("Error reading the packets: %s\n" % pcap_geterr(fp))
    sys.exit(-1)

pcap_close(fp)

print len(show)

root.title('Analyse packet')
rows = []
cols = ['No.','Timer(us)','Source','Destination','Protocol','Length']
for j in range(len(cols)):
        e = Entry(bg='green',relief=SUNKEN)
        e.grid(row=1, column=j, sticky=NSEW)
        e.insert(END, cols[j])
        cols.append(e)
rows.append(cols)
for i in range(2,len(show)):
    cols = []
    for j in range(6):
        e = Entry(relief=RIDGE)
        e.grid(row=i, column=j, sticky=NSEW)
        e.insert(END, show[i][j])
        cols.append(e)
    rows.append(cols)

mainloop()

sys.exit(0)

