#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import argparse
import logging
import threading
import queue
import http.client
import ssl
from netaddr import IPNetwork
from bs4 import BeautifulSoup
import re
import datetime, time

class realIPFinder(object):
    def __init__(self, thread, protocol, domain, port, path, iplist, identifystring):
        self.thread     =   thread
        self.protocol   =   protocol
        self.domain     =   domain
        self.path       =   path
        self.port       =   port
        self.iplistQ    =   queue.Queue()
        self.identifyStr=   identifystring
        self.messageQ   =   queue.Queue()
        self.thread_arr =   []
        self.timeout    =   30

        [self.iplistQ.put(query) for query in iplist]

    def run_finder(self):
        t = threading.Thread(target=self.messager)
        t.start()

        for i in range(self.thread):
            t = threading.Thread(target=self.checker)
            self.thread_arr.append(t)
            t.start()

    def checker(self):
        headers = {}
        headers['User-Agent'] = "Mozilla/5.0 (Linux; U; Android 2.2) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1"
        while not self.iplistQ.empty():
            ip = self.iplistQ.get()
            # self.messageQ.put("testing %s"%ip)
            msg = "%s  "%ip
            headers['Host'] = "%s:%d"%(self.domain,self.port) if self.port not in (80,443) else self.domain
            try:
                if self.protocol.upper() == "HTTP":
                    conn = http.client.HTTPConnection(ip, self.port, timeout=self.timeout)
                elif self.protocol.upper() == "HTTPS":
                    conn = http.client.HTTPSConnection(ip, self.port, timeout=self.timeout, context = ssl._create_unverified_context())
                conn.request("GET", self.path, headers = dict(headers))
                res = conn.getresponse()
                res_body = res.read()
                try:
                    soup = BeautifulSoup(res_body, 'html.parser')
                    html = soup.prettify()
                    msg += "%d  --> %s"%(res.code, soup.title.string)
                    # print(html[:800])
                    if (self.identifyStr is not None) and (self.identifyStr in html):
                        msg += "   🍺🍺🍺🍺🍺   %s"%(self.identifyStr)
                except Exception as e:
                    # print(e)
                    msg += "%d  --> %s"%(res.code,"No Title")
            except Exception as e:
                msg += str(e)
            finally:
                self.messageQ.put(msg)
        return

    def messager(self):
        outputPath = os.path.join(os.path.split(os.path.realpath(__file__))[0],"output")
        if not os.path.exists(outputPath):
            os.mkdir(outputPath)
        logPath = os.path.join(outputPath,"%s_log.txt"%self.domain)
        f = open(logPath, 'a+', encoding='utf-8');
        while True:
            if not self.messageQ.empty():
                info = self.messageQ.get()
                print(" \b\b"*100,end="")
                print(info)
                f.write(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                f.write(" || ")
                f.write(info)
                f.write("\n")
                f.flush()
            else:
                print(" \b\b"*100,end="")
                print(" Remaining IPs : %d"%self.iplistQ.qsize(), end="")
                time.sleep(0.5)
                threadAliveCount = 0
                for t in self.thread_arr:
                    if t.is_alive():      # 切记勿用 t.isAlive
                        threadAliveCount += 1
                if threadAliveCount <=0 and (self.messageQ.qsize()==0):    # 数据呈现完毕
                    f.close
                    return

def getIPlist(originalIPs):
    iplist = []
    for line in originalIPs:
        try:
            for ip in IPNetwork(line):
                # print(ip)
                iplist.append(str(ip))
        except:
            print("Ignore Wrong IP/CIDR : %s"%line)
    return iplist

def main():
    headCharPic="\r        .--.\n" \
                "       |o_o |    ------------------ \n" \
                "       |:_/ |   <      Mr.Bingo     >\n" \
                "      //   \ \   ------------------ \n" \
                "     (|     | ) < https://oddboy.cn >\n" \
                "    /'\_   _/`\  ------------------ \n" \
                "    \___)=(___/\n"
    print(headCharPic)
    # Creating a parser
    parser = argparse.ArgumentParser()

    parser.add_argument('--protocol', dest="protocol",default='HTTP', help='HTTP or HTTPS, default: HTTP')
    parser.add_argument('--domain',required=True, dest='domain', help='Target Domain, eg: www.oddboy.cn')
    parser.add_argument('--port', dest='port',type=int, help='Service Port, eg: 80')
    parser.add_argument('--path',default="/", dest='path', help='Target Path, eg: / or /WebRoot, default: / ')
    
    groupIP = parser.add_mutually_exclusive_group(required=True)
    groupIP.add_argument('-i',dest="ip",help="Signal IP, eg: 8.8.8.8 or 8.8.8.8/24")
    groupIP.add_argument('-I',dest='ips',help="IP list file")

    parser.add_argument('-t',dest='thread', default=1, type=int, help="Thread Count, default: 1")
    # parser.add_argument('--log-level', default='CRITICAL', choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'), help='Default: CRITICAL')

    parser.add_argument('--identifystring',dest="identifystring",help="Use Identify String to Ident The True Target")

    args = parser.parse_args()
    if args.port is None:
        targetPort = 80 if args.protocol.upper() == 'HTTP' else 443
    else:
        targetPort = args.port
    originalIPs = []
    
    if args.ip is not None:
        originalIPs.append(args.ip)
    elif (args.ips is not None) and os.path.exists(args.ips):
        with open(args.ips,'r') as f:
            for line in f.readlines():
                compile_ip=re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)(\/\d{1,2})*$')  # 校验IP或者cidr是否合规
                if compile_ip.match(line.strip()):
                    originalIPs.append(line.strip())
                else:
                    print("%s not a valid IP/CIDR, ignored"%line.strip())
    else:
        print("The IP list file(%s) is not Exist!!!"%args.ips)

    iplist = getIPlist(originalIPs)

    # print(iplist)

    finder_obj = realIPFinder(args.thread,args.protocol, args.domain, targetPort, args.path,iplist, args.identifystring)
    finder_obj.run_finder()

if __name__ == '__main__':
    main()
