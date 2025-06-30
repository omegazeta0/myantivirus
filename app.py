from scapy.all import *
import threading
import time
import requests
from flask import *
from bs4 import BeautifulSoup

# Settings

app=Flask(__name__)

# Main class

class Defender:

    def __init__(self):
        self.INTERFACE = "Wi-Fi"           
        self.CLIENT_IP = "192.168.0.195"    
        self.GATEWAY_IP = "192.168.0.1" 
        self.results=[]

    # Functions

    def get_mac(self,ip):
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False, iface=self.INTERFACE)[0]

        if answered_list:
            mac = answered_list[0][1].hwsrc
            self.results.append(f"[+] MAC found for {ip}: {mac}")
            return mac
        else:
            self.results.append(f"[!] MAC for {ip} not found")
            return None


    def dns(self,pkt):
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            qname = pkt[DNSQR].qname
            self.results.append(f"[DNS] Request for {qname.decode()}")
           

    # Execution

def initializeInspecting():
    if __name__ == "__main__":
        defender=Defender()
       
        sniff(filter="udp port 53 and ip src " + defender.CLIENT_IP, prn=defender.dns(), iface=defender.INTERFACE)
        return defender.results

# Web class

class web:
    def __init__(self):
        self.count=0
        self.host='127.0.0.1'
        self.port='1002'
        self.database='https://urlhaus.abuse.ch/browse/page/0/'
        self.headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        }

    def search(self):
        searching=requests.get(self.database,headers=self.headers)
        soup = BeautifulSoup(searching.text, 'html.parser')
        links = []
        for tag in soup.find_all('a'):
            links.append(str(tag))
        return links
        


    
    def routes(self):
        @app.route('/')
        def index():
            return render_template('index.html',host=self.host,port=self.port)
        
        @app.route('/inspect')
        def inspect():
            final_results=initializeInspecting()
            return render_template('inspect.html',result=final_results)

        if __name__=='__main__':
            app.run(host=self.host,port=self.port)

# Execution

site = web()
site.routes()

        
        
    
    

