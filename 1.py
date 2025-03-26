from scapy.all import rdpcap
from collections import Counter
import requests
import time

def check_ip_with_virustotal(ips, api_key):
    for i in range(len(ips)):
        time.sleep(16)
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ips[i]}"
        headers = {
            "x-apikey": api_key
        }
        odpowiedz = requests.get(url, headers=headers)
        if odpowiedz.status_code == 200:
            dane = odpowiedz.json()
            if dane['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                ilosc = dane['data']['attributes']['last_analysis_stats']['malicious']
                if ilosc > 0:
                    print(f"IP {ips[i]} został oznaczony jako złośliwy, ilość raportów: {ilosc}")
            else:
                print(f"IP {ips[i]} nie zostal oznaczony jako zlosliwy")
        else:
            print(f"Błąd podczas sprawdzania IP: {odpowiedz.status_code}")

def czy_prywatne(ip):
    return (ip.startswith("10.") or
            ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31 or
            ip.startswith("192.168."))

def szukaj_ddos(plik_pcap, limit=100):
    packets = rdpcap(plik_pcap)
    ip_licznik = Counter()
    total_packets = len(packets)

    for i, packet in enumerate(packets, start=1):
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            if not czy_prywatne(src_ip):
                ip_licznik[src_ip] += 1
        print(f"Przeanalizowano {i}/{total_packets} pakietów", end='\r')

    ddos_ips = {ip: count for ip, count in ip_licznik.items() if count > limit}

    print(f"\nLiczba podejrzanych adresów IP: {len(ddos_ips)}")
    for ip, count in ddos_ips.items():
        print(f"Adres IP: {ip}, Liczba wystąpień: {count}")

    return list(ddos_ips.keys())

if __name__ == "__main__":
    api_key= "" # TWOJ API KEY
    plik_pcap = "plik3.pcapng"  # PLIK PCAP
    ddos_ips = szukaj_ddos(plik_pcap, limit=1000) 
    print("Stosunkowy czas weryfikacji Virus totalem: "+str(len(ddos_ips)*16)+" sekund")
    check_ip_with_virustotal(ddos_ips, api_key)
