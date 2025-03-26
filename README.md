Wersja 1.0 programu, ktory sprawdza potencjalne adresy IP ktore mogly być powiazane z atakami DDoS a nastepnie dzieki API
VirusTotala sprawdza czy dany adres IP jest okreslony jako zlosliwy.


Trzeba pipem zainstlować następujace biblioteki:
1. scapy
2. requests

time.sleep(16) nie moze byc ustawiony na mniejsza wartosc, chyba ze ma sie virustotal premium xD
w linijce plik_pcap trzeba wpisac jaki pcap chcemy sprawdzic,
w linijce api_key nalezy wpisac api Virustotala.
limit mozna zmienic w zaleznosci od tego jak chcemy interpreztowac liczbe pakietów jako atak DDoS (np. 1000 pakietów dla danego IP => potencjalny DDoS)
