from scapy.all import *

def get_packets (p):
    print("Total number of packets are", len(p))

def get_ip_fields (pkt):
    temporary = str(pkt.show)
    if "IP " in temporary:
        start = temporary.find("IP ")
        end = temporary.find("|", start)
        sliced_string = slice(start, end)
        print(temporary[sliced_string])
    else:
        print("No IP found")

def get_prot_percentage (p):
    temporary = str(p.show)
    tcp_number = 0
    udp_number = 0
    for word in temporary.split():
        if "TCP:" in word:
            sliced_string = slice(4, len(word))
            tcp_number = int(word[sliced_string])
        if "UDP:" in word:
            sliced_string = slice(4, len(word))
            udp_number = int(word[sliced_string])
    total = int(len(p))
    print("TCP:", str(int(tcp_number/total*100)), "% ,", "UDP:", str(int(udp_number/total*100)), "%")

def get_prot_fields (pkt):
    temporary = str(pkt.show)
    protocol = " "
    found = False
    if "<TCP" in temporary:
        protocol = "TCP"
        found = True
    if "<UDP" in temporary:
        protocol = "UDP"
        found = True
    if found:
        start = temporary.find(protocol)
        end = temporary.find("|", start)
        sliced_string = slice(start, end)
        print(temporary[sliced_string])
    else:
        print("No protocol found")

def get_fragmented_packets (p):
    total = 0
    fragmented = " "
    for pkt in p:
        if "flags=MF" in str(pkt.show):
            #total = total + 1
            temporary = str(pkt.show)
            start = temporary.find("id=")
            end = temporary.find(' ', start)
            sliced_string = slice(start+3, end)
            id = temporary[sliced_string]
            if not id in fragmented:
                fragmented = fragmented + id
    temporary = fragmented.split()
    for id in temporary:
        total = total +1
    print("Total number of fragmented packets are", total)

def run_packet_analyzer ():
    print("Enter the path of .pcap file: ")
    path = input()
    p = rdpcap(path)
    while True:
        print("what do you want to do?")
        print("1. Get total number of packets\n2. Get total number of fragmented packets\n3. Get percentage of TCP and UDP\n4. Get IP and protocol fields\n5. Exit")
        choice = int(input())
        if choice == 1:
            get_packets(p)
        elif choice == 2:
            get_fragmented_packets(p)
        elif choice == 3:
            get_prot_percentage(p)
        elif choice == 4:
            get_fields(p)
        elif choice == 5:
            break
        else:
            print("Invalid choice")

def get_fields(p):
    number = 0
    for pkt in p:
        print("Packet#", number)
        get_ip_fields(pkt)
        get_prot_fields(pkt)
        number = number + 1

# p = rdpcap("trace1.pcap")
# getPackets(p)
# getFragmentedPackets(p)
# getProtPercentage(p)
# number = 0
# for pkt in p:
#     print("Packet#", number)
#     getIPFields(pkt)
#     getProtFields(pkt)
#     number = number + 1
run_packet_analyzer()