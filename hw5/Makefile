all: ipscanner

pcap.o: pcap.h pcap.c
	gcc -c pcap.c -o pcap.o

fill_packet.o: fill_packet.h fill_packet.c
	gcc -c fill_packet.c -o fill_packet.o

main.o: main.c
	gcc -c main.c -o main.o

ipscanner: main.o fill_packet.o pcap.o
		   gcc main.o fill_packet.o pcap.o -lpcap -o ipscanner

clean:
	rm ipscanner *.o