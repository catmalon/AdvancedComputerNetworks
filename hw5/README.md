# IP SCANNER (ICMP Request & Reply)
- **OS** Ubuntu 1604 (libpcap-dev 1.7.4)
- **Makefile**
## Usage
1. Error message when the program isn’t executedby superuser privileges   
![image](https://user-images.githubusercontent.com/75157669/118087395-16295180-b3f8-11eb-9a7b-ea1b17684204.png)

2. Use “./ipscanner -help” to show commands    
![image](https://user-images.githubusercontent.com/75157669/118087245-d6626a00-b3f7-11eb-88e6-e95ded397b13.png)

3. Use “./ipscanner -i [Network Interface Name] -t [timeout(ms)]” 
![image](https://user-images.githubusercontent.com/75157669/118087899-d57e0800-b3f8-11eb-9293-eac64defdb53.png)


## Bugs about libpcap-dev for Pcap

The "timeout" function in "pcap" will be stuck when run in the Ubuntu 18.04.
The description of the problem is as follows:
  https://bugs.launchpad.net/ubuntu/+source/libpcap/+bug/1825106

The pcap can run in libpcap-dev 1.7.4 well.
https://www.tcpdump.org/#latest-release
