# ARP Request and Reply and spoof program
- **OS: Ubuntu 1804**
- **Makefile**

## PART 1: Requset
1. Error message when the program isn’t executedby superuser privileges
![root](https://user-images.githubusercontent.com/75157669/117762602-10970480-b25c-11eb-95e9-ff9ea4c8c429.png)

2. Use “./arp -help” to show all commands
![help](https://user-images.githubusercontent.com/75157669/117762980-a0d54980-b25c-11eb-83f5-395ad3bb02cf.png)

3. Use “./arp -l -a” command to show all of the ARP packets
![la](https://user-images.githubusercontent.com/75157669/117763038-b5b1dd00-b25c-11eb-9fb5-3c15f524f106.png)

4. Use “./arp -l <filter_ip_address>” command to implement the filter work. Thus, it show specific ARP packets
![addr](https://user-images.githubusercontent.com/75157669/117763086-cc583400-b25c-11eb-9d8b-a4be5ee07501.png)

## PART 2: Reply
1. Use “./arp -l <filter_ip_address>” to listen the packets
![addr](https://user-images.githubusercontent.com/75157669/117764147-987e0e00-b25e-11eb-885c-99858874b68b.png)

2. Use “./arp -q <query_ip_address>” to query the mac address of specific IP (send ARP )
![query](https://user-images.githubusercontent.com/75157669/117764197-ad5aa180-b25e-11eb-8515-9a323d28ae08.png)

- Wireshark

**Request**

![shark_request](https://user-images.githubusercontent.com/75157669/117764388-f90d4b00-b25e-11eb-85c6-c107bf38682d.png)

**Reply**

![shark_reply](https://user-images.githubusercontent.com/75157669/117764407-ff9bc280-b25e-11eb-8540-9e79291dfeae.png)

## PART 3: Spoof
1. Use “./arp <fake_mac_address> <taget_ip_address>” 

When program receive an ARP request for <taget_ip_address> (140.117.171.172), send a <fake_mac_address> (00:11:22:33:44:55) reply
![spoof](https://user-images.githubusercontent.com/75157669/117764905-c6178700-b25f-11eb-971b-448de7c0f709.png)

