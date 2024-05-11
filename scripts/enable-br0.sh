sudo mkdir /etc/qemu
sudo echo "allow br0" >> /etc/qemu/bridge.conf
sudo ip link add br0 type bridge
sudo ip addr add 192.168.0.1/24 dev br0
sudo ip link set br0 up
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t filter -A FORWARD -i br0 -j ACCEPT
sudo iptables -t filter -A FORWARD -o br0 -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o enp0s31f6 -j MASQUERADE
