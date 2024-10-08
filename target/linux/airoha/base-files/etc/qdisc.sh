#!/bin/sh

ifconfig lan1 192.168.83.115 up
tc qdisc replace dev eth0 root handle 1: tbf rate 400mbit burst 10kb limit 1M
tc qdisc replace dev eth0 parent 1: handle 2: ets bands 8 strict 8
#tc qdisc add dev eth0 clsact

#tc filter add dev eth0 protocol ip egress flower ip_proto tcp dst_port 6001 action skbedit queue 0 flowid 1:1
#tc filter add dev eth0 protocol ip egress flower ip_proto tcp dst_port 6002 action skbedit queue 1 flowid 1:2

#tc filter add dev eth0 protocol ip parent 1: flower ip_proto tcp dst_port 6001 action skbedit queue 0 flowid 1:1
#tc filter add dev eth0 protocol ip parent 1: flower ip_proto tcp dst_port 6002 action skbedit queue 1 flowid 1:2

tc filter add dev eth0 protocol ip parent 2: flower ip_proto tcp dst_port 6001 action skbedit queue 0
tc filter add dev eth0 protocol ip parent 2: flower ip_proto tcp dst_port 6002 action skbedit queue 1

tc qdisc show dev eth0
tc filter show dev eth0 parent 2:

# channel 1 queue 0
#devmem 0x1fb54400 32 0x80000008
# channel 1 queue 1
#devmem 0x1fb54408 32 0x80000009

sleep 1
ping -c 3 192.168.83.120
#iperf3 -c 192.168.83.120 -p6002 -t 120 > /dev/null & sleep 1; iperf3 -c 192.168.83.120 -p6001 -t 120 > /dev/null &
#sleep 1

#while sleep 1; do
#clear
#echo "CHAN 1 QUEUE 0: $(devmem 0x1fb54404)"
#echo "CHAN 1 QUEUE 1: $(devmem 0x1fb5440c)"
#done
