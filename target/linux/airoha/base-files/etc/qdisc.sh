#!/bin/sh

IP=192.168.83.115
DST=192.168.83.120
RATE=500mbit
PORT0=6001
QUEUE0=0
PORT1=6002
QUEUE1=5

brctl addbr br0
sleep 1
for i in $(seq 4); do
	ip link set dev lan$i up
	brctl addif br0 lan$i
done
ip a a $IP/24 dev br0
ip link set dev br0 up
sleep 2
ping -c 3 $DST

#tc qdisc replace dev eth0 root handle 1: tbf rate $RATE burst 10kb limit 1M
#tc qdisc replace dev eth0 parent 1: handle 2: ets bands 8 strict 8
tc qdisc replace dev eth0 root handle 1: ets bands 8 strict 2 quanta 3528 1514 1514 1514 1514 1514
sleep 1
#tc qdisc add dev eth0 clsact

#tc filter add dev eth0 protocol ip egress flower ip_proto tcp dst_port 6001 action skbedit queue 0 flowid 1:1
#tc filter add dev eth0 protocol ip egress flower ip_proto tcp dst_port 6002 action skbedit queue 1 flowid 1:2

tc filter add dev eth0 protocol ip parent 1: flower ip_proto tcp dst_port $PORT0 action skbedit queue $QUEUE0
tc filter add dev eth0 protocol ip parent 1: flower ip_proto tcp dst_port $PORT1 action skbedit queue $QUEUE1

#tc filter add dev eth0 protocol ip parent 2: flower ip_proto tcp dst_port 6001 action skbedit queue 0
#tc filter add dev eth0 protocol ip parent 2: flower ip_proto tcp dst_port 6002 action skbedit queue 1

tc qdisc show dev eth0
tc filter show dev eth0 parent 1:

iperf3 -c $DST -p $PORT1 -t 120 > /dev/null & sleep 1; iperf3 -c $DST -p $PORT0 -t 120 > /dev/null &
while sleep 1; do
clear
cat /sys/kernel/debug/airoha-eth:1/qos-tx-counters
done
#sleep 1

#while sleep 1; do
#clear
#echo "CHAN 1 QUEUE 0: $(devmem 0x1fb54404)"
#echo "CHAN 1 QUEUE 1: $(devmem 0x1fb5440c)"
#done
