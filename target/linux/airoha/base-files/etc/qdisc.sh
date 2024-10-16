#!/bin/sh

IP=192.168.83.115
DST=192.168.83.120
RATE=500mbit
NSTRICT=8
#QUANTA="quanta 3528 1514 1514 1514 1514 1514"
QUANTA=""
PORT0=6001
QUEUE0=0
FLOWID0=""
#FLOWID0="flowid 1:1"
PRIO0=2
PORT1=6002
QUEUE1=5
PRIO1=3
#FLOWID1="flowid 1:2"
FLOWID1=""
TIME=60

brctl addbr br0
sleep 1
for i in $(seq 4); do
	ip link set dev lan$i up
	brctl addif br0 lan$i
done
ip a a $IP/24 dev br0
ip link set dev br0 up
sleep 2
ping -c 10 $DST

#tc qdisc replace dev eth0 root handle 1: tbf rate $RATE burst 10kb limit 1M
tc filter del dev eth0 egress
#tc qdisc replace dev eth0 root handle 1: ets bands 8 strict $NSTRICT $QUANTA
tc qdisc add dev eth0 clsact
sleep 2
tc filter add dev eth0 protocol ip egress flower ip_proto tcp dst_port $PORT0 action skbedit queue $QUEUE0 $FLOWID0
tc filter add dev eth0 protocol ip egress flower ip_proto tcp dst_port $PORT1 action skbedit queue $QUEUE1 $FLOWID1

tc qdisc show dev eth0
tc filter show dev eth0 egress

iperf3 -c $DST -p $PORT0 -t $((TIME*10)) > /dev/null &
for i in $(seq 3); do
	sleep 10
	iperf3 -c $DST -p $PORT1 -t $TIME > /dev/null
done &
while sleep 1; do
clear
cat /sys/kernel/debug/airoha-eth:1/qos-tx-counters
done
