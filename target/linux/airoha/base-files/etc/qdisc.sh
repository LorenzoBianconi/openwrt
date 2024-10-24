#!/bin/sh

IP=192.168.83.115
DST=192.168.83.120
RATE=100000
NSTRICT=8
#QUANTA="quanta 3528 1514 1514 1514 1514 1514"
QUANTA=""
PORT0=6001
QUEUE0=1
PORT1=6002
QUEUE1=5
TIME=30

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
sleep 2
#for i in $(seq 8); do
#echo $RATE > /sys/class/net/eth0/queues/tx-$i/tx_maxrate
#done
echo $RATE > /sys/class/net/eth0/queues/tx-1/tx_maxrate

tc filter del dev eth0 egress
# Comment it out to be fully offloaded
#tc qdisc replace dev eth0 root handle 1: ets bands 8 strict $NSTRICT $QUANTA priomap 7 6 5 4 3 2 1 0
tc qdisc add dev eth0 clsact
sleep 2
tc filter add dev eth0 protocol ip egress flower ip_proto tcp dst_port $PORT0 action skbedit queue $QUEUE0
tc filter add dev eth0 protocol ip egress flower ip_proto tcp dst_port $PORT1 action skbedit queue $QUEUE1

tc qdisc show dev eth0
tc filter show dev eth0 egress
cat /sys/kernel/debug/airoha-eth:1/qos-tx-meters
sleep 5

iperf3 -c $DST -p $PORT0 -t $((TIME*30)) > /dev/null &
for i in $(seq 15); do
	sleep 30
	iperf3 -c $DST -p $PORT1 -t $TIME > /dev/null
done
