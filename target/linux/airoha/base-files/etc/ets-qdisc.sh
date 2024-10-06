#!/bin/sh

ifconfig lan1 192.168.83.115 up
tc qdisc replace dev eth0 root handle 1: ets bands 8 strict 8

tc filter add dev eth0 protocol ip parent 1: flower ip_proto tcp dst_port 6001 action skbedit queue 0
tc filter add dev eth0 protocol ip parent 1: flower ip_proto tcp dst_port 6002 action skbedit queue 1

tc qdisc show dev eth0
tc filter show dev eth0
