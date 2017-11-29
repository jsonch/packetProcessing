#!/bin/bash
calc(){ awk "BEGIN { print "$*" }"; }

INTERVAL="1"  # update interval in seconds
 
if [ -z "$1" ]; then
        echo
        echo usage: $0 [network-interface]
        echo
        echo e.g. $0 eth0
        echo
        echo shows packets-per-second
        exit
fi
 
IF=$1
 
while true
do
        R1=`cat /sys/class/net/$1/statistics/rx_bytes`
        T1=`cat /sys/class/net/$1/statistics/tx_bytes`
        sleep $INTERVAL
        R2=`cat /sys/class/net/$1/statistics/rx_bytes`
        T2=`cat /sys/class/net/$1/statistics/tx_bytes`
        TXBPS=`expr $T2 - $T1`
        RXBPS=`expr $R2 - $R1`
	TXMBPS=`expr $TXBPS / 1000000`
	RXMBPS=`expr $RXBPS / 1000000`
        echo "TX $1: $TXMBPS MB/s RX $1: $RXMBPS MB/s"
done
