echo "sudo tcpreplay --p 10000 -i eth1 $1"
echo "sudo ifconfig vf0 promisc"
echo "sudo ifconfig vf1 promisc"
echo "sudo ./pps.sh vf0"
