taskset -c $1 tcpreplay --preload-pcap --quiet --loop=0 --topspeed -i enp5s0f$1 10m_180f.pcap
