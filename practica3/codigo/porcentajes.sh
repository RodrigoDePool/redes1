#!/bin/bash

$(tshark -r traza.pcap -E separator=: -T fields -e eth.type -e vlan.etype -e ip.proto > ./data/tipos)
total=$(cat ./data/tipos | wc -l)
$(cat ./data/tipos | grep 0800 > ./data/tiposIP)

paquetesIP=$(cat ./data/tiposIP | wc -l)
paquetesUDP=$(cat ./data/tiposIP | grep 17 | wc -l)
paquetesTCP=$(cat ./data/tiposIP | grep 6 | wc -l)

