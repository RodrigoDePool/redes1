#!/bin/bash

$(tshark -r traza.pcap -E separator=: -T fields -e eth.type -e vlan.etype -e ip.proto > tipos)
total=$(cat tipos | wc -l)
$(cat tipos | grep 0800 > tiposIP)

paquetesIP=$(cat tiposIP | wc -l)
paquetesUDP=$(cat tiposIP | grep 17 | wc -l)
paquetesTCP=$(cat tiposIP | grep 6 | wc -l)

