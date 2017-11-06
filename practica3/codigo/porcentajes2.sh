#!/bin/bash

tshark -r traza.pcap -E separator=: -T fields -e eth.type -e vlan.etype -e ip.proto > ./data/tipos

awk 'BEGIN{ FS=":"; lineas_totales=0; lineas_ip=0; lineas_udp=0; lineas_tcp=0; }
 {
	lineas_totales = lineas_totales + 1;

	if( $1 == "0x00000800" || $2 == "0x00000800" ){
		lineas_ip = lineas_ip + 1;

		if( $3 == "6")
			lineas_tcp = lineas_tcp + 1;
		else if( $3 == "17" )
			lineas_udp = lineas_udp + 1;
	}
} END{
	print "No IP\t", 100 - lineas_ip*100/lineas_totales, "%";
	print "IP\t", lineas_ip*100/lineas_totales, "%";

	print "\nEntre los paquetes IP tenemos:";
	print "UDP\t", lineas_udp*100/lineas_ip, "%";
	print "TCP\t", lineas_tcp*100/lineas_ip, "%";
	print "Otros\t", 100 - lineas_udp*100/lineas_ip - lineas_tcp*100/lineas_ip, "%";
}' ./data/tipos
