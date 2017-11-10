#!/bin/bash


#Wrapper que realiza todas las acciones pedidas en la practica


#Creamos el directorio graficas y datos si no existen
mkdir -p graficas
mkdir -p datos
#Compilamos el script en C para crear ECDF
make --quiet

#Si no existe el fichero tipos.tshark lo creamos
#Tiene traza con el siguiente formato
#col1: tipo_eth   col2: tipo_vlan   col3: protocolo_ip
#col4: ipdst      col5: ipsrc		col6: tcp.portdst
#col7: tcp.portsrc col6: udp.portdst col7: udp.portsrc
#col8: tamano_paq  col9: tamano_ip  col10: tiempo_rel
if ! [ -a tipos.tshark ]
then
	tshark -r traza.pcap -E separator=: -T fields -e eth.type -e vlan.etype -e ip.proto -e ip.dst -e ip.src -e tcp.dstport -e tcp.srcport -e udp.dstport -e udp.srcport -e frame.len -ip.len -e frame.time_relative > tipos.tshark
fi

echo 'Porcentajes de paquetes por protocolo:'
bash scripts/porcentajes.sh #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 IP SRC PAQUETES'
bash scripts/scriptTop.sh ip src paquetes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 IP SRC BYTES'
bash scripts/scriptTop.sh ip src bytes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 IP DST PAQUETES'
bash scripts/scriptTop.sh ip dst paquetes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 IP SRC BYTES'
bash scripts/scriptTop.sh ip dst bytes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 TCP SRC PAQUETES'
bash scripts/scriptTop.sh tcp src paquetes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 TCP SRC BYTES'
bash scripts/scriptTop.sh tcp src bytes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 TCP DST PAQUETES'
bash scripts/scriptTop.sh tcp dst paquetes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 TCP SRC BYTES'
bash scripts/scriptTop.sh tcp dst bytes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 UDP SRC PAQUETES'
bash scripts/scriptTop.sh udp src paquetes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 UDP SRC BYTES'
bash scripts/scriptTop.sh udp src bytes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 UDP DST PAQUETES'
bash scripts/scriptTop.sh udp dst paquetes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 UDP SRC BYTES'
bash scripts/scriptTop.sh udp dst bytes #Hara falta meterlo en un fichero ??
echo ''

#Creacion de ecdfs por tamano
bash scripts/ecdf_tam.sh eth src
echo ''
bash scripts/ecdf_tam.sh eth dst
echo ''
bash scripts/ecdf_tam.sh http src
echo ''
bash scripts/ecdf_tam.sh http dst
echo ''
bash scripts/ecdf_tam.sh dns src
echo ''
bash scripts/ecdf_tam.sh dns dst
echo ''

#Creacion de ecdfs por tiempo
bash scripts/ecdf_tiempo.sh tcp src
echo ''
bash scripts/ecdf_tiempo.sh tcp dst
echo ''
bash scripts/ecdf_tiempo.sh udp src
echo ''
bash scripts/ecdf_tiempo.sh udp dst
echo ''

#Medicion de ancho de banda
bash scripts/bandwidth.sh src
echo ''
bash scripts/bandwidth.sh dst
echo ''
