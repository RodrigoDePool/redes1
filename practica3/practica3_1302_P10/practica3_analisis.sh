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
#col4: ipdst      col5: ipsrc       col6: tcp.portdst
#col7: tcp.portsrc col8: udp.portdst col9: udp.portsrc
#col10: tamano_paq  col11: tamano_ip  col12: tiempo_rel
#col13: MAC dst     col14: MAC src
if ! [ -a tipos.tshark ]
then
    tshark -r traza.pcap -T fields -e eth.type -e vlan.etype -e ip.proto -e ip.dst -e ip.src -e tcp.dstport -e tcp.srcport -e udp.dstport -e udp.srcport -e frame.len -e ip.len -e frame.time_relative -e eth.dst -e eth.src > tipos.tshark
fi

echo 'Porcentajes de paquetes por protocolo:'
bash scripts/porcentajes.sh
echo ''

echo 'Top 10 IP SRC PAQUETES'
bash scripts/scriptTop.sh ip src paquetes 
echo ''

echo 'Top 10 IP SRC BYTES'
bash scripts/scriptTop.sh ip src bytes 
echo ''

echo 'Top 10 IP DST PAQUETES'
bash scripts/scriptTop.sh ip dst paquetes 
echo ''

echo 'Top 10 IP DST BYTES'
bash scripts/scriptTop.sh ip dst bytes 
echo ''

echo 'Top 10 TCP SRC PAQUETES'
bash scripts/scriptTop.sh tcp src paquetes 
echo ''

echo 'Top 10 TCP SRC BYTES'
bash scripts/scriptTop.sh tcp src bytes 
echo ''

echo 'Top 10 TCP DST PAQUETES'
bash scripts/scriptTop.sh tcp dst paquetes 
echo ''

echo 'Top 10 TCP DST BYTES'
bash scripts/scriptTop.sh tcp dst bytes 
echo ''

echo 'Top 10 UDP SRC PAQUETES'
bash scripts/scriptTop.sh udp src paquetes 
echo ''

echo 'Top 10 UDP SRC BYTES'
bash scripts/scriptTop.sh udp src bytes 
echo ''

echo 'Top 10 UDP DST PAQUETES'
bash scripts/scriptTop.sh udp dst paquetes 
echo ''

echo 'Top 10 UDP DST BYTES'
bash scripts/scriptTop.sh udp dst bytes 
echo ''

#Creacion de ecdfs por tamano

echo 'ECDFs de tamanos'
echo ''
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
echo 'ECDFs de tiempos'
echo ''
bash scripts/ecdf_tiempo.sh tcp src
echo ''
bash scripts/ecdf_tiempo.sh tcp dst
echo ''
bash scripts/ecdf_tiempo.sh udp src
echo ''
bash scripts/ecdf_tiempo.sh udp dst
echo ''

#Medicion de ancho de banda
echo 'Grafica de anchos de banda'
echo ''
bash scripts/bandwidth.sh src
echo ''
bash scripts/bandwidth.sh dst
echo ''
