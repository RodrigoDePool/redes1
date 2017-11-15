#!/bin/bash

#Este script devuelve por terminal el top 10 decidido segun los criterios dado en
#los argumentos de entrada
#Input: $1 = ip/tcp/udp, $2=src/dst $3=paquetes/bytes

TAM_PAQ="10"
IP_SRC="5"
IP_DST="4"
TCP_SRC="7"
TCP_DST="6"
UDP_SRC="9"
UDP_DST="8"

#Creamos el fichero tshark si no existe ya 
if ! [ -a tipos.tshark ]
then
    tshark -r traza.pcap -T fields -e eth.type -e vlan.etype -e ip.proto -e ip.dst -e ip.src -e tcp.dstport -e tcp.srcport -e udp.dstport -e udp.srcport -e frame.len -e ip.len -e frame.time_relative -e eth.dst -e eth.src > tipos.tshark
fi


#Asignamos columnas a checkear en funcion de $1 y $2
if [ "$2" != "src" ] && [ "$2" != "dst" ]; then echo "Arg 2 erroneo: tcp/ip/udp src/dst paquetes/bytes"; exit -1; fi

if [ "$1" == "ip" ]; then
    if [ "$2" = "src" ]; then PORT_COL=$IP_SRC;
    elif [ "$2" = "dst" ]; then PORT_COL=$IP_DST; fi;
elif [ "$1" == "tcp" ]; then
    if [ "$2" = "src" ]; then PORT_COL=$TCP_SRC;
    elif [ "$2" = "dst" ]; then PORT_COL=$TCP_DST; fi;
elif [ "$1" == "udp" ]; then
    if [ "$2" = "src" ]; then PORT_COL=$UDP_SRC;
    elif [ "$2" = "dst" ]; then PORT_COL=$UDP_DST; fi;
else
    echo "Argumento 1 erroneo: tcp/ip/udp src/dst paquetes/bytes"
    exit -1
fi

#Comprobamos el tercer argumento
if [ "$3" != "paquetes" ] && [ "$3" != "bytes" ]
then
    echo "Argumento 3 erroneo: tcp/ip/udp src/dst paquetes/bytes"
    exit -1 
fi

#Segun el tercer argumentos realizamos el top
if [ "$3" == "paquetes" ]; then
    awk -v port_col=$PORT_COL 'BEGIN{ FS="\t"; }{ if($port_col != null){npaquetes[$port_col]++} }
    END{ for(key in npaquetes){ printf "%s\t%d\tpaquetes\n", key, npaquetes[key] } }' tipos.tshark | sort -k 2 -nr | head -n 10
elif [ "$3" == "bytes" ]; then
    awk -v port_col=$PORT_COL -v tam_paq=$TAM_PAQ 'BEGIN{ FS="\t"; }{ if($port_col != null){nbytes[$port_col] += $tam_paq} }
    END{ for(key in nbytes){ printf "%s\t%d\tbytes\n", key, nbytes[key] } }' tipos.tshark | sort -k 2 -nr | head -n 10
fi
#Eliminamos el archivo temporal
#rm temporal.top

exit 0
