#!/bin/bash

#Este script devuelve por terminal el top 10 decidido segun los criterios dado en
#los argumentos de entrada
#Input: $1 = ip/tcp/udp, $2=src/dst $3=paquetes/bytes

#Preparamos el filtro
if [ "$1" == "ip" ] 
then
    LAYER="ip"
elif [ "$1" == "tcp" ]
then
    LAYER="tcp"
elif [ "$1" == "udp" ]
then
    LAYER="udp"
else
    echo "Argumento 1 erroneo: tcp/ip/udp src/dst paquetes/bytes"
    exit -1
fi

#Campo a mostrar por tshark dependiendo de $1 t $2
if [ "$2" == "src" ]
then
	WAY="${LAYER}.src"
elif [ "$2" == "dst" ]
then
	WAY="${LAYER}.dst"
else
	echo "Argumento 2 erroneo: tcp/ip/udp src/dst paquetes/bytes"
	exit -1
fi
#En el caso de tcp y udp el campo lleva al final el sufijo port :)
if [ "$1" != "ip" ]
then
	WAY="${WAY}port"
fi

#Comprobamos el tercer argumento
if [ "$3" != "paquetes" ] && [ "$3" != "bytes" ]
then
    echo "Argumento 3 erroneo: tcp/ip/udp src/dst paquetes/bytes"
    exit -1	
fi

#Guardamos en un fichero temporal el filtro de la traza para luego usar awk
tshark -r traza.pcap -E separator=, -Y $LAYER -T fields -e $WAY -e frame.len > temporal.top

#Segun el tercer argumentos realizamos el top
if [ "$3" == "paquetes" ]
then
    awk 'BEGIN{ FS=","; }{ npaquetes[$1]++ }
	END{ for(key in npaquetes){ printf "%s\t%d\tpaquetes\n", key, npaquetes[key] } }' temporal.top | sort -k 2 -nr | head -n 10
elif [ "$3" == "bytes" ]
then
    awk 'BEGIN{ FS=","; }{ nbytes[$1] += $2 }
	END{ for(key in nbytes){ printf "%s\t%d\tbytes\n", key, nbytes[key] } }' temporal.top | sort -k 2 -nr | head -n 10
fi
#Eliminamos el archivo temporal
rm temporal.top
