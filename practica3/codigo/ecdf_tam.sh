#!/bin/bash


#Input: $1 = eth/http/dns, $2 = src/dst
MAC="00:11:88:CC:33:CA"

if [ "$2" != "src" ] && [ "$2" != "dst" ]
then
    echo "Argumento 2 erroneo: src/dst"
    exit -1
fi

if [ "$1" = "eth" ]
then
    FILTER="eth.$2==$MAC"; TAMANIO="frame.len"
elif [ "$1" = "http" ]
then
    FILTER="tcp.${2}port==80"; TAMANIO="ip.len"
elif [ "$1" = "dns" ]
then
    FILTER="udp.${2}port==53"; TAMANIO="ip.len"
else
    echo "Argumento 1 erroneo: http/dns/eth"
    exit -1
fi

#Si no existe, creamos dir apra guardar ficheros con tamanios.
#Guardamos en fichero tamanios deseados segun los inputs
DIR="data/ecdf_tam/"
mkdir -p $DIR
tshark -r traza.pcap -Y $FILTER -T fields -e $TAMANIO > "$DIR${1}_$2" 
