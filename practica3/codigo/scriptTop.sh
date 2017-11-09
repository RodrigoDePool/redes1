#!/bin/bash

#Input: $1 = ip/tcp, $2=src/dst
if [ "$1" = "ip" ] 
then
    LAYER="ip"
    if [ "$2" = "src" ]
    then
        WAY="ip.src"
    elif [ "$2" = "dst" ]
    then
        WAY="ip.dst"
    else
        echo "Argumento erroneo: src/dst"
        exit -1
    fi
elif [ "$1" = "tcp" ]
then
    LAYER="tcp"
    if [ "$2" = "src" ]
    then
        WAY="tcp.srcport"
    elif [ "$2" =  "dst" ]
    then
        WAY="tcp.dstport"
    else
        echo "Argumento erroneo: src/dst"
        exit -1
    fi
elif [ "$1" = "udp" ]
then
    LAYER="udp"
    if [ "$2" = "src" ]
    then
        WAY="udp.srcport"
    elif [ "$2" =  "dst" ]
    then
        WAY="udp.dstport"
    else
        echo "Argumento erroneo: src/dst"
        exit -1
    fi
else
    echo "Argumento erroneo: tcp/ip/udp src/dst paquetes/bytes"
    exit -1
fi
#Input: $3 = paquetes/bytes
if [ "$3" = "paquetes" ]
then
    K=2
elif [ "$3" = "bytes" ]
then
    K=4
else
    echo "Argumento 3 erroneo: tcp/ip/udp src/dst paquetes/bytes"
    exit -1
fi

# Leemos los paquetes ip e imprimimos su ip origen y tamanio paquete

tshark -r traza.pcap -E separator=, -Y $LAYER -T fields -e $WAY -e frame.len > $WAY

awk 'BEGIN{ FS=",";}{
        
        npaquetes[$1] ++;
        nbytes[$1] += $2;
}
END{
   for (key in npaquetes) {printf "%s %d paquetes %d bytes\n", key, npaquetes[key], nbytes[key] }
}' $WAY | sort -k $K -nr | head -n 10 > "$WAY.txt"

rm $WAY

awk 'BEGIN{}{print $1}END{}' "$WAY.txt"

