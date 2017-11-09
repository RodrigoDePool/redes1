#!/bin/bash

#Este script devuelve por terminal el top 10 decidido segun los argumentos de entrada
#Adicionalmente, genera un fichero en data/top con los datos asociados a ese top 10 (direccion numpaquetes numbytes).
#El nombre del fichero es autodescriptivo: tcp.dstport.paquetes guarda el top 10 en paquetes de puertos tcp destino

#Input: $1 = ip/tcp/udp, $2=src/dst $3=paquetes/bytes
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

# Si no existia anteriormente, creamos el directorio "data/top/" donde almacenar resultados
DIR="./data/top/"
mkdir -p $DIR
# Leemos los paquetes ip e imprimimos su ip origen y tamanio paquete

tshark -r traza.pcap -E separator=, -Y $LAYER -T fields -e $WAY -e frame.len > $WAY

awk 'BEGIN{ FS=",";}{
        
        npaquetes[$1] ++;
        nbytes[$1] += $2;
}
END{
   for (key in npaquetes) {printf "%s %d paquetes %d bytes\n", key, npaquetes[key], nbytes[key] }
}' $WAY | sort -k $K -nr | head -n 10 > "$DIR$WAY.$3"

rm $WAY

awk 'BEGIN{}{print $1}END{}' "$DIR$WAY.$3"

