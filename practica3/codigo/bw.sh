#!/bin/bash

if [ "$1" != "dst" ] && [ "$1" != "src" ]
then
    echo "Argumento invalido: src/dst"
    exit -1
fi

MAC="00:11:88:CC:33:CA"

#Si no existe, creamos directorio para guardar ficheros
DIR="data/bandwidth/"
mkdir -p $DIR

#En AUX_FILE volcamos la salida de tshark, en PLOT_FILE el array que relaciona segundo-bytes
AUX_FILE="${DIR}aux"
PLOT_FILE="${DIR}bandwidth_$1"


tshark -r traza.pcap -Y "eth.${1}==$MAC" -T fields -e frame.time_relative -e frame.len > $AUX_FILE

#Ahora hay que agrupar los tamanios en segundos
#En el END, los imprimimos y redireccionamos al fichero $FILE
awk 'BEGIN{}{
    nbytes[int($1)] += $2;
}END{
    for(key in nbytes) {printf "%d %d\n", key, nbytes[key]*8 }
}' $AUX_FILE | sort -k 1 -n > $PLOT_FILE

rm $AUX_FILE

gnuplot -p <<-EOFMarker
set autoscale
unset log
unset label
set title "Ancho de banda a nivel 2 con la MAC $MAC como $1"
set xlabel "Tiempo (segundos)"
set ylabel "Ancho de banda (bits/segundo)"
unset key
set terminal png size 800,600 
set output "$PLOT_FILE.png"
plot "$PLOT_FILE" u 1:2 w lines
exit
EOFMarker

rm $PLOT_FILE
