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
DIR="data/ecdf_tam/"
mkdir -p $DIR
#Necesitamos ficheros input y output para crearCDF.c
#Formato input: data/ecdf_tam/in_dns_src | Formato output: data/ecdf_tam/out_dns_src 
ECDF_INPUT="${DIR}in_${1}_$2"
ECDF_OUTPUT="${DIR}out_${1}_$2"
#Guardamos en fichero tamanios deseados segun los inputs
tshark -r traza.pcap -Y $FILTER -T fields -e $TAMANIO > $ECDF_INPUT

#ES HORA DE GNUPLOTTEAR :D
make
./crearCDF $ECDF_INPUT $ECDF_OUTPUT

gnuplot -p <<-EOFMarker
set autoscale
unset log
unset label
set title "Distribucion de variable aleaoria T = 'tamanio paquetes $1 \($2\)'"
set xlabel "tamanio \(bytes\)"
set ylabel "P\(T <= tamanio\)"
unset key
set terminal png size 800,600 
set output "$ECDF_OUTPUT.png"
plot "$ECDF_OUTPUT" u 1:2 w lines
exit
EOFMarker

#Para futuro @TODO : ¿borrar archivo ecdf_output y ecdf_input?
rm $ECDF_OUTPUT
rm $ECDF_INPUT

exit 0
