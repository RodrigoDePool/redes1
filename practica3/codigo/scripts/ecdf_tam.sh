#!/bin/bash

#Este script se encarga de generar las graficas que corresponden a los ECDFs de:
# tamano a nivel 2 (solo de la MAC dada), tamanio a nivel 3 (una para HTTP y una para DNS)

#Input: $1 = eth/http/dns, $2 = src/dst

MAC="00:11:88:CC:33:CA"

#Probamos argumentos, establecemos filtro y nivel de filtrado
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

if [ "$2" != "src" ] && [ "$2" != "dst" ]
then
    echo "Argumento 2 erroneo: src/dst"
    exit -1
fi

#Guardamos en fichero tamanios deseados en inputs
tshark -r traza.pcap -Y $FILTER -T fields -e $TAMANIO > input.tmp

#Ejecutamos creador de ECDFs
./scripts/crearCDF input.tmp output.tmp

#Ejecutamos gnuplot
gnuplot << EOF
set autoscale
unset log
unset label
set title "Distribucion de variable aleaoria T = tamanio paquetes ${1} \(${2}\)"
set xlabel "tamanio \(bytes\)"
set ylabel "P\( T <= tamanio \)"
unset key
set terminal png size 800,600
set output "./graficas/out_${1}_${2}.png" 
plot "output.tmp" u 1:2 w lines
EOF

rm input.tmp
rm output.tmp

echo 'Grafica out_'${1}'_'${2}'.png creada en el directorio graficas'

exit 0
