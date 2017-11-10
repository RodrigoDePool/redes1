#!/bin/bash

#Este script se encarga de crear una grafica con el ancho de banda por segundo
#en subida o bajada segun el argumento dado. Solo se toma en cuenta la MAC dada por el generador

#input: src/dst

MAC="00:11:88:CC:33:CA"

#Comprobamos cantidad de argumentos
if [ "$#" != "1" ]
then
	echo 'Cantidad de argumentos erronea: src/dst'
fi

#Establecemos filtros
if [ "$1" == "src" ]
then
	FILTER="eth.src==${MAC}"
elif [ "$1" == "dst" ]
then
	FILTER="eth.dst==${MAC}"
else
	echo 'Argumento erroneo: src/dst'
	exit -1
fi

#Filtramos por MAC dst/src y las organizamos por tiempo
tshark -r traza.pcap  -Y "$FILTER" -T fields -e frame.len -e frame.time_relative | sort -n -k 2 > tiempo.tmp

#Generamos fichero con segundo bits_de_ese_segundo
awk 'BEGIN{FS="\t"; secs=1;}
{
	if($2<secs){ bytes[secs]+=$1 }else{ secs++; }
} END{ for(time=1; time<=secs; time++){printf "%d %f\n",time,bytes[time] } }' tiempo.tmp > input.tmp


#Generamos png
gnuplot << EOF
set autoscale
unset log
unset label
set title "Ancho de banda a nivel 2 con la MAC $MAC como $1"
set xlabel "Tiempo (segundos)"
set ylabel "Ancho de banda (bits/segundo)"
unset key
set terminal png size 800,600 
set output "./graficas/bandwidth_${1}.png"
plot "input.tmp" u 1:2 w steps
exit
EOF


rm tiempo.tmp
rm input.tmp

echo 'Grafica bandwidth_'${1}'.png creada en el directorio graficas'
