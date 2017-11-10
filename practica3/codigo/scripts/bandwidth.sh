#!/bin/bash

#Este script se encarga de crear una grafica con el ancho de banda por segundo
#en subida o bajada segun el argumento dado. Solo se toma en cuenta la MAC dada por el generador

#input: src/dst

MAC="00:11:88:cc:33:ca"

#Comprobamos cantidad de argumentos
if [ "$#" != "1" ]
then
	echo 'Cantidad de argumentos erronea: src/dst'
fi

#Si no existe el directorio datos y graficas los crea
mkdir -p datos
mkdir -p graficas

#Si no existe el tipo.tshark lo creamos
if ! [ -a tipos.tshark ]
then
	tshark -r traza.pcap -T fields -e eth.type -e vlan.etype -e ip.proto -e ip.dst -e ip.src -e tcp.dstport -e tcp.srcport -e udp.dstport -e udp.srcport -e frame.len -e ip.len -e frame.time_relative -e eth.dst -e eth.src > tipos.tshark
fi

#Columna a filtrar por awk
if [ "$1" == "src" ]
then
	COL=14
elif [ "$1" == "dst" ]
then
	COL=13
else
	echo 'Argumento erroneo: src/dst'
	exit -1
fi

#Generamos fichero con segundo bits_de_ese_segundo en directorio datos
awk -v col=${COL} -v mac=${MAC} 'BEGIN{ FS="\t"; maxsecs=0; }
{
	if( $col == mac ){ bytes[int($12)]+=$10; if(int($12)>maxsecs) maxsecs=int($12); }
} END{ for(time=0; time<=maxsecs; time++){ printf "%d\t%f\n",time,bytes[time] } }' tipos.tshark > datos/bandwidth_${1}


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
plot "datos/bandwidth_${1}" u 1:2 w steps
exit
EOF


echo 'Datos de bandwidth_'${1}' creada en el directorio datos'
echo 'Grafica bandwidth_'${1}'.png creada en el directorio graficas'
