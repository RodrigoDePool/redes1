#!/bin/bash


#Script que dara ECDF de tiempo entre llegadas del flujo tcp/udp con src/dst segun los argumentos
#Se aplicara el filtro indicado en el generador

#input: tcp/udp dst/src

IP="63.161.195.170"
PORT="10455"

#Comprobamos input
if [ "$#" != "2" ]
then
	echo 'Introduzca dos argumentos: tcp/udp src/dst'
	exit -1
fi

#Creamos variables para filtrar en awk
if [ "$1" == "tcp" ] && [ "$2" == "src" ]
then
	COL=5
	CONDITION=IP
elif [ "$1" == "tcp" ] && [ "$2" == "dst" ]
then
	COL=4
	CONDITION=IP
elif [ "$1" == "udp" ] && [ "$2" == "src" ]
then
	COL=9
	CONDITION=PORT
elif [ "$1" == "udp" ] && [ "$2" == "dst" ]
then
	COL=8
	CONDITION=PORT
else
	echo 'Argumentos erroneos: tcp/udp src/dst'
	exit -1
fi


#Si no existe creamos el fichero de tshark
if ! [ -a tipos.tshark ]
then
	tshark -r traza.pcap -T fields -e eth.type -e vlan.etype -e ip.proto -e ip.dst -e ip.src -e tcp.dstport -e tcp.srcport -e udp.dstport -e udp.srcport -e frame.len -e ip.len -e frame.time_relative -e eth.dst -e eth.src > tipos.tshark
fi


#Si no existen creamos los directorios graficas y datos
mkdir -p graficas
mkdir -p datos


#AWK DE FILTRADO + GENERAR TODO CORRECTAMENTE

#En caso de que el filtro no deje pasar ningun paquete
if ! [ -s input.tmp ]
then
	echo 'No hay paquetes en '${2}' con el flujo '${1}', no se generara grafica'
	rm input.tmp
	exit -1
fi


./scripts/crearCDF input.tmp output.tmp

#Ejecutamos gnuplot
gnuplot << EOF
set autoscale
unset log
unset label
set title "Distribucion de variable aleaoria T = tiempo entre paquetes  \( flujo $2 con $1 \)"
set xlabel "tiempo \(segundos\)"
set ylabel "P\( T <= tiempo \)"
unset key
set terminal png size 800,600
set output "./graficas/out_flujo_${1}.png" 
plot "output.tmp" u 1:2 w steps
EOF

rm input.tmp
rm output.tmp

echo 'Grafica out_flujo_'${1}'_'${2}'.png creada en el directorio graficas'

exit 0
