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
elif [ "$2" != "dst" ] && [ "$2" != "src" ]
then
	echo 'error en el segundo argumento'
	exit -1
fi

#Creamos filtros
if [ "$1" == "tcp" ]
then
	FILTER="tcp and ip.${2}==63.161.195.170";
elif [ "$1" == "udp" ]
then
	FILTER="udp.${2}port==10455";
else
	echo 'Argumento erroneo: tcp/udp'
	exit -1
fi

tshark -r traza.pcap -E separator=, -Y "$FILTER" -T fields -e frame.time_delta_displayed > input.tmp

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
