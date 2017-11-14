#!/bin/bash


#Script que dara ECDF de tiempo entre llegadas del flujo tcp/udp con src/dst segun los argumentos
#Se aplicara el filtro indicado en el generador

#input: tcp/udp dst/src

#Filtro por IP en el caso de TCP y filtro por PUERTO en el caso de UDP
IP="63.161.195.170"
PORT="10455"

#Comprobamos input
if [ "$#" != "2" ]
then
	echo 'Introduzca dos argumentos: tcp/udp src/dst'
	exit -1
fi

#Creamos variables para filtrar en awk (Columna a comparar con la condicion)
if [ "$1" == "tcp" ] && [ "$2" == "src" ]
then
	COL=5
	CONDITION=${IP}
elif [ "$1" == "tcp" ] && [ "$2" == "dst" ]
then
	COL=4
	CONDITION=${IP}
elif [ "$1" == "udp" ] && [ "$2" == "src" ]
then
	COL=9
	CONDITION=${PORT}
elif [ "$1" == "udp" ] && [ "$2" == "dst" ]
then
	COL=8
	CONDITION=${PORT}
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

#Pequeno resumen del funcionamiento de este awk criptico:
# El primer if dejara pasar a todos los paquetes en caso de UDP
# en caso de TCP comprobara que en efecto el paquete es tcp (viendo que uno de sus ports no es null)
# El segundo if comprueba la condicion de filtrado (para tcp por ip y para udp por puerto)
# Finalmente se encarga de generar los interarrivals a partir de los tiempos relativos
# en el caso de ser el primer paquete pone el interarrival a 0, en otro caso hace la resta entre
# los tiempos.
awk -v col=$COL -v cond=${CONDITION} -v prot=$1 'BEGIN{ FS="\t"; anterior=0; }{
	if( prot != "tcp" || $6 != null ){
		if( $col == cond ){
			if( anterior == 0 ) interarrival=0;
			else 				interarrival=$12-anterior;
			printf "%f\n",interarrival;
			anterior=$12;
		}
	}

}' tipos.tshark > input.tmp

#En caso de que el filtro no deje pasar ningun paquete
if ! [ -s input.tmp ]
then
	echo 'No hay paquetes en '${2}' con el flujo '${1}', no se generara grafica'
	rm input.tmp
	exit -1
fi

#Generamos el ECDF con el input y lo guardamos en datos
./scripts/crearCDF input.tmp datos/flujo_${1}_${2}

#En caso de ser TCP utilizamos escala logaritmica en eje X, en caso UDP
#Utilizamos escala normal
if [ "$1" == "tcp" ]
then
	SCALE="set log x"
else
	SCALE="unset log x"
fi

#Ejecutamos gnuplot
gnuplot << EOF
set autoscale
${SCALE}
unset label
set title "Distribucion de variable aleaoria T = tiempo entre paquetes  \( flujo $2 con $1 \)"
set xlabel "tiempo \(segundos\)"
set ylabel "P\( T <= tiempo \)"
unset key
set terminal png size 800,600
set output "./graficas/flujo_${1}_${2}.png" 
plot "datos/flujo_${1}_${2}" u 1:2 w steps
EOF

#Eliminamos el input temporal
rm input.tmp

echo 'Datos de flujo_'${1}'_'${2}' creada en el directorio datos'
echo 'Grafica flujo_'${1}'_'${2}'.png creada en el directorio graficas'

exit 0
