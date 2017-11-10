#!/bin/bash


#Wrapper que realiza todas las acciones pedidas en la practica

#Creamos el directorio graficas si no existe
mkdir -p graficas
#Compilamos el script en C para crear ECDF
make --quiet

echo 'Porcentajes de paquetes por protocolo:'
bash scripts/porcentajes.sh #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 IP SRC PAQUETES'
bash scripts/scriptTop.sh ip src paquetes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 IP SRC BYTES'
bash scripts/scriptTop.sh ip src bytes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 IP DST PAQUETES'
bash scripts/scriptTop.sh ip dst paquetes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 IP SRC BYTES'
bash scripts/scriptTop.sh ip dst bytes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 TCP SRC PAQUETES'
bash scripts/scriptTop.sh tcp src paquetes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 TCP SRC BYTES'
bash scripts/scriptTop.sh tcp src bytes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 TCP DST PAQUETES'
bash scripts/scriptTop.sh tcp dst paquetes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 TCP SRC BYTES'
bash scripts/scriptTop.sh tcp dst bytes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 UDP SRC PAQUETES'
bash scripts/scriptTop.sh udp src paquetes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 UDP SRC BYTES'
bash scripts/scriptTop.sh udp src bytes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 UDP DST PAQUETES'
bash scripts/scriptTop.sh udp dst paquetes #Hara falta meterlo en un fichero ??
echo ''

echo 'Top 10 UDP SRC BYTES'
bash scripts/scriptTop.sh udp dst bytes #Hara falta meterlo en un fichero ??
echo ''



