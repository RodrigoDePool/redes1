#!/bin/bash

#Este script se encarga de generar las graficas que corresponden a los ECDFs de:
# tamano a nivel 2 (solo de la MAC dada), tamanio a nivel 3 (una para HTTP y una para DNS)

#Input: $1 = eth/http/dns, $2 = src/dst

MAC="00:11:88:CC:33:CA"
# Si no existian, creamos dirs para graficas y data
DATA="datos/ecdf_tam/"
GRAF="graficas/ecdf_tam/"
mkdir -p $DATA
mkdir -p $GRAF
#Probamos argumentos, establecemos filtro y nivel de filtrado
if [ "$1" = "eth" ]; then
    if [ "$2" = "src" ]; then COL_PORT="14";
    elif [ "$2" = "dst" ]; then COL_PORT="13";
    fi
    COL_TAM="11"; FILTER=$MAC
elif [ "$1" = "http" ]; then
    if ["$2" = "src" ]; then COL_PORT="7";
    elif ["$2" = "dst" ]; then COL_PORT="6";
    fi
    COL_TAM="10"; FILTER="80"
elif [ "$1" = "dns" ]; then
    if [ "$2" = "src" ]; then COL_PORT="9";
    elif [ "$2" = "dst "]; then COL_PORT="8";
    fi
    COL_TAM="10"; FILTER="53"
else
    echo "Argumentos erroneos: http/dns/eth src/dst"
    exit -1
fi

#Guardamos en fichero tamanios deseados en inputs
awk -v col_tam=$COL_TAM -v col_port=$COL_PORT -v filter=$FILTER 'BEGIN{ FS="\t"; }
{   printf "HOLA tam %s port %s filter %s\n", $col_tam, $col_port, filter
    if($col_port != null && $col_port == filter ){printf "%d\n", $col_tam;}
}
END{}' tipos.tshark > input.tmp

#Ejecutamos creador de ECDFs
./scripts/crearCDF input.tmp "$DATA${1}_$2"

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
set output "$GRAF${1}_${2}.png" 

plot "$DATA${1}_$2" u 1:2 w lines
EOF

# rm input.tmp

echo 'Grafica '${1}'_'${2}'.png creada en el directorio $GRAF'

exit 0
