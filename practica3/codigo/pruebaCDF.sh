#!/bin/bash

## Script para probar funcionamineto crearCDF.c

$(tshark -r traza.pcap -E separator=: -T fields -e frame.cap_len > ./data/paquetes_tamanios)

$(./crearCDF ./data/paquetes_tamanios ./data/salida)

