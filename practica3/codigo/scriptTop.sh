#!/bin/bash

# Leemos los paquetes ip e imprimimos su ip origen y tamanio paquete

tshark -r traza.pcap -E separator=, -Y ip -T fields -e ip.src -e frame.len > top
> top.txt

awk 'BEGIN{ FS=",";}{
        
        npaquetes[$1] ++;
        nbytes[$1] += $2;
}
END{
   for (key in npaquetes) {printf "%s %d paquetes %d bytes\n", key, npaquetes[key], nbytes[key] >> "top.txt" }
}' top >> top.txt

