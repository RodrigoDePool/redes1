#!/bin/bash

# Leemos los paquetes ip e imprimimos su ip origen y tamanio paquete

tshark -r traza.pcap -Y ip -T fields -e ip.src -e frame.len > top

awk 'BEGIN{ FS="\t"; }
# /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.\t[0-9]+/{
{
    #print $1 
    #if( !($1 in npaquetes)){
            #npaquetes[$1] = 1;
     #   }else{
            npaquetes[$1] ++;
      #  }

        if( !($1 in nbytes)){
            # nbytes[$1] = $2;
        }else{
            nbytes[$1] += $2;
        }
}
{
    for (key in npaquetes) {print key " " npaquetes[key] " paquetes"}
    #for (key in nbytes) {print key nbytes[key] "bytes"}
}' top

