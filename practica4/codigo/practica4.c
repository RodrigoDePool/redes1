/***************************************************************************
 practica4.c
 Inicio, funciones auxiliares y modulos de transmision implmentados y a implementar de la practica 4.
Compila con warning pues falta usar variables y modificar funciones
 
 Compila: make
 Autor: Jose Luis Garcia Dorado
 2014 EPS-UAM v2
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "interface.h"
#include "practica4.h"

/***************************Variables globales utiles*************************************************/
pcap_t* descr, *descr2; //Descriptores de la interface de red
pcap_dumper_t * pdumper;//y salida a pcap
uint64_t cont=0;	//Contador numero de mensajes enviados
char interface[10];	//Interface donde transmitir por ejemplo "eth0"
uint16_t ID=1;		//Identificador IP


void handleSignal(int nsignal){
	printf("Control C pulsado (%"PRIu64")\n", cont);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv){	

	char errbuf[PCAP_ERRBUF_SIZE];
	char fichero_pcap_destino[CADENAS];
	uint8_t IP_destino_red[IP_ALEN];
	uint16_t MTU;
	uint16_t datalink;
	uint16_t puerto_destino;
	char data[IP_DATAGRAM_MAX];
	uint16_t pila_protocolos[CADENAS];
    FILE *file_in;

    
	int long_index=0;
	char opt;
	char flag_iface = 0, flag_ip = 0, flag_port = 0, flag_file = 0;

	static struct option options[] = {
		{"if",required_argument,0,'1'},
		{"ip",required_argument,0,'2'},
		{"pd",required_argument,0,'3'},
		{"f",required_argument,0,'4'},
		{"h",no_argument,0,'5'},
		{0,0,0,0}
	};

		//Dos opciones: leer de stdin o de fichero, adicionalmente para pruebas si no se introduce argumento se considera que el mensaje es "Payload "
	while ((opt = getopt_long_only(argc, argv,"1:2:3:4:5", options, &long_index )) != -1) {
		switch (opt) {

			case '1' :

				flag_iface = 1;
					//Por comodidad definimos interface como una variable global
				sprintf(interface,"%s",optarg);
				break;

			case '2' : 

				flag_ip = 1;
					//Leemos la IP a donde transmitir y la almacenamos en orden de red
				if (sscanf(optarg,"%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",
				                   &(IP_destino_red[0]),&(IP_destino_red[1]),&(IP_destino_red[2]),&(IP_destino_red[3])) != IP_ALEN){
					printf("Error: Fallo en la lectura IP destino %s\n", optarg);
					exit(ERROR);
				}

				break;

			case '3' :

				flag_port = 1;
					//Leemos el puerto a donde transmitir y la almacenamos en orden de hardware
				puerto_destino=atoi(optarg);
				break;

			case '4' :

				if(strcmp(optarg,"stdin")==0) {
					if (fgets(data, sizeof data, stdin)==NULL) {
						printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					sprintf(fichero_pcap_destino,"%s%s","stdin",".pcap");
				} else {
					sprintf(fichero_pcap_destino,"%s%s",optarg,".pcap");
                    file_in = fopen(optarg,"r");
                    if (file_in == NULL){
                        printf("Error leyendo el fichero %s: %s %s %d.\n",optarg,errbuf,__FILE__,__LINE__);
                        return ERROR;
                    }
                    if (fgets(data, sizeof data, file_in)==NULL) {
                        fclose(file_in);
						printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						return ERROR;
					}
                    fclose(file_in);
                }
                /*If para asegurarnos de que hay cantidad par de caracteres*/
                if(strlen(data)%2 != 0){
                    /*La longitud maxima es 65535 (65534 caracteres)*/
                    /*Si entra en este if, NO tiene longitud maxima */
                    strcat(data," ");

                }

                flag_file = 1;

				break;

			case '5' : printf("Ayuda. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;

			case '?' : printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;

			default: printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;
        }
    }

	if ((flag_iface == 0) || (flag_ip == 0) || (flag_port == 0)){
		printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc);
		exit(ERROR);
	} else {
		printf("Interface:\n\t%s\n",interface);
		printf("IP:\n\t%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n",IP_destino_red[0],IP_destino_red[1],IP_destino_red[2],IP_destino_red[3]);
		printf("Puerto destino:\n\t%"PRIu16"\n",puerto_destino);
	}

	if (flag_file == 0) {
		sprintf(data,"%s","Payload "); //Deben ser pares!
		sprintf(fichero_pcap_destino,"%s%s","debugging",".pcap");
	}

	if(signal(SIGINT,handleSignal)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		return ERROR;
	}
		//Inicializamos las tablas de protocolos
	if(inicializarPilaEnviar()==ERROR){
      	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
		//Leemos el tamano maximo de transmision del nivel de enlace
	if(obtenerMTUInterface(interface, &MTU)==ERROR)
		return ERROR;
		//Descriptor de la interface de red donde inyectar trafico
	if ((descr = pcap_open_live(interface,MTU+ETH_HLEN,0, 0, errbuf)) == NULL){
		printf("Error: pcap_open_live(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}

	datalink=(uint16_t)pcap_datalink(descr); //DLT_EN10MB==Ethernet

		//Descriptor del fichero de salida pcap para debugging
	descr2=pcap_open_dead(datalink,MTU+ETH_HLEN);
	pdumper=pcap_dump_open(descr2,fichero_pcap_destino);

		//Formamos y enviamos el trafico, debe enviarse un unico segmento por llamada a enviar() aunque luego se traduzca en mas de un datagrama
		//Primero un paquete UDP
		//Definimos la pila de protocolos que queremos seguir
	pila_protocolos[0]=UDP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=ETH_PROTO;
		//Rellenamos los parametros necesario para enviar el paquete a su destinatario y proceso
	Parametros parametros_udp; memcpy(parametros_udp.IP_destino,IP_destino_red,IP_ALEN); parametros_udp.puerto_destino=puerto_destino;
		//Enviamos
	if(enviar((uint8_t*)data,strlen(data),pila_protocolos,&parametros_udp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;

	printf("Enviado mensaje %"PRIu64", almacenado en %s\n\n\n", cont,fichero_pcap_destino);

		//Luego, un paquete ICMP en concreto un ping
	pila_protocolos[0]=ICMP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=0; /*0 es ETH_PROTO*/
	Parametros parametros_icmp; parametros_icmp.tipo=PING_TIPO; parametros_icmp.codigo=PING_CODE; memcpy(parametros_icmp.IP_destino,IP_destino_red,IP_ALEN);
	if(enviar((uint8_t*)"Probando a hacer un ping",strlen("Probando a hacer un ping"),pila_protocolos,&parametros_icmp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;
	printf("Enviado mensaje %"PRIu64", ICMP almacenado en %s\n\n", cont,fichero_pcap_destino);

		//Cerramos descriptores
	pcap_close(descr);
	pcap_dump_close(pdumper);
	pcap_close(descr2);
	return OK;
}


/****************************************************************************************
* Nombre: enviar 									*
* Descripcion: Esta funcion envia un mensaje						*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen mensaje						*
*  -parametros: parametros necesario para el envio (struct parametros)			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t enviar(uint8_t* mensaje, uint64_t longitud,uint16_t* pila_protocolos,void *parametros){
	uint16_t protocolo=pila_protocolos[0];
    printf("Enviar(%"PRIu16") %s %d.\n",protocolo,__FILE__,__LINE__);
	if(protocolos_registrados[protocolo]==NULL){
		printf("Protocolo %"PRIu16" desconocido\n",protocolo);
		return ERROR;
	}
	else {
		return protocolos_registrados[protocolo](mensaje,longitud,pila_protocolos,parametros);
	}
	return ERROR;
}


/***************************TODO Pila de protocolos a implementar************************************/

/****************************************************************************************
* Nombre: moduloUDP 									*
* Descripcion: Esta funcion implementa el modulo de envio UDP				*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen mensaje						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloUDP(uint8_t* mensaje,uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
	uint8_t segmento[UDP_SEG_MAX]={0};
	uint16_t puerto_origen = 0;
	uint16_t aux16;
	uint32_t pos=0;
	uint16_t protocolo_inferior=pila_protocolos[1];
    uint16_t long_udp;
    printf("modulo UDP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	if (longitud>UDP_SEG_MAX-UDP_HLEN){
		printf("Error: mensaje demasiado grande para UDP (%d).\n",UDP_SEG_MAX-UDP_HLEN);
		return ERROR;
	}

	Parametros udpdatos=*((Parametros*)parametros);
	uint16_t puerto_destino=udpdatos.puerto_destino;

    /*Agregamos el puerto origen al paquete*/
    if( obtenerPuertoOrigen(&puerto_origen) == ERROR){
        printf("Error: fallo al solicitar puerto origen.\n");
        return ERROR;
    }
	aux16=htons(puerto_origen);
	memcpy(segmento,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t); /*reposicionamos el segmento*/

    /*Agregamos el puerto destino*/
    aux16=htons(puerto_destino);
    memcpy(segmento+pos,&aux16,sizeof(uint16_t));
    pos+=sizeof(uint16_t);

    /*Agregamos tamanio de paquete UDP*/
    long_udp = UDP_HLEN + (uint16_t)longitud;
    aux16 = htons(long_udp);
    memcpy(segmento+pos,&aux16,sizeof(uint16_t));
    pos+=sizeof(uint16_t);

    /*Agregamos la suma de control a 0*/
    aux16=0;
    memcpy(segmento+pos,&aux16,sizeof(uint16_t));
    pos+=sizeof(uint16_t);

    /*Agregamos los datos*/
    memcpy(segmento + pos, mensaje, sizeof(char)*longitud);
    
	return protocolos_registrados[protocolo_inferior](segmento,long_udp,pila_protocolos,parametros);
}


/****************************************************************************************
* Nombre: moduloIP 									*
* Descripcion: Esta funcion implementa el modulo de envio IP				*
* Argumentos: 										*
*  -segmento: segmento a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el segmento						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
*
* ***************************************************************************************/



uint8_t moduloIP(uint8_t* segmento, uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
	uint8_t datagrama[IP_DATAGRAM_MAX]={0};
	uint32_t aux32;
	uint16_t aux16;
	uint8_t aux8,resultado;
	uint32_t pos=0,pos_control=0;
	uint8_t IP_origen[IP_ALEN];
	uint16_t protocolo_superior=pila_protocolos[0];
	uint16_t protocolo_inferior=pila_protocolos[2];
	pila_protocolos++;
	uint8_t mascara[IP_ALEN]; /*IP_rango_origen[IP_ALEN], IP_rango_destino[IP_ALEN];*/
    uint8_t IP_gateway[IP_ALEN], localNet[IP_ALEN];
    uint16_t MTU,offset,flags,i;
    uint64_t tam_envio;
    

    printf("modulo IP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	Parametros ipdatos=*((Parametros*)parametros);
	uint8_t* IP_destino=ipdatos.IP_destino;

    if(longitud > IP_DATAGRAM_MAX-IP_HLEN){
        printf("Error: mensaje demasiado grande para IP (%d).\n", IP_DATAGRAM_MAX-IP_HLEN);
		return ERROR;
    }
    if(obtenerMTUInterface(interface,&MTU) == ERROR){
        printf("Error: el mtu no se obtuvo con exito.\n");
        return ERROR;
    }
    if(obtenerIPInterface(interface,IP_origen)==ERROR){
        printf("Error: el ip origen no se obtuvo con exito,\n");
        return ERROR;
    }
    if(obtenerMascaraInterface(interface,mascara)==ERROR){
        printf("Error: no se pudo obtener la mascara de red.\n");
        return ERROR;
    }

    /*Aplicamos mascara y establecemos el eth_destino en parametros*/
    if(aplicarMascara(IP_origen,mascara,IP_ALEN,localNet)==ERROR){
        printf("Error: fallo al aplicar la mascara.\n");
        return ERROR;
    }
    if( pertenece_redLocal(localNet,IP_destino, IP_ALEN,&resultado) == ERROR){
        printf("Error: no se pudo revisar si la ip destino pertenece a la red local.\n");
        return ERROR;
    }
    
    /*Establecemos el mac destino correspondiente*/
    if( resultado == 1){/*Pertenece a la red local*/
        if( ARPrequest(interface,IP_destino, ipdatos.ETH_destino) == ERROR){
            printf("Error: fallo al hacer arprequest.\n");
            return ERROR;
        }
    }else{/*no pertenece*/
        if(obtenerGateway(interface,IP_gateway)== ERROR){
            printf("Error: fallo al obtener IP del gateway.\n");
            return ERROR;
        }
        if( ARPrequest(interface,IP_gateway, ipdatos.ETH_destino) == ERROR){
            printf("Error: fallo al hacer arprequest del gateway.\n");
            return ERROR;
        }

    }

    
    /*BUCLE DE FRAGMENTACION DE MTU*/
    tam_envio = MTU - IP_HLEN;
    /*Obtenemos max multiplo de 8 menor que tam_envio. Aprovechamos el truncamiento de division entera*/
    tam_envio /= 8;
    tam_envio *= 8;
    
    for(i = 0; i < longitud; i += tam_envio){
        /*Limpiamos el datagrama en cada envio*/
        memset(datagrama, 0, IP_DATAGRAM_MAX * sizeof(uint8_t));
        
        /*Agregamos la version y el IHL */
        aux8 = 69; /*0010 (version 4) 0101 (IHL sin opciones)*/
        memcpy(datagrama,&aux8,sizeof(uint8_t));
        pos+=sizeof(uint8_t);

        /*Agregamos campo tipo de servicio a cero*/
        aux8 = 0;
        memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
        pos+=sizeof(uint8_t);

        /*Longitud total*/
        if( (i + tam_envio) >= longitud){/*Ultimo fragmento*/
            aux16 = longitud - i + IP_HLEN;
        }else{
            aux16 = tam_envio + IP_HLEN;
        }
        aux16 = htons(aux16);
        memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
        pos+=sizeof(uint16_t);

        /*Agregamos el identificador*/
        aux16 = htons(ID);
        memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
        pos+=sizeof(uint16_t);    

        /*flags + posicion*/
        if( (i + tam_envio) >= longitud){/*Ultimo fragmento*/
            flags = 0; /* 0x0000 */
        }else{
            flags=8192; /* 0x2000*/
        }
        offset = i/8;
        aux16 = flags | offset;
        aux16 = htons(aux16);
        memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
        pos+=sizeof(uint16_t);

        /*TTL*/
        aux8=64;/*time to live usual*/
        memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
        pos+=sizeof(uint8_t);

        /*Protocolo*/
        aux8=protocolo_superior;
        memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
        pos+=sizeof(uint8_t);
        /*guardamos la posicion antes del checksum en un control*/
        pos_control=pos;
        pos+=sizeof(uint16_t); /*saltamos el checksum*/
        
        /*Continuamos con la ip origen*/
        aux32=*((uint32_t *) IP_origen);
        memcpy(datagrama+pos,&aux32,sizeof(uint32_t));
        pos+=sizeof(uint32_t);
        
        /*ip destino*/
        aux32=*((uint32_t *)ipdatos.IP_destino);
        memcpy(datagrama+pos,&aux32,sizeof(uint32_t));
        pos+=sizeof(uint32_t);
        
        /*rellenamos el checksum*/
        if( calcularChecksum(IP_HLEN, datagrama, (uint8_t *)(&aux16)) == ERROR){
            printf("Error al calcular el checksum de ip.\n");
            return ERROR;
        }
        memcpy(datagrama+pos_control,&aux16,sizeof(uint16_t));
               
       /*Agregamos datos*/
        if( (i + tam_envio) >= longitud){/*Ultimo fragmento*/
            aux16 = longitud - i;
        }else{
            aux16 = tam_envio;
        }
        memcpy(datagrama+pos,segmento+i,aux16);

        /*Enviamos paquete al siguiente nivel de la pila*/
        if(protocolos_registrados[protocolo_inferior](datagrama,aux16+IP_HLEN,pila_protocolos,&ipdatos) == ERROR){
            printf("Error al enviar fragmento ip.\n");
            return ERROR;
        }
    }
    ID++; /*Incrementamos el identificador*/
    return OK;
}


/****************************************************************************************
* Nombre: moduloETH 									*
* Descripcion: Esta funcion implementa el modulo de envio Ethernet			*
* Argumentos: 										*
*  -datagrama: datagrama a enviar							*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el datagrama						*
*  -parametros: Parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloETH(uint8_t* datagrama, uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
    uint8_t trama[ETH_FRAME_MAX]={0};
    uint32_t pos = 0;
    uint64_t mac; /*No hay de 48 :( */
    uint16_t protocolo_superior=pila_protocolos[0];
    Parametros ethdatos = *((Parametros *)parametros);
    
    struct pcap_pkthdr hdr;
    struct timeval tv;

    printf("modulo ETH(fisica) %s %d.\n",__FILE__,__LINE__);	

 
    if(longitud > ETH_FRAME_MAX-ETH_HLEN){
        printf("Error: mensaje demasiado grande para ETH (%d).\n", ETH_FRAME_MAX-ETH_HLEN);
		return ERROR;
    }

    /*NOTA: las MACs ya estan en orden de red*/
    
    /*Aniadimos MAC destino*/
    memcpy(trama + pos, &(ethdatos.ETH_destino), ETH_ALEN);
    pos += ETH_ALEN;
    
    /*Aniadimos MAC origen*/
    if(obtenerMACdeInterface(interface, (uint8_t *)(&mac)) == ERROR){
        printf("Error obteniendo mac origen");
        return ERROR;
    }
    memcpy(trama + pos, &mac, ETH_ALEN);
    pos += ETH_ALEN;

    /*Aniadimos tipo ethernet*/
    protocolo_superior=htons(protocolo_superior);
    memcpy(trama + pos, &protocolo_superior, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    /*Aniadimos datagrama*/
    memcpy(trama+pos, datagrama, longitud);
    pos += longitud;

    if(pcap_sendpacket(descr, trama, (longitud + ETH_HLEN)) == -1){
        printf("Error enviando paquete\n");
        return ERROR;
    }
    //TODO  Otra duda: xq descr2 es global si no la uso? Deberia estar usandose? 
    /*Rellenamos la cabecera*/
    gettimeofday(&tv, NULL);
    hdr.ts = tv;
    hdr.len = longitud + ETH_HLEN;
    hdr.caplen = hdr.len;

    pcap_dump((u_char *)pdumper, &hdr, trama);
    return OK;
}


/****************************************************************************************
* Nombre: moduloICMP 									*
* Descripcion: Esta funcion implementa el modulo de envio ICMP				*
* Argumentos: 										*
*  -mensaje: mensaje a anadir a la cabecera ICMP					*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el mensaje						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloICMP(uint8_t* mensaje,uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
	uint8_t datagrama[IP_DATAGRAM_MAX]={0};
	uint32_t pos=0, checksum_pos;
    uint16_t checksum;
    uint16_t icmp_long;
	uint16_t protocolo_inferior=pila_protocolos[1];
	Parametros icmpdatos=*((Parametros*)parametros);
    
    if(longitud > ICMP_DATAGRAM_MAX-ICMP_HLEN){
        printf("Error: mensaje demasiado grande para ICMP (%d).\n", ICMP_DATAGRAM_MAX-ICMP_HLEN);
		return ERROR;
    }
    memcpy(datagrama, &(icmpdatos.tipo), sizeof(uint8_t) );
    pos += sizeof(uint8_t);
    memcpy(datagrama+pos, &(icmpdatos.codigo), sizeof(uint8_t) );
    pos += sizeof(uint8_t);
    checksum_pos = pos;
    
    /*Checksum*/
    /*lo saltamos y lo agregamos al final*/
    pos += sizeof(uint16_t);
    
    /* Identificador (aleatorio)- misma semilla en cada ejecucion,
     * pero como no tiene más uso en la práctica lo dejamos así*/
    *(datagrama + pos) = htons((uint16_t)rand());
    pos += sizeof(uint16_t);

    /* Numero se secuencia (mismo comentario que para el identificador)*/
    *(datagrama + pos) = htons((uint16_t)rand());
    pos += sizeof(uint16_t);

    /* Mensaje*/
    memcpy(datagrama+pos, mensaje, longitud);
    pos += sizeof(uint8_t)*longitud;
    
    /* Modificamos checksum */
    if (calcularChecksum(pos, datagrama, (uint8_t *)(&checksum)) == ERROR){
        return ERROR;
    }
    memcpy(datagrama+checksum_pos, &checksum, sizeof(uint16_t));
    
    icmp_long = (uint16_t)longitud + ICMP_HLEN;
	return protocolos_registrados[protocolo_inferior](datagrama, icmp_long, pila_protocolos, parametros);
}


/***************************Funciones auxiliares a implementar***********************************/

/****************************************************************************************
* Nombre: aplicarMascara 								*
* Descripcion: Esta funcion aplica una mascara a una vector				*
* Argumentos: 										*
*  -IP: IP a la que aplicar la mascara en orden de red					*
*  -mascara: mascara a aplicar en orden de red						*
*  -longitud: bytes que componen la direccion (IPv4 == 4)				*
*  -resultado: Resultados de aplicar mascara en IP en orden red
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t aplicarMascara(uint8_t* IP, uint8_t* mascara, uint32_t longitud, uint8_t* resultado){
    int i;
    
    if(IP == NULL || mascara == NULL){
        return ERROR;
    }
    for(i=0; i<longitud; i++){
        resultado[i] = IP[i] & mascara[i];
    }
    return OK;
}

/****************************************************************************************
 * Nombre: pertenece_redLocal
 * Descripcion: Devuelve si una ip pertence o no a una red local
 * Argumentos:
 * - localNet: And entre las mascara y una ip de la red local
 * - ip: ip a probar si esta o no en la red
 * - longitud: tamanio de ip
 * - bool: se escribira 1 en caso de que pertenezca a la red, 0 en caso contrario
 * Retorno: OK/ERROR
 ***************************************************************************************/
uint8_t pertenece_redLocal(uint8_t *localNet, uint8_t *ip, int longitud, uint8_t *bool){
    int i;
    if( localNet == NULL || ip == NULL || bool == NULL) return ERROR;
    
    for( i = 0 ; i< longitud; i++){
        /*Se devuelve 0 si no pertence a la mascara de la red*/
        if( (localNet[i] & ip[i]) != localNet[i]){
            *bool=0;
            return OK;
        }
    }
    *bool=1;
    return OK;
}


/***************************Funciones auxiliares implementadas**************************************/

/****************************************************************************************
* Nombre: mostrarPaquete 								*
* Descripcion: Esta funcion imprime por pantalla en hexadecimal un vector		*
* Argumentos: 										*
*  -paquete: bytes que conforman un paquete						*
*  -longitud: Bytes que componen el mensaje						*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t mostrarPaquete(uint8_t * paquete, uint32_t longitud){
	uint32_t i;
	printf("Paquete:\n");
	for (i=0;i<longitud;i++){
		printf("%02"PRIx8" ", paquete[i]);
	}
	printf("\n");
	return OK;
}


/****************************************************************************************
* Nombre: calcularChecksum							     	*
* Descripcion: Esta funcion devuelve el ckecksum tal como lo calcula IP/ICMP		*
* Argumentos:										*
*   -longitud: numero de bytes de los datos sobre los que calcular el checksum		*
*   -datos: datos sobre los que calcular el checksum					*
*   -checksum: checksum de los datos (2 bytes) en orden de red! 			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t calcularChecksum(uint16_t longitud, uint8_t *datos, uint8_t *checksum) {
    uint16_t word16;
    uint32_t sum=0;
    int i;
    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i=0; i<longitud; i=i+2){
        word16 = (datos[i]<<8) + datos[i+1];
        sum += (uint32_t)word16;       
    }
    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum>>16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }
    // one's complement the result
    sum = ~sum;      
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;
    return OK;
}


/***************************Funciones inicializacion implementadas*********************************/

/****************************************************************************************
* Nombre: inicializarPilaEnviar     							*
* Descripcion: inicializar la pila de red para enviar registrando los distintos modulos *
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t inicializarPilaEnviar() {
	bzero(protocolos_registrados,MAX_PROTOCOL*sizeof(pf_notificacion));
	if(registrarProtocolo(ETH_PROTO, moduloETH, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(IP_PROTO, moduloIP, protocolos_registrados)==ERROR)
		return ERROR;
    if(registrarProtocolo(UDP_PROTO, moduloUDP, protocolos_registrados)==ERROR)
        return ERROR;
    if(registrarProtocolo(ICMP_PROTO, moduloICMP, protocolos_registrados)==ERROR)
        return ERROR;
    return OK;
}


/****************************************************************************************
* Nombre: registrarProtocolo 								*
* Descripcion: Registra un protocolo en la tabla de protocolos 				*
* Argumentos:										*
*  -protocolo: Referencia del protocolo (ver RFC 1700)					*
*  -handleModule: Funcion a llamar con los datos a enviar				*
*  -protocolos_registrados: vector de funciones registradas 				*
* Retorno: OK/ERROR 									*
*****************************************************************************************/

uint8_t registrarProtocolo(uint16_t protocolo, pf_notificacion handleModule, pf_notificacion* protocolos_registrados){
	if(protocolos_registrados==NULL ||  handleModule==NULL){		
		printf("Error: registrarProtocolo(): entradas nulas.\n");
		return ERROR;
	}
	else
		protocolos_registrados[protocolo]=handleModule;
	return OK;
}


