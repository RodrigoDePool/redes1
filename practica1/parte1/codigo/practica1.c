#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include "practica1.h"


/* Global vars */
pcap_t *descr=NULL,*descr2=NULL;
pcap_dumper_t *pdumper=NULL;
int nPaquetes = 0; /* TODO:  necesita ser global? */

/*
	Realiza control de argumentos de entrada.
	Prepara descr, descr2 y pdumper para leer trafico segun los argumentos de entrada.
	Devuelve nBytes a escribir de cada paquete.
*/
int ini(int argc, char **argv);

/*
	Se encarga de cerrar los descriptores globales
*/
void cerrar();

/*
	Funcion que anyade dos dias  a la fecha de llegada
	de la cabacera de un paquete
*/
void sumar_dos(struct pcap_pkthdr *cabecera);

/*
	Funcion que imprime el numero de bytes solicitados de un paquete.
	Si el paquete tiene menos bytes que los solicitados, se imprime
	todo el paquete.
*/
void imprime_paquete(uint8_t *paquete,struct pcap_pkthdr *cabecera, long int nbytes);

/* Handle : cuando Ctrl-C, imprime nPaquetes*/
void handle(int nsignal){
	printf("%d paquetes fueron recibidos.\n", nPaquetes);
	cerrar();
	exit(OK);
}

int main(int argc, char **argv){
	long int nBytes = 0;
	int retorno = 0;
	uint8_t *paquete=NULL;
	struct pcap_pkthdr *cabecera=NULL;

	nBytes = ini(argc, argv);
	if(nBytes == ERROR){
		return ERROR;
	}

	while(retorno >= 0){
		retorno = pcap_next_ex(descr,&cabecera,(const u_char **)&paquete);
		if(retorno > 0){
			nPaquetes++;
			/*Volcado*/
			if(argc == 2){
				sumar_dos(cabecera);
				pcap_dump((uint8_t *)pdumper,cabecera,paquete);
			}			
			imprime_paquete(paquete,cabecera,nBytes);
		}
	}

	/*Caso de error*/
	if(retorno == -1){
		printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
		cerrar();
		exit(ERROR);
	}
	/*Caso de que no habia mas paquetes que leer*/
	printf("%d paquetes fueron leidos.\n", nPaquetes);
	cerrar();
	return OK;


}

int ini(int argc, char **argv){
	char errbuf[PCAP_ERRBUF_SIZE];
	char file_name[256];
	struct timeval time;
	int nBytes;

	/*Analizamos args entrada*/
	if(argc < 2 || argc > 3){
		printf("Argumentos invalidos. Si desea:\n");
		printf("1)Capturar de interfaz: introduce nº de bytes a leer por paquete.\n");
		printf("2)Analizar traza: introduce nº de bytes a leer por paquete + traza a analizar\n");
		return ERROR;
	}

	if(signal(SIGINT,handle)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		return ERROR;
	}

	nBytes = strtol(argv[1], NULL, 10);

	if(nBytes <= 0){
		printf("Error: el primer argumento debe ser un entero > 1.\n");
		return ERROR;
	}

	 /* Distinguimos abrir interfaz/traza */
	if(argc == 2){
		/*INTERFAZ LUCIA enp4s0*/
		descr = pcap_open_live("wlp3s0",ETH_FRAME_MAX,0,100, errbuf);
		if (descr == NULL){
			printf("Error: pcap_open_live(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
			return ERROR;
		}

		descr2=pcap_open_dead(DLT_EN10MB,ETH_FRAME_MAX);
		if (descr2 == NULL){
			printf("Error al abrir el dump.\n");
			pcap_close(descr);
			exit(ERROR);
		}
		gettimeofday(&time,NULL);
		sprintf(file_name,"eth0.%lld.pcap",(long long)time.tv_sec);
		pdumper=pcap_dump_open(descr2,file_name);
		if(!pdumper){
			printf("Error al abrir el dumper: %s, %s %d.\n",pcap_geterr(descr2),__FILE__,__LINE__);
			pcap_close(descr);
			pcap_close(descr2);
			return ERROR;
		}
	}else{
		descr = pcap_open_offline(argv[2], errbuf);
		if( descr == NULL){
			printf("Error: pcap_open_offline(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
			return ERROR;
		}
	}
	return nBytes;
}

void cerrar(){
	if( descr != NULL )
		pcap_close(descr);
	if( descr2 != NULL )
		pcap_close(descr2);
	if( pdumper != NULL )
		pcap_dump_close(pdumper);
}


void sumar_dos(struct pcap_pkthdr *cabecera){
	if(cabecera == NULL) return;
	cabecera->ts.tv_sec = cabecera->ts.tv_sec + TWODAYS_SECS;
}


void imprime_paquete(uint8_t *paquete,struct pcap_pkthdr *cabecera, long int nbytes){
	int min = nbytes;
	int i;
	if(paquete == NULL || cabecera == NULL) return;
	/*Minimo entre bytes totales y solicitados*/
	if(cabecera->caplen < min) min = cabecera->caplen;
	printf("Paquete %d:\n",nPaquetes);
	for(i=0; i<min ; i++)
		printf("%02x ",paquete[i]);
	printf("\n\n");
}
