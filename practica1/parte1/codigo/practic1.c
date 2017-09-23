#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>


/*******
    ESQUEMA MENTAL;
    Caso live:
        descr1 = open_live;
        descr2 = open dead; descr3 = dump_open(descr2); <--- PARA VOLCAR TRAZA
    Caso offline:
        descr1 = open_offline;
        
    En ambos casos:
        Empiezo a leer y a imprimir con pcapNext.
        Cuento numero de paquetes
    
    Lo que diferencia los dos casos es cuando paro de leer y muestro num paquetes
        Caso live: sigint --> POR TANTO, numPaquetes global
        Caso offline: pcapNext == -2 :D
        
******/


/* Global vars */
pcap_t *descr=NULL,*descr2=NULL;
pcap_dumper_t *pdumper=NULL;
int nPaquetes = 0; /* TODO:  necesita ser global? */

/* Handle : cuando Ctrl-C, imprime nPaquetes*/
void handle(int nsignal){
    printf("%d paquetes fueron recibidos por la interfaz.\n", nPaquetes);
    if(descr)
		pcap_close(descr);
	if(descr2)
		pcap_close(descr2);
	if(pdumper)
		pcap_dump_close(pdumper);
    exit(OK);
}

/*  
    Realiza control de argumentos de entrada.
    Prepara descr, descr2 y pdumper para leer trafico segun los argumentos de entrada.
    Devuelve nBytes a escribir de cada paquete.
*/
int ini(int argc, char **argv);

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
        }
        /*Volcado*/
        if(argc == 2){
            /*TODO funcion que aumente 2 al dia. (= a la cabecera?)*/
            pcap_dump((uint8_t *)pdumper,cabecera,paquete);
        }        
        /*Imprime paquete*/
    }
    
    /*Lectura terminada*/
	pcap_close(descr2);
	pcap_dump_close(pdumper);
	/*Caso de error*/			
    if(retorno == -1){
			printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
			pcap_close(descr);
			exit(ERROR);
	}
	/*Caso de que no habia mas paquetes que leer*/
	printf("%d paquetes fueron leidos de la traza pcap.\n", nPaquetes);
	pcap_close(descr);
	return OK;
	
	    
}

int ini(int argc, char **argv){
    char errbuf[PCAP_ERRBUF_SIZE];
    char file_name[256];
	struct timeval time;
    
    /*Analizamos args entrada*/
    if(argc < 2 || argc > 3){
        printf("Argumentos invalidos. Si desea:\n
                1)Capturar de interfaz: introduce nº de bytes a leer por paquete.\n
                2)Analizar traza: introduce nº de bytes a leer por paquete + traza a analizar\n");
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
        if ((descr = pcap_open_live("enp4s0",ETH_FRAME_MAX,0,100, errbuf)) == NULL){
	        printf("Error: pcap_open_live(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
	        return ERROR;
        }
        descr2=pcap_open_dead(DLT_EN10MB,ETH_FRAME_MAX);
	    if (!descr2){
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
        if((descr = pcap_open_offline(argv[2], errbuf)) == NULL){
	        printf("Error: pcap_open_offline(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
	        return ERROR;
        }
    }
    return nBytes;       
}
