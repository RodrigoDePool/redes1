
#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <inttypes.h>




pcap_t *descr = NULL;
uint64_t contador = 0;
uint8_t ipsrc_filter[IP_ALEN] = {NO_FILTER};
uint8_t ipdst_filter[IP_ALEN] = {NO_FILTER};
uint16_t sport_filter= NO_FILTER;
uint16_t dport_filter = NO_FILTER;

/*
*	Manejador para el sigint
*/
void handleSignal(int nsignal)
{
	printf("Control C pulsado (%"PRIu64" paquetes leidos)\n", contador);
	pcap_close(descr);/*ESTO SE MANTIENE??*/
	exit(OK);
}

/*
*	Un par de printf que se repiten mucho en la inicializacion.
*	Cierra el descriptor global.
*/
void mensajeFormatoError(){
	printf("Formato de argumentos erroneo.\n");
	printf("Ejecucion: practica2 <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]\n");
	if(descr != NULL) pcap_close(descr);
}


/*
*	Se encarga de inicializar el descriptor y los filtros con los argumentos
*	Devuelve OK si todo se inicializo correctamente o ERROR en caso contrario
*	Si hubo error imprime por terminal una pequena descripcion
*	Se rige al formato estricto que se da en la practica
*/
int init(int argc, char **argv);

int main(int argc, char **argv)
{
//	uint8_t *pack = NULL;
//	struct pcap_pkthdr *hdr;

//	char errbuf[PCAP_ERRBUF_SIZE];
//	char entrada[256];
//	int long_index = 0, retorno = 0;
//	char opt;

	if (signal(SIGINT, handleSignal) == SIG_ERR) {
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}

	if(argc <= 1){
		mensajeFormatoError();
		exit(ERROR);
	}

	if(init(argc,argv) == ERROR){
		exit(ERROR);
	}


	//Simple comprobacion de la correcion de la lectura de parametros
	printf("Filtro:");
	//if(ipsrc_filter[0]!=0)
	printf("ipsrc_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipsrc_filter[0], ipsrc_filter[1], ipsrc_filter[2], ipsrc_filter[3]);
	//if(ipdst_filter[0]!=0)
	printf("ipdst_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipdst_filter[0], ipdst_filter[1], ipdst_filter[2], ipdst_filter[3]);

	if (sport_filter!= NO_FILTER) {
		printf("po_filtro=%"PRIu16"\t", sport_filter);
	}

	if (dport_filter != NO_FILTER) {
		printf("pd_filtro=%"PRIu16"\t", dport_filter);
	}

	printf("\n\n");

	do {
		retorno = pcap_next_ex(descr, &hdr, (const u_char **)&pack);

		if (retorno == PACK_READ) { //Todo correcto
			contador++;
			analizar_paquete(hdr, pack);

		} else if (retorno == PACK_ERR) { //En caso de error
			printf("Error al capturar un paquetes %s, %s %d.\n", pcap_geterr(descr), __FILE__, __LINE__);
			pcap_close(descr);
			exit(ERROR);

		}
	} while (retorno != TRACE_END);

	printf("Se procesaron %"PRIu64" paquetes.\n\n", contador);
	pcap_close(descr);
	return OK;
}





int init(int argc, char **argv){
	int i;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(argc <= 1 || argv == NULL) return ERROR;
	/*numero de argumentos - 1 (nombre del programa) tiene que ser par*/
	if( (argc - 1)%2 != 0){
		mensajeFormatoError();
		return ERROR;
	}

	for(i = 1; i + 1 < argc; i = i + 2){
		if( strcmp(argv[i],"-f") == 0 ){
			if(descr != NULL){
				printf("Has seleccionado mas de una fuente de datos\n");
				pcap_close(descr);
				return ERROR;
			}
			descr = pcap_open_offline(argv[i+1],errbuf);
			if( descr == NULL ){
				printf("Error al abrir el archivo pcap: %s\n",errbuf);
				return ERROR;
			}
		}else if( strcmp(argv[i],"-i") == 0 ){
			if(descr != NULL){
				printf("Has seleccionado mas de una fuente de datos\n");
				pcap_close(descr);
				return ERROR;
			}
			descr = pcap_open_live(argv[i+1],ETH_FRAME_MAX,0,100, errbuf);
			if( descr == NULL ){
				printf("Error al abrir el interfaz: %s\n",errbuf);
				return ERROR;
			}
		}else if( strcmp(argv[i],"-ipo") == 0 ){

			/*TODO: COLOCAR FILTROOOOOOS*/

		}else if( strcmp(argv[i],"-ipd") == 0 ){

			/*TODO: COLOCAR FILTROOOOOOS*/

		}else if( strcmp(argv[i],"-po") == 0 ){
			sport_filter = atoi(argv[i+1]);
			if(sport_filter == 0){
				printf("Valor del puerto origen invalido.\n");
				if(descr != NULL) pcap_close(descr);
				return ERROR;
			}
		}else if( strcmp(argv[i],"-pd") == 0 ){
			dport_filter = atoi(argv[i+1]);
			if(dport_filter == 0){
				printf("Valor del puerto destino invalido.\n");
				if(descr != NULL) pcap_close(descr);
				return ERROR;
			}
		}else{/*El argumento no coincide con ninguna bandera*/
			mensajeFormatoError();
			return ERROR;
		}
	}/*end for*/

	if ( descr == NULL ) {
		printf("No selecciono ningún origen de paquetes.\n");
		return ERROR;
	}

	return OK;
}
