
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

/*Definicion de constantes *************************************************/
#define ETH_ALEN      6      /* Tamanio de la direccion ethernet           */
#define ETH_HLEN      14     /* Tamanio de la cabecera ethernet            */
#define ETH_TLEN      2      /* Tamanio del campo tipo ethernet            */
#define ETH_FRAME_MAX 1514   /* Tamanio maximo la trama ethernet (sin CRC) */
#define ETH_FRAME_MIN 60     /* Tamanio minimo la trama ethernet (sin CRC) */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN) /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define IP_ALEN 4			/* Tamanio de la direccion IP					*/
#define OK 0
#define ERROR 1
#define PACK_READ 1
#define PACK_ERR -1
#define TRACE_END -2
#define NO_FILTER 0


pcap_t *descr = NULL;
uint64_t contador = 0;
uint8_t ipsrc_filter[IP_ALEN] = {0};
uint8_t ipdst_filter[IP_ALEN] = {0};
uint16_t sport_filter= NO_FILTER;
uint16_t dport_filter = NO_FILTER;

/*
*	Manejador para el sigint
*/
void handleSignal(int nsignal)
{
	printf("Control C pulsado (%"PRIu64" paquetes leidos)\n", contador);
	pcap_close(descr);
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

/*
*	Imprime los filtros que se han establecido
*/
void printFiltros();

/*
*	Se encarga de imprimir la informacion referente al paquete capturado
*/
void analizar_paquete(const struct pcap_pkthdr *hdr, const uint8_t *pack);

/*
*	Analiza el paquete a nivel 3 (llamada internamente por analizar paquete)
*	Luego si el paquete pasa los filtros se llama a analizar el nivel 4
*/
void analizar_nivel3(const struct pcap_pkthdr *hdr, const uint8_t *pack);

/*
*	Analiza el paquete TCP (llamada internamente por analizar_nivel3)
*/
void analizar_TCP(const struct pcap_pkthdr *hdr, const uint8_t *pack);

/*
*	Analiza el paquete UDP(llamada internamente por analizar_nivel3)
*/
void analizar_UDP(const struct pcap_pkthdr *hdr, const uint8_t *pack);

int main(int argc, char **argv)
{
	uint8_t *pack = NULL;
	struct pcap_pkthdr *hdr;
	int retorno = 0;

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

	printFiltros();


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
	int i, aux;
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
			aux = sscanf(argv[i+1]," %"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",ipsrc_filter,ipsrc_filter + 1,ipsrc_filter + 2,ipsrc_filter + 3);
			if(aux != 4){
				printf("Error en el filtro de ip origen.\n");
				if(descr != NULL) pcap_close(descr);
				return ERROR;
			}
		}else if( strcmp(argv[i],"-ipd") == 0 ){
			aux = sscanf(argv[i+1]," %"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",ipdst_filter,ipdst_filter + 1,ipdst_filter + 2,ipdst_filter + 3);
			if(aux != 4){
				printf("Error en el filtro de ip destino.\n");
				if(descr != NULL) pcap_close(descr);
				return ERROR;
			}
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

void printFiltros(){
	printf("Filtro:\n");
	if(sport_filter != NO_FILTER){
		printf("po_filtro=%"PRIu16"\t", sport_filter);
	}
	if (dport_filter != NO_FILTER) {
		printf("pd_filtro=%"PRIu16"\t", dport_filter);
	}
	if( ipsrc_filter[0] != 0 ){
		printf("ipsrc_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipsrc_filter[0], ipsrc_filter[1], ipsrc_filter[2], ipsrc_filter[3]);
	}
	if( ipdst_filter[0] != 0 ){
		printf("ipdst_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipdst_filter[0], ipdst_filter[1], ipdst_filter[2], ipdst_filter[3]);
	}
	printf("\n\n");
}

void analizar_paquete(const struct pcap_pkthdr *hdr, const uint8_t *pack)
{
	int i;
	uint16_t *aux_paquete;
	uint16_t aux;

	printf("Paquete numero %"PRIu64" capturado el %s\n", contador,ctime((const time_t *) & (hdr->ts.tv_sec)));
	printf("Direccion ETH destino = ");
	printf("%02X", pack[0]);
	for (i = 1; i < ETH_ALEN; i++) {
		printf(":%02X", pack[i]);
	}
	printf("\n");
	pack += ETH_ALEN;

	printf("Direccion ETH origen = ");
	printf("%02X", pack[0]);
	for (i = 1; i < ETH_ALEN; i++) {
		printf(":%02X", pack[i]);
	}
	printf("\n");
	pack+=ETH_ALEN;

	aux_paquete = (uint16_t *) pack;
	aux = ntohs(aux_paquete[0]);
	if(aux == 2048){
		printf("Tipo ethernet = IPv4\n");
		pack+=ETH_TLEN;
		analizar_nivel3(hdr,pack);
	}else{
		printf("Tipo ethernet = 0x%04x\n",aux);
		printf("El protocolo no es el esperado. Por tanto, no se imprimiran los siguientes niveles.\n");
	}
	printf("\n\n");
}

void analizar_nivel3(const struct pcap_pkthdr *hdr, const uint8_t *pack){
	uint8_t aux8;
	uint8_t *pack_aux;
	uint16_t *paux;
	uint16_t aux16;
	int flag;/*flag para avisar que no se continua al siguiente nivel*/
	int prot;/*0 para analizar udp, 1 para analizar tcp*/

	printf("  Cabecera IPv4:\n");
	/*Version*/
	aux8 = 240;/*11110000*/
	aux8 = aux8 & pack[0]; /*Tenemos campo version en los 4 primeros bits*/
	aux8 = aux8 >> 4;
	printf("Version = %"PRIu8"\n",aux8);

	/*Longitud cabecera*/
	aux8 = 15; /*00001111 en binario*/
	aux8 = aux8 & pack[0]; /*Eliminamos asi el campo version, tenemos IHL*/
	aux8 = (aux8 & pack[0])*4; /* IHL*4 tamanio en bytes de cabecera ip*/
	printf("Longitud de cabecera ip en bytes = %"PRIu8"\n",aux8);
	pack_aux = (uint8_t *)pack + aux8;/*Nos guardamos el final de la cabecera ip*/

	pack += 2;/*Posicion antes de la longitud*/
	/*Longitud*/
	paux = (uint16_t *)pack;
	aux16 = ntohs(paux[0]);
	printf("Longitud total = %"PRIu16"\n",aux16);

	pack += 4; /*Posicion antes de flags*/
	/*Posicion*/
	paux = (uint16_t *)pack;
	aux16 = ntohs(paux[0]);
	aux16 = aux16 & 8191;/*0001111111111111 and aux16, resultado = posicionamiento*/
	aux16 = aux16*8; /*Posicionamiento por unidad de 64 bits a posci por byte*/
	printf("Posicionamiento = %"PRIu16"\n",aux16);
	if(aux16 != 0){
		flag = 1;
		printf(" No se mostrara el siguiente nivel por no ser el primer fragmento\n");
	}

	pack += 2;/*Posicion antes de tiempo de vida*/
	/*Tiempo de vida*/
	printf("Tiempo de vida = %"PRIu8"\n",pack[0]);

	pack += 1;/*Posicion antes de protocolo*/
	/*Protocolo*/
	if(pack[0] == 6){
		printf("Protocolo = TCP\n");
		prot = 1;
	}else if(pack[0] == 17){
		printf("Protocolo = UDP\n");
		prot = 0;
	}else{
		printf("Protocolo = %"PRIu8"\n",pack[0]);
		printf(" No se mostrara el siguiente nivel porque el protocolo no es ni TCP ni UDP\n");
		flag = 1;
	}

	pack += 3;/*Antes de ip origen*/
	/*IP origen*/
	/*crear uint de 32, hacer un ntohl */
	/*utilizar uint8 y con el and correspondiente hacer byte a byte*/
	/*El filtro tambien puede hacerse byte a byte*/
	/*TODO:FILTRO Y CODIGO*/

	pack += 4;
	/*IP destino*/
	/*TODO:FILTRO Y CODIGO*/


	if(flag == 1){
		return;
	}else if(prot == 0){
		analizar_UDP(hdr,pack_aux);
	}else{
		analizar_TCP(hdr,pack_aux);
	}
}

void analizar_TCP(const struct pcap_pkthdr *hdr, const uint8_t *pack){
	uint16_t *paux;
	uint16_t aux16;
	uint8_t aux8;
	uint8_t syn, ack;

	printf("  Cabecera TCP:\n");

	/*Puerto origen*/
	paux = (uint16_t *)pack;
	aux16 = ntohs(paux[0]);
	printf("Puerto origen = %"PRIu16"\n", aux16);
	if(sport_filter != 0 && aux16 != sport_filter){
		printf("El puerto origen no pasa el filtro, no se mostraran mas campos\n");
		return;
	}

	pack += 2;/*Antes de puerto destino*/
	/*Puerto destino*/
	paux = (uint16_t *)pack;
	aux16 = ntohs(paux[0]);
	printf("Puerto destino = %"PRIu16"\n", aux16);
	if(dport_filter != 0 && aux16 != dport_filter){
		printf("El puerto destino no pasa el filtro, no se mostraran mas campos\n");
		return;
	}

	pack += 11;/*Ultimos dos bits de reservado y flags*/
	/*Flags*/
	syn = 2 & pack[0];/* 00000010 and pack[0] = flag de syn*/
	if(syn == 0) printf("Flag SYN = 0\n");
	else printf("Flag SYN = 1\n");
	ack = 16 & pack[0]; /*00010000 and pack[0] = flag de ack*/
	if(ack == 0 ) printf("Flag ACK = 0\n");
	else printf("Flag ACK = 1\n");

	return;
}


void analizar_UDP(const struct pcap_pkthdr *hdr, const uint8_t *pack){
	uint16_t *paux;
	uint16_t aux16;

	printf("  Cabecera UDP:\n");

	/*Puerto origen*/
	paux = (uint16_t *)pack;
	aux16 = ntohs(paux[0]);
	printf("Puerto origen = %"PRIu16"\n", aux16);
	if(sport_filter != 0 && aux16 != sport_filter){
		printf("El puerto origen no pasa el filtro, no se mostraran mas campos\n");
		return;
	}

	pack += 2;/*Antes de puerto destino*/
	/*Puerto destino*/
	paux = (uint16_t *)pack;
	aux16 = ntohs(paux[0]);
	printf("Puerto destino = %"PRIu16"\n", aux16);
	if(dport_filter != 0 && aux16 != dport_filter){
		printf("El puerto destino no pasa el filtro, no se mostraran mas campos\n");
		return;
	}

	pack += 2;/*Antes de longitud*/
	paux = (uint16_t *)pack;
	aux16 = ntohs(paux[0]);
	printf("Longitud UDP = %"PRIu16"",aux16);
	return;
}
