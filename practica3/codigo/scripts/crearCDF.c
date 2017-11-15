/***********************************************************
 crearCDF.c  
 Primeros pasos para implementar y validar la funcion crearCDF(). Est funcion debe devolver
 un fichero con dos columnas, la primera las muestras, la segunda de distribucion de
 probabilidad acumulada.

 El fichero recibido deberia tener una unica columna donde aparecen los valores de la muestra 

 Compila: gcc -Wall -o crearCDF crearCDF.c
 Autor: Jose Luis Garcia Dorado
 2014 EPS-UAM 
***************************************************************************/

#include <stdio.h> 
#include <stdlib.h> 
#include <strings.h> 
#include <string.h> 

#define OK 0
#define ERROR 1
#define TEMPORAL "temporal.cdf"

/* Se encarga de crear el fichero con el ECDF
 * este fichero tiene en la primera columna el valor y en la segunda el valor de su distribucion
 */
int crearCDF(char* filename_data, char* filename_cdf);

/* Elimina el fichero temporal creado
*/
void eliminarTemporal();

int main(int argc, char **argv){
  if(argc != 3){
    printf("\nError en el formato de ejecucion\n");
    printf("Ejecutar: ./programa fichero_muestra fichero_salida_ECDF\n");
    return OK;
  }
  crearCDF(argv[1],argv[2]);
  return OK;
}

int crearCDF(char* filename_data, char* filename_cdf) {
    char comando[255]; char linea[255]; char aux[255];
    int num_lines, acumulador, repeticiones;
    float valor;
    FILE *f, *aux_f;

    /*Lectura total de lineas*/
    sprintf(comando,"wc -l %s",filename_data);      /*wc cuenta las lineas del fichero dado*/
    f = popen(comando, "r");
    if(f == NULL){
        printf("Error ejecutando el comando\n");
        return ERROR;
    }
    fgets(linea,255,f);
    sscanf(linea,"%d %s",&num_lines,aux);
    pclose(f);

    /*Ordenar fichero (menor a mayor)*/
    sprintf(comando,"sort -n  %s > %s",filename_data,filename_cdf); /*Orden numerico*/
    f = popen(comando, "r");
    if(f == NULL){
        printf("Error ejecutando el comando\n");
        return ERROR;
    }
    bzero(linea,255);
    fgets(linea,255,f);
    pclose(f);
    
    /* Creamos fichero con: cantidad_de_ocurrencias valor
     * lo almacenamos en un fichero temporal
    */
    sprintf(comando,"uniq -c  %s > %s", filename_cdf, TEMPORAL);
    f = popen(comando, "r");
    if(f == NULL){
        printf("Error ejecutando el comando\n");
        return ERROR;
    }
    bzero(linea,255);
    fgets(linea,255,f);
    pclose(f);

    /*Creamos fichero con ECDF*/
    f = fopen(TEMPORAL, "r");
    aux_f = fopen( filename_cdf, "w");
    /*caso de error*/
    if( f == NULL || aux == NULL){
      if(f != NULL) fclose(f);
      if(aux_f != NULL) fclose(aux_f);
      printf("Error en la apertura de ficheros\n");
      eliminarTemporal(); /*Eliminamos fichero temporal*/
      return ERROR;
    }
    bzero(linea,255);
    acumulador = 0;
    while( fgets(linea,255,f) != NULL ){
      sscanf(linea,"%d %f",&repeticiones, &valor);  /*Leemos el repeticiones valor*/
      acumulador += repeticiones;                   /*Sumamos las acumuladas*/
      /*Imprime valor porcentaje_de_apariciones*/
      fprintf(aux_f,"%f %f\n",valor,acumulador/(float)num_lines);
      bzero(linea,255);
    }
    fclose(f);
    fclose(aux_f);
    
    eliminarTemporal();
    return OK;
}


void eliminarTemporal(){
  FILE *f;
  char comando[255];
  sprintf(comando,"rm %s", TEMPORAL);   /*Eliminamos el fichero temporal*/
  f = popen(comando,"r");
  pclose(f);
}
