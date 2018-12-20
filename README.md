
# CarvBin2Lite
Carving de binarios para obtener SQLite

Este script en python es capaz de recorrer un binario dd en busca de archivos SQLite3 y extraerlos en archivos independientes.
#####################################################################
usage: carvBin2Lite.py [-h] [-e] sourc

Find and extract SQLite files from binary forensics files

positional arguments:
    sourc         Path and file source

optional arguments:
    -h, --help    show this help message and exit
    -e, -extract  Use to extract found files
That's all folks!!! 
#####################################################################

"Versión 1 de este script"
Es la versión básica. 
Recorre el archivo buscando la cabecera de 16 bytes típica en un archivo SQLite3. Cuando lo encuentra cuenta con triple control de integridad:

1.- Comprueba que el tamaño de leaf esté en los parámetros establecidos

2.- Comprueba que la versión de bbdd corresponda con la 3 y obtiene la versión completa

3.- Comprueba que los 20 bytes reservados estén a 00

Una vez pasados esos 3 filtros, comprueba que el tamaño del archivo a extraer no supera el tamaño del binario y en su caso pasa a crear un archivo al que le pone el nombre del offset donde se ha encontrado "offset.db".

Muestra información de los offset de donde se ha encontrado la cabecera del archivo para que se pueda comprobar la información que hubiera alrededor con un visor hex

MEJORAS A REALIZAR

- Obtención del hash mientras extrae los archivos.


