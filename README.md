
# CarvBin2Lite
Carving de binarios para obtener SQLite

Este script en python es capaz de recorrer un binario dd en busca de archivos SQLite3 y extraerlos en archivos independientes.

#####################################################################
usage: carvBin2Lite.py [-h] [-e {md5,sha256,sha512}] [-hc [HC [HC ...]]] sourc

Find and extract SQLite files from binary forensics files

positional arguments:
  sourc                 Path and file source

optional arguments:
  -h, --help            show this help message and exit
  -e {md5,sha256,sha512}, -extract {md5,sha256,sha512}
                        Use "-e" to extract found files with hash type "md5",
                        "sha256" or "sha512"
  -hc [HC [HC ...]], -hashcrypt [HC [HC ...]]
                        Obtiene el hash del binario fuente y lo compara con
                        uno dado si es pasado como argumento. Si no se pasa el
                        argumento, calcula el hash md5 del archivo. Example:
                        "-hc/-hashcrypt \{md5(default)|sha256|sha512\}
                        <hash_model>"

That's all folks!!!
#####################################################################

*** Versión 2 ***
- Comprueba que el archivo source exista.
- Introducido argumentos.
- Comprueba el md5 del source, utilizando el parametro '-hc' se puede seleccionar el hash a obtener (md5, sha256, sha512) y como segundo argumento de '-hc' se puede utilizar un hash que tengamos para comprobar integridad.
- Presenta los sqlite encontrados en pantalla, sólo los extrae al usar el argumento '-e' junto a un tipo de hash (md5, sha256, sha512). "De momento no calcula el hash del archivo extraído".




*** Version 1 ***
Recorre el archivo buscando la cabecera de 16 bytes típica en un archivo SQLite3. Cuando lo encuentra cuenta con triple control de integridad:

1.- Comprueba que el tamaño de leaf esté en los parámetros establecidos

2.- Comprueba que la versión de bbdd corresponda con la 3 y obtiene la versión completa

3.- Comprueba que los 20 bytes reservados estén a 00

Una vez pasados esos 3 filtros, comprueba que el tamaño del archivo a extraer no supera el tamaño del binario y en su caso pasa a crear un archivo al que le pone el nombre del offset donde se ha encontrado "offset.db".

Muestra información de los offset de donde se ha encontrado la cabecera del archivo para que se pueda comprobar la información que hubiera alrededor con un visor hex

MEJORAS A REALIZAR

- Obtención del hash mientras extrae los archivos.
- Creación de informe

