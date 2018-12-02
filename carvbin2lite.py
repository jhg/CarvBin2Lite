#!/usr/bin/env python3
# Script en Python 3.7 
# Carving de bbdd SQLite3, busqueda y extraccion de los archivos.
# No confundir con obtener datos borrados dentro de la bbdd
# 

from io import DEFAULT_BUFFER_SIZE

import sys


sqlhead = ("53", "514c69746520666f726d6174203300")
# cabecera del archivo y longitud
LENSH = 2
posi = []
pos = 0  # control de posicion 
pot = 0  # control de posicion en la tupla
logro = 0  # control de la cantidad de archivos encontrados
inic = 0

longarch = 4  # control de la longitud en bytes del archivo, en pruebas fijo



# funcion para extraer los datos una vez encontrados
def saca_bin(arch, inicio, dato):
        global i
        print('Vamos a sacar los datos de la posicion', inicio)
        nombre = str(inicio)+'.db'
        f = open(nombre, "wb", buffering=min(dato, 67108864))
        arch.seek(inicio)
        print("Datos pasados, inicio", inicio, "y dato", dato) 
        conte = arch.read(dato)
        f.write(conte)
        f.close()
        print(f"SQLite {nombre} extraída satisfactoriamente, creo ;)")
        #damos a i el valor del final del archivo a extraer
        i = i + dato


# funcion para obtener la longitud de la sqlite
def longi_sql(arch, lenar, inicio, tama):
        # comprobamos si el tamaño es 1 y asignamos valor real
        if tama == 1:
                itama = 65536
        else:
                itama = int(tama, 16)

        # obtenemos numero de hojas
        arch.seek(inicio+28)
        pags = arch.read(4).hex()
        
        # calculamos tamaño archivo
        # itama = int(tama,16)
        ipags = int(pags,16)
        datos = itama * ipags
        print("Tamaño de página:",itama,", número de páginas:",ipags)
        print("tamaño de los datos", datos)
        
        # comprobamos que el tamaño no es mayor que el contenedor
        cont_tam = lenar - datos
        if cont_tam > 0 and itama != 0:
                
                # mandamos sacar a archivo
                saca_bin(arch, inicio, datos)
                
        

def contr_integridad(arch, lenar, inicio):
        # Comprobamos tamaño de pagina correcto 512-32768 o 65536
        arch.seek(inicio + 16)
        tpag = arch.read(2).hex()
        if (int(tpag, 16) > 511 and int(tpag, 16) < 32769) or int(tpag, 16) == 1:
                print("Tamaño de la SQLite", tpag, "dentro de los rangos")
                cia = 1
        else:
                cia = 0

        # Control de la versión
        arch.seek(inicio + 96)
        nver = arch.read(4).hex()
        nveri = int(nver, 16)
        if str(nveri)[0:1] == "3":
                print("Versión de la SQLite", str(nveri)[0:1] + "." + str(nveri)[2:4] + "." +str(nveri)[5:7])
                cib = 1
        else:
                cib = 0

        # control de offset 72 a 92 que sean zeros
        arch.seek(inicio + 72)
        roff = arch.read(20).hex()
        if bool(int(roff,16)):
                cic = 0
        else:
                cic = 1
        
        # Si cia y cib son verdaderas, se supone que la sqlite está correcta
        # y podemos extraerla
        if bool(cia) and bool(cib) and bool(cic):
                print("SQLite correcta, procedemos a extraer")
                longi_sql(arch, lenar, inicio, tpag)
        else:
                print("Parece que la SQLite en posicion", inicio, "está corrupta")
                print("Compuébela con un editor hex")


def carving_file(filename):
    sqlite_head = b"\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x33\x00"
    buffer_size = max(DEFAULT_BUFFER_SIZE, 134217728)
    with open(filename, "rb", buffering=buffer_size) as source_file:
        # TODO: this block and child blocks need refactor
        lenar = source_file.seek(0,2)
        source_file.seek(0)
        print("Longitud de archivo", lenar)  # depuracion
        buffer_bytes = source_file.read(buffer_size)
        while len(buffer_bytes) > 15:
            next_buffer_offset = source_file.tell()
            if len(buffer_bytes) < buffer_size:
                buffer_size = len(buffer_bytes)
                print(buffer_size)
            sqlite_found_offset = -1
            # Index is relative to buffer read
            sqlite_head_index = buffer_bytes.find(sqlite_head)
            # Find all offsets in buffer
            while sqlite_head_index > -1:
                # Calculate offset relative to file
                sqlite_found_offset = source_file.tell() - buffer_size + sqlite_head_index
                print("Sqlite found at ", sqlite_found_offset)
                # TODO: this need refactor, optimization work continue here
                global i
                i = sqlite_found_offset
                print("Comprobando integridad de la SQLite:")
                contr_integridad(source_file, lenar, i)
                print("------------------------")
                sqlite_head_index = buffer_bytes.find(sqlite_head, sqlite_head_index+1)
            # Continue reading next buffer
            source_file.seek(next_buffer_offset-len(sqlite_head)+1)
            buffer_bytes = source_file.read(buffer_size)


def main(*argv, **kargv):
    carving_file(argv[0])


if __name__ == "__main__":
        _script_argv = sys.argv[1:]
        if len(_script_argv) == 0:
                print("Usage: %s filename" % (sys.argv[0]))
        else:
                main(*_script_argv)
