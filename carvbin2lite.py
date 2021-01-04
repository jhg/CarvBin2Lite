#!/usr/bin/env python3
# Script en Python 3.7 
# Carving de bbdd SQLite3, busqueda y extraccion de los archivos.
# No confundir con obtener datos borrados dentro de la bbdd
# 

import sys, os
import hashlib, datetime

from argparse import ArgumentParser
from io import DEFAULT_BUFFER_SIZE

parser = ArgumentParser(description="Find and extract SQLite files from binary forensics files",
                         epilog='That\'s all folks!!!')
parser.add_argument('-e', '-extract', default='', choices=['md5', 'sha256', 'sha512'],
                    help='Use \"-e\" to extract found files with hash type \"md5\", \"sha256\" or \"sha512\"')
parser.add_argument('sourc', help='Path and file source')
parser.add_argument('-hc', '-hashcrypt', default='md5', nargs='*', 
                    help='Obtiene el hash del binario fuente y lo compara con uno dado si es pasado como argumento.\
                    Si no se pasa el argumento, calcula el hash md5 del archivo. \
                    Example: \"-hc/-hashcrypt \{md5(default)|sha256|sha512\} <hash_model>\"')
global arch_inf
global non_bmp_map


def hc_inf():
    hc_inf = hashlib.sha256()
    ar_inf = open("informe.txt", "rb")
    buf = ar_inf.read()
    hc_inf.update(buf)
    ar_inf.close()
    ar_inf = open("informe.sha256.txt", "w+")
    ar_inf.write(hc_inf.hexdigest())
    ar_inf.close()
    print('Generado \'.txt\' con hash sha256 del informe') 

def abre_inf():
        global arch_inf
        global non_bmp_map
        arch_inf = open("informe.txt", "w+", encoding='utf-8')
        non_bmp_map = dict.fromkeys(range(0x10000, sys.maxunicode + 1), 0xfffd)
        s3 = hashlib.sha256()
        hini = str(datetime.datetime.now())
        arch_inf.write("--- INICIO DE INFORME --- \n" + hini + "\r\n\r\n")
        arch_inf.write("-- ARCHIVOS \'SQLite\' ENCONTRADOS:        \n\n")


def cerrar_inf():
        global arch_inf
        hfin = str(datetime.datetime.now())
        arch_inf.write(hfin+ "\n--- FIN DE INFORME ---")
        arch_inf.close()
        print("Informe generado")



def hashcalc():
    global arch_inf
    #calculo del hash según argumentos pasados
    ####meter buffer de lectura###
    buffer_size = max(DEFAULT_BUFFER_SIZE, 134217728)
    if argvs.hc[0] == 'sha256':
        leido = hashlib.sha256()
    elif argvs.hc[0] == 'sha512':
        leido = hashlib.sha512()
    else:
        leido = hashlib.md5()
        
    with open(argvs.sourc, "rb", buffering=buffer_size) as afile:
        buf = afile.read(buffer_size)
        while len(buf)>0:
            leido.update(buf)
            buf = afile.read(buffer_size)

    if type(argvs.hc) is list:
        print(f'Obtenido {argvs.hc[0]}:{leido.hexdigest()} del archivo {argvs.sourc}')
       
        if len(argvs.hc) > 1:
            comp = str(argvs.hc[1]) == str(leido.hexdigest())
            print(f'Comprobando el hash {argvs.hc[1]} del archivo pasado')
            if comp and argvs.hc[1]:
                print('Hash comprobado correcto')
                arch_inf.write(f'El archivo {argvs.sourc} ha lanzado un hash {argvs.hc[0]}:{leido.hexdigest()}.\n\n')
                return True
            else:
                print(f'Hash obtenido {leido.hexdigest()} no conincide con pasado por argumento {argvs.hc[1]}\
, por favor, compuebelo o deje en blanco.')
                arch_inf.write(f'La comprobación del hash {argvs.hc[0]} del archivo {argvs.sourc} ha causado error.\n\n')
                return False
        else:
            return True
    else:
        print(f'Obtenido md5:{leido.hexdigest()} del archivo {argvs.sourc}')
        return True
        
 

def extract_length(input_file, offset):
    global arch_inf
    """Get SQLite length and check it"""
    db_size = None
    # Comprobamos tamaño de pagina correcto 512-32768 o 65536
    input_file.seek(offset + 16)
    page_size = int.from_bytes(input_file.read(2), 'big')
    if (page_size > 511 and page_size < 32769) or page_size == 1:
        print("SQLite page size value", page_size, "within the ranges")
        arch_inf.write(f'SQLite page size value {page_size} within the ranges')
        # Set real size when page size is 1
        if page_size == 1:
            page_size = 65536
        # obtenemos numero de paginas
        input_file.seek(offset+28)
        total_pages = int.from_bytes(input_file.read(4), 'big')
        if total_pages != 0:
            # calculamos tamaño archivo
            db_size = page_size * total_pages
            print("DB page size:", page_size)
            print("DB pages:", total_pages)
            print("DB file size:", db_size)
            arch_inf.write(f'DB page size: {page_size}\nDB pages: {total_pages}\nDB file size: {db_size}\n')
    return db_size


def check_null_bytes(input_file, offset):
    """Check from offset+72 to offset+92 all bytes are 0x00"""
    input_file.seek(offset + 72)
    return not max(input_file.read(20))


def check_version(input_file, offset):
    global arch_inf
    """Check SQLite version"""
    version_is_correct = False
    input_file.seek(offset + 96)
    version_number_string = str(int.from_bytes(input_file.read(4), 'big'))
    version_components = (
        version_number_string[0:1].lstrip('0'),
        version_number_string[2:4].lstrip('0'),
        version_number_string[5:7].lstrip('0')
        )
    if version_components[0] == "3":
        print("SQLite version", ".".join(version_components))
        arch_inf.write(f'SQLite version: {version_components}')
        version_is_correct = True
    return version_is_correct


def extract_bin(input_file, offset, db_size):
    global arch_inf
    """Extract SQLite file with offset and size"""
    leido=''
    print(f"Extracting offset {offset} size {db_size}")
    db_file_name = str(offset) + '.db'
    buffer_size = min(db_size, DEFAULT_BUFFER_SIZE)
    if argvs.e == 'sha256':
        leido = hashlib.sha256()
    elif argvs.e == 'sha512':
        leido = hashlib.sha512()
    else:
        leido = hashlib.md5()
        
    # Open file where to copy SQLite file
    with open(db_file_name, "wb", buffering=buffer_size) as db_file:
        # Move to offset and start extraction
        input_file.seek(offset)
        remain_to_copy = db_size
        while remain_to_copy > 0:
            buffer_bytes = input_file.read(min(buffer_size, remain_to_copy))
            leido.update(buffer_bytes)
            db_file.write(buffer_bytes)
            remain_to_copy = remain_to_copy - len(buffer_bytes)
        print(f"SQLite {db_file_name} extraída satisfactoriamente, con {argvs.e}:{leido.hexdigest()}")
        arch_inf.write(f"\nSQLite {db_file_name} extraída satisfactoriamente, con {argvs.e}:{leido.hexdigest()}\n")


def check_and_extract(input_file, input_file_size, offset):
    global arch_inf
    # Get and check db size (it moves to offset+16 and offset+28)
    db_size = extract_length(input_file, offset)
    if db_size is not None and (offset + db_size) < input_file_size:
        # Check from offset+72 to offset+92 all bytes are 0x00
        # And check version (it moves to offset+96)
        # If arg -e, extract sqlite
        if check_null_bytes(input_file, offset) and check_version(input_file, offset):
            print(f"SQLite at offset {offset} is OK!!!")
            arch_inf.write(f"\nSQLite at offset {offset} is OK!!!")
            if argvs.e:
                # Extract SQLite (it moves to offset)
                extract_bin(input_file, offset, db_size)

            # As it has been extracted return
            return

    # If not return before then it has not been extracted
    print(f"SQLite at offset {offset} integrity fail!!!")
    arch_inf.write(f"SQLite at offset {offset} integrity fail!!!\n")



def carving_file(filename):
    global arch_inf
    sqlite_head = b"\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x33\x00"
    buffer_size = max(DEFAULT_BUFFER_SIZE, 134217728)
    with open(filename, "rb", buffering=buffer_size) as source_file:
        # TODO: this block and child blocks need refactor
        input_file_size = source_file.seek(0,2)
        source_file.seek(0)
        print(f'Longitud de archivo {argvs.sourc}: {input_file_size} bytes\r\n- - - - - - - - - -\n')  # depuracion
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
                print("Comprobando integridad de la SQLite:")
                arch_inf.write(f'Sqlite found at {sqlite_found_offset}\n')
                check_and_extract(source_file, input_file_size, sqlite_found_offset)
                print("------------------------")
                arch_inf.write("\n----------------\n\n")
                sqlite_head_index = buffer_bytes.find(sqlite_head, sqlite_head_index+1)
            # Continue reading next buffer
            source_file.seek(next_buffer_offset-len(sqlite_head)+1)
            buffer_bytes = source_file.read(buffer_size)


def main():

    abre_inf()
    #comprobamos el hash del source y si falla, salimos del programa
    print(f'Hashing {argvs.sourc}.\nPlease wait...')
    compro = hashcalc()
    if compro:
        print("\r\nProcediento a buscar los datos......\nPor favor, espere.\r\n")
        
    else:
        print("Compruebe los datos del hash y vuelva a intentarlo")
        return

    
    if argvs.e:
        print(f'Extraeremos los archivos obteniendo el hash {argvs.e}\r\n')
        
    carving_file(argvs.sourc)
    cerrar_inf()
    hc_inf()

if __name__ == "__main__":
    argvs = parser.parse_args()
    
    try:
        os.stat(argvs.sourc).st_size
        print(f'Valid file {argvs.sourc}\r\n')
        if argvs.e:
            print(f'Las bases de datos encontradas se extraerán a un archivo calculando el hash {argvs.e}\r\n')
        else:
            print("Las sqlite encontradas sólo se mostrarán en pantalla.\r\nUse modificador -e para la extracción.\r\n")
        main()
    except IOError:
        print(f'File \"{argvs.sourc}\" does not existe, please retry')
