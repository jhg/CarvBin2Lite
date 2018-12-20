#!/usr/bin/env python3
# Script en Python 3.7 
# Carving de bbdd SQLite3, busqueda y extraccion de los archivos.
# No confundir con obtener datos borrados dentro de la bbdd
# 

from io import DEFAULT_BUFFER_SIZE

import sys, os

from argparse import ArgumentParser

parser = ArgumentParser(description="Find and extract SQLite files from binary forensics files",
                         epilog='That\'s all folks!!!')
parser.add_argument('-e', '-extract', action='store_true',
                    default='', help='Use to extract found files')
parser.add_argument('sourc', help='Path and file source')


def extract_length(input_file, offset):
    """Get SQLite length and check it"""
    db_size = None
    # Comprobamos tamaño de pagina correcto 512-32768 o 65536
    input_file.seek(offset + 16)
    page_size = int.from_bytes(input_file.read(2), 'big')
    if (page_size > 511 and page_size < 32769) or page_size == 1:
        print("SQLite page size value", page_size, "within the ranges")
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
    return db_size


def check_null_bytes(input_file, offset):
    """Check from offset+72 to offset+92 all bytes are 0x00"""
    input_file.seek(offset + 72)
    return not max(input_file.read(20))


def check_version(input_file, offset):
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
        version_is_correct = True
    return version_is_correct


def extract_bin(input_file, offset, db_size):
    """Extract SQLite file with offset and size"""
    print(f"Extracting offset {offset} size {db_size}")
    db_file_name = str(offset) + '.db'
    buffer_size = min(db_size, DEFAULT_BUFFER_SIZE)
    # Open file where to copy SQLite file
    with open(db_file_name, "wb", buffering=buffer_size) as db_file:
        # Move to offset and start extraction
        input_file.seek(offset)
        remain_to_copy = db_size
        while remain_to_copy > 0:
            buffer_bytes = input_file.read(min(buffer_size, remain_to_copy))
            db_file.write(buffer_bytes)
            remain_to_copy = remain_to_copy - len(buffer_bytes)
        print(f"SQLite {db_file_name} extraída satisfactoriamente, creo ;)")


def check_and_extract(input_file, input_file_size, offset):
    
    # Get and check db size (it moves to offset+16 and offset+28)
    db_size = extract_length(input_file, offset)
    if db_size is not None and (offset + db_size) < input_file_size:
        # Check from offset+72 to offset+92 all bytes are 0x00
        # And check version (it moves to offset+96)
        # If arg -e, extract sqlite
        if check_null_bytes(input_file, offset) and check_version(input_file, offset):
            print(f"SQLite at offset {offset} is OK!!!")
            if sali:
                # Extract SQLite (it moves to offset)
                extract_bin(input_file, offset, db_size)

            # As it has been extracted return
            return

    # If not return before then it has not been extracted
    print(f"SQLite at offset {offset} integrity fail!!!")



def carving_file(filename):
    sqlite_head = b"\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x33\x00"
    buffer_size = max(DEFAULT_BUFFER_SIZE, 134217728)
    with open(filename, "rb", buffering=buffer_size) as source_file:
        # TODO: this block and child blocks need refactor
        input_file_size = source_file.seek(0,2)
        source_file.seek(0)
        print("Longitud de archivo", input_file_size)  # depuracion
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
                check_and_extract(source_file, input_file_size, sqlite_found_offset)
                print("------------------------")
                sqlite_head_index = buffer_bytes.find(sqlite_head, sqlite_head_index+1)
            # Continue reading next buffer
            source_file.seek(next_buffer_offset-len(sqlite_head)+1)
            buffer_bytes = source_file.read(buffer_size)


def main():
    carving_file(arch)
    

if __name__ == "__main__":
    argvs = parser.parse_args()
    arch = argvs.sourc
    sali = argvs.e
    try:
        os.stat(arch).st_size
        print(f'Valid file {arch}\r\n {sali}')
        if sali:
            print("Las bases de datos encontradas se extraerán a un archivo")
        else:
            print("Las sqlite encontradas sólo se mostrarán en pantalla.\r\nUse modificador -e para la extracción.\r\n")
        main()
    except IOError:
        print(f'File \"{arch}\" does not existe, please retry')
