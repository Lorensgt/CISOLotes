import sys, os, subprocess,math,zlib,sys,struct,datetime,re
from os import listdir
from os.path import isfile, join

output_text={
    "es":{
    "INFO_name_language":"Español",
    "INFO_progres":"Progreso",
    "INFO_write_blocks":"Finalizando Rom",
    "INFO_item_list_found":"Estos son los archivos encontrados:",
    "INFO_size_info_convert":"Conversion %s finalizada. Ahorrados %s.",
    "INFO_erase_rom":"Eliminando %s.",
    "INFO_rom_props":"Las características de la rom:",
    "INFO_no_lang_verbose":"No se ha selecionado idioma",
    "INFO_item_select":"Que imagenes deseas convertir:",
    "INFO_info_name_converse":"Convirtiendo %s...",
    "INFO_finished_count":"Convertidos %s.",
    "delete_file_original":"Desea eliminar los archivos originales despues de convertir?",
    "ERROR_lvl_error":"El nivel de compression ha de estar entre 1-9",
    "ERROR_type_input_level":"El nivel ha de ser un número",
    "ERROR_none_input_level":"Falta el nivel de compression",
    "ERROR_none_verbose_mode":"No se reconoce el modo. Use:",
    "ERROR_type_verbose_mode":"No se reconoce el modo. Use:",
    "ERROR_type_language_mode":"Idioma no reconocido. Use:",
    "ERROR_index_no_exist":"Uno de los valores introducidos no existe.",
    "HELP":"""

    CISO
    Convierte ISO a CSO y vicecersa en lotes.

    Opciones                Descripción
    -r                      Recursivo.
    -s                      Seleccionar los archivos a convertir.
    -i                      Ruta de entrada personalizada.
    -l                      Nivel de compression personalizado. 0 = iso, 1-9 = cso (A más alto menos peso y más lento)
    -o                      Ruta de salida personalizada.
    -d                      Elimina el archivo de origen.
    -v [mode][Idioma]       Verbose - all|short Idioma

    Para el cambio de Idioma usar '-v código_de_idioma' Ej: -v es | Para el español.
    Idiomas disponibles:
    """
    }
}

#Utils
def getDate():
    now = datetime.datetime.now()
    return ("%02i:%02i:%02i")%(now.hour, now.minute, now.second)

def bytesToSize(bytes):
    sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
    if bytes == 0:
       return '0 Byte'
    i = int(math.floor(math.log(bytes) / math.log(1024)))
    return str(round(bytes / math.pow(1024, i), 2)) + ' ' + sizes[i]

def printError(text):
    print(text)

def printInfo(text,verbose,type):
    date = ''
    if verbose == type or verbose == 'all' or type =='info':
        if verbose == 'all':
            date = getDate()
        print(text)

#----------------------------------------------------------------------------
#Based on ciso from https://github.com/jamie/ciso
#Thanks for code to https://github.com/phyber/ciso

CISO_MAGIC = 0x4F534943 # CISO
CISO_HEADER_SIZE = 0x18 # 24
CISO_BLOCK_SIZE = 0x800 # 2048
CISO_HEADER_FMT = '<LLQLBBxx' # Little endian
CISO_WBITS = -15 # Maximum window size, suppress gzip header check.
CISO_PLAIN_BLOCK = 0x80000000

def get_terminal_size(fd=sys.stdout.fileno()):
    try:
        import fcntl, termios
        hw = struct.unpack("hh", fcntl.ioctl(
            fd, termios.TIOCGWINSZ, '1234'))
    except:
        try:
            hw = (os.environ['LINES'], os.environ['COLUMNS'])
        except:
            hw = (25, 80)
    return hw

(console_height, console_width) = get_terminal_size()

def seek_and_read(f, pos, size):
    try:
        f.seek(pos, os.SEEK_SET)
        return f.read(size)
    except:
        f.seek(pos, os.SEEK_SET)
        return ""

def parse_header_info(header_data):
    (magic, header_size, total_bytes, block_size,
            ver, align) = header_data
    if magic == CISO_MAGIC:
        ciso = {
            'magic': magic,
            'magic_str': ''.join(
                [chr(magic >> i & 0xFF) for i in (0,8,16,24)]),
            'header_size': header_size,
            'total_bytes': total_bytes,
            'block_size': block_size,
            'ver': ver,
            'align': align,
            'total_blocks': int(total_bytes / block_size),
            }
        ciso['index_size'] = (ciso['total_blocks'] + 1) * 4
    else:
        raise Exception("Not a CISO file.")
    return ciso

def update_progress(progress):
    barLength = console_width - len(output_text[LANGUAGE]["INFO_progres"]+": 100% []") - 1
    block = int(round(barLength*progress)) + 1
    text = "\r"+output_text[LANGUAGE]["INFO_progres"]+": [{blocks}] {percent:.0f}%".format(
            blocks="■" * block + "-" * (barLength - block),
            percent=progress * 100)
    sys.stdout.write(text)
    sys.stdout.flush()

def decompress_cso(infile, outfile):
    with open(outfile, 'wb') as fout:
        with open(infile, 'rb') as fin:
            data = seek_and_read(fin, 0, CISO_HEADER_SIZE)
            header_data = struct.unpack(CISO_HEADER_FMT, data)
            ciso = parse_header_info(header_data)

            # Print some info before we start
            printInfo(output_text[LANGUAGE]["INFO_rom_props"],VERBOSE_MODE,"all")
            for k, v in ciso.items():
                if k == "block_size" or k == "total_bytes":
                    v=bytesToSize(v)
                printInfo("     {}: {}".format(k.capitalize(), v),VERBOSE_MODE,"all")

            # Get the block index
            block_index = [struct.unpack("<I", fin.read(4))[0]
                    for i in
                    range(0, ciso['total_blocks'] + 1)]

            percent_period = ciso['total_blocks'] / 100
            percent_cnt = 0

            for block in range(0, ciso['total_blocks']):
                #print("block={}".format(block))
                index = block_index[block]
                plain = index & 0x80000000
                index &= 0x7FFFFFFF
                read_pos = index << (ciso['align'])
                #print("index={}, plain={}, read_pos={}".format(
                #    index, plain, read_pos))

                if plain:
                    read_size = ciso['block_size']
                else:
                    index2 = block_index[block + 1] & 0x7FFFFFFF
                    read_size = (index2 - index) << (ciso['align'])

                raw_data = seek_and_read(fin, read_pos, read_size)
                raw_data_size = len(raw_data)
                if raw_data_size != read_size:
                    #print("read_size={}".format(read_size))
                    #print("block={}: read error".format(block))
                    sys.exit(1)

                if plain:
                    decompressed_data = raw_data
                else:
                    decompressed_data = zlib.decompress(raw_data, CISO_WBITS)

                # Write decompressed data to outfile
                fout.write(decompressed_data)

                # Progress bar
                percent = int(round((block / (ciso['total_blocks'] + 1)) * 100))
                if percent > percent_cnt:
                    update_progress((block / (ciso['total_blocks'] + 1)))
                    percent_cnt = percent
        # close infile
    # close outfile
    return True

def check_file_size(f):
    f.seek(0, os.SEEK_END)
    file_size = f.tell()
    ciso = {
            'magic': CISO_MAGIC,
            'ver': 1,
            'block_size': CISO_BLOCK_SIZE,
            'total_bytes': file_size,
            'total_blocks': int(file_size / CISO_BLOCK_SIZE),
            'align': 0,
            }
    f.seek(0, os.SEEK_SET)
    return ciso

def write_cso_header(f, ciso):
    f.write(struct.pack(CISO_HEADER_FMT,
        ciso['magic'],
        CISO_HEADER_SIZE,
        ciso['total_bytes'],
        ciso['block_size'],
        ciso['ver'],
        ciso['align']
        ))

def write_block_index(f, block_index):
    for index, block in enumerate(block_index):
        try:
            f.write(struct.pack('<I', block))
        except Exception as e:
            print("Writing block={} with data={} failed.".format(
                index, block))
            print(e)
            sys.exit(1)

def compress_iso(infile, outfile, compression_level):
    with open(outfile, 'wb') as fout:
        with open(infile, 'rb') as fin:
            ciso = check_file_size(fin)
            printInfo(output_text[LANGUAGE]["INFO_rom_props"],VERBOSE_MODE,"all")
            for k, v in ciso.items():
                if k == "block_size" or k == "total_bytes":
                    v=bytesToSize(v)
                printInfo("     {}: {}".format(k.capitalize(), v),VERBOSE_MODE,"all")

            write_cso_header(fout, ciso)
            block_index = [0x00] * (ciso['total_blocks'] + 1)

            # Write the dummy block index for now.
            write_block_index(fout, block_index)

            write_pos = fout.tell()
            align_b = 1 << ciso['align']
            align_m = align_b - 1

            # Alignment buffer is unsigned char.
            alignment_buffer = struct.pack('<B', 0x00) * 64

            # Progress counters
            percent_period = ciso['total_blocks'] / 100
            percent_cnt = 0

            for block in range(0, ciso['total_blocks']):
                # Write alignment
                align = int(write_pos & align_m)
                if align:
                    align = align_b - align
                    size = fout.write(alignment_buffer[:align])
                    write_pos += align

                # Mark offset index
                block_index[block] = write_pos >> ciso['align']

                # Read raw data
                raw_data = fin.read(ciso['block_size'])
                raw_data_size = len(raw_data)

                # Compress block
                # Compressed data will have the gzip header on it, we strip that.
                compressed_data = zlib.compress(raw_data, compression_level)[2:]
                compressed_size = len(compressed_data)

                if compressed_size >= raw_data_size:
                    writable_data = raw_data
                    # Plain block marker
                    block_index[block] |= 0x80000000
                    # Next index
                    write_pos += raw_data_size
                else:
                    writable_data = compressed_data
                    # Next index
                    write_pos += compressed_size

                # Write data
                fout.write(writable_data)

                # Progress bar
                percent = int(round((block / (ciso['total_blocks'] + 1)) * 100))
                if percent > percent_cnt:
                    update_progress((block / (ciso['total_blocks'] + 1)))
                    percent_cnt = percent

            # end for block
            # last position (total size)
            block_index[block] = write_pos >> ciso['align']

            # write header and index block
            printInfo(output_text[LANGUAGE]["INFO_write_blocks"],VERBOSE_MODE,"short")
            fout.seek(CISO_HEADER_SIZE, os.SEEK_SET)
            write_block_index(fout, block_index)

#----------------------------------------------------------------------------

def getFile(extension,path_,RECURSIVE):
    if RECURSIVE == True:
        try:
            if path_:
                path=path_
            else:
                path = os.getcwd()
        except:
            path = os.getcwd()

        extension_len=len(extension)
        files_list = []
        for root, directories, filenames in os.walk(path):
            for filename in filenames:
                if filename[-extension_len:] == extension:
                    files_list.append({"root":root,"filename":filename})
        return len(files_list),files_list
    else:
        try:
            if path_:
                path=path_
            else:
                path = os.getcwd()
        except:
            path = os.getcwd()

        extension_len=len(extension)
        files_list = []
        for f in listdir(path):
            if isfile(join(path, f)):
                if f[-extension_len:] == extension:
                    files_list.append({"root":path,"filename":f})
        return len(files_list),files_list


#Constants
LANGUAGE = 'es'
REMOVE = False
RECURSIVE = False
SELECT_FILES = False
COMPRESSLVL = 9
RUN = True
VERBOSE_TYPE = {"short":"Short Mode","all":"All Mode"}
VERBOSE_MODE = ""
INPUT_PATH = ""
OUTPUT_PATH = ""
DECOMPRESS = False

"""
-r : Recursive
-s : Select Files
-i : Custom path input
-l : Custom level
-o : Custom path output
-d : Delete file
-v : Verbose - all|short language

"""

def convert(files,REMOVE,COMPRESSLVL,extension_out,extension_in,OUTPUT_PATH,DECOMPRESS):
    if OUTPUT_PATH:
        o_exist=True
    else:
        o_exist=False
    for index,rom in enumerate(files):
        if not o_exist:
            OUTPUT_PATH=rom["root"]
        name_rom=rom["filename"][:-(len(extension_in)+1)]
        rom = os.path.join(rom["root"],rom["filename"])
        name_output = rom[:-(len(extension_in)+1)]
        printInfo(output_text[LANGUAGE]["INFO_info_name_converse"]%name_rom,VERBOSE_MODE,"short")
        if DECOMPRESS:
            decompress_cso(rom,os.path.join(OUTPUT_PATH,name_rom+"."+extension_out))
        else:
            compress_iso(rom,os.path.join(OUTPUT_PATH,name_rom+"."+extension_out), COMPRESSLVL)
        printInfo(output_text[LANGUAGE]["INFO_size_info_convert"]%(rom,bytesToSize(os.stat(rom).st_size - os.stat(os.path.join(OUTPUT_PATH,name_rom+"."+extension_out)).st_size)),VERBOSE_MODE,"short")
        if REMOVE:
            printInfo(output_text[LANGUAGE]["INFO_erase_rom"]%rom,VERBOSE_MODE,"short")
            os.remove(rom)
        printInfo(output_text[LANGUAGE]["INFO_finished_count"]%(str(index+1)+"/"+str(len(files))),VERBOSE_MODE,"short")

args = len(sys.argv)
if args <= 1:
    RUN=False
    printError(output_text[LANGUAGE]["HELP"])
else:
    for index, arg in enumerate(sys.argv):
        if arg == "-r":     #Recursive files
            RECURSIVE= True
        if arg == "-l":     #Insert custom level
            try:
                if sys.argv[index+1]:
                    try:
                        lvl = int(sys.argv[index+1])
                        if lvl >=0 and lvl <=9:
                            if lvl>0:
                                COMPRESSLVL = int(sys.argv[index+1])
                            else:
                                DECOMPRESS = True
                        else:
                            printError(output_text[LANGUAGE]["ERROR_lvl_error"])
                            RUN = False
                    except:
                        printError(output_text[LANGUAGE]["ERROR_type_input_level"])
                        RUN = False
            except:
                printError(output_text[LANGUAGE]["ERROR_none_input_level"])
                RUN = False
        if arg == "-s":     #Select Files
            SELECT_FILES=True
        if arg == "-v":     #Active verbose
            try:
                if sys.argv[index+1]:
                    try:
                        if VERBOSE_TYPE[sys.argv[index+1]]:
                            VERBOSE_MODE = sys.argv[index+1]
                        else:
                            printError(output_text[LANGUAGE]["ERROR_type_verbose_mode"])
                            for type in VERBOSE_TYPE:
                                printError("%s - %s"%(type,VERBOSE_TYPE[type]))
                    except:
                        printError(output_text[LANGUAGE]["ERROR_type_verbose_mode"])
                        for type in VERBOSE_TYPE:
                            printError("%s - %s"%(type,VERBOSE_TYPE[type]))

            except:
                printError(output_text[LANGUAGE]["ERROR_none_verbose_mode"])
                for type in VERBOSE_TYPE:
                    printError("%s - %s"%(type,VERBOSE_TYPE[type]))

            try:
                if sys.argv[index+2]:
                    try:
                        if output_text[sys.argv[index+2]]:
                            LANGUAGE = sys.argv[index+1]
                        else:
                            printError(output_text[LANGUAGE]["ERROR_type_language_mode"])
                            for lang in output_text:
                                printError("%s - %s"%(lang,output_text[lang]["INFO_name_language"]))
                    except:
                        printError("%s - %s"%(lang,output_text[lang]["INFO_name_language"]))
            except:
                printInfo(output_text[LANGUAGE]["INFO_no_lang_verbose"],VERBOSE_MODE,"all")
        if arg == "-i":     #Custom path input
            try:
                if sys.argv[index+1]:
                    if re.match("^/[^%S]*", sys.argv[index+1]):
                        INPUT_PATH = sys.argv[index+1]+"/"
                    else:
                        INPUT_PATH = ""
            except IndexError:
                INPUT_PATH = ""
        if arg == "-o":     #Custom path output
            try:
                if sys.argv[index+1]:
                    if re.match("^/[^%S]*", sys.argv[index+1]):
                        OUTPUT_PATH = sys.argv[index+1]+"/"
                    else:
                        OUTPUT_PATH = ""
            except IndexError:
                OUTPUT_PATH = ""
        if arg == "-d":     #Remove files after compress
            REMOVE = True

def selectFiles(extension,INPUT_PATH,VERBOSE_MODE,LANGUAGE,SELECT_FILES,RECURSIVE):
    nfiles,files =getFile(extension,INPUT_PATH,RECURSIVE)
    printInfo(output_text[LANGUAGE]["INFO_item_list_found"]+" "+str(nfiles),VERBOSE_MODE,"info")

    if SELECT_FILES:
        while True:
            for index, file in enumerate(files):
                printInfo(str(index)+":  "+os.path.join(file["root"],file["filename"]),VERBOSE_MODE,"info")
            select_indexes = input(output_text[LANGUAGE]["INFO_item_select"]).split()
            selected=[]
            try:
                for index in select_indexes:
                    selected.append(files[int(index)])
                break
            except:
                printInfo(output_text[LANGUAGE]["ERROR_index_no_exist"],VERBOSE_MODE,"info")

        for x in selected:
            printInfo(os.path.join(x["root"],x["filename"]),VERBOSE_MODE,"short")
        return selected
    else:
        for index, file in enumerate(files):
            printInfo(str(index)+":  "+os.path.join(file["root"],file["filename"]),VERBOSE_MODE,"short")
        return files

def main(REMOVE,COMPRESSLVL,RECURSIVE,SELECT_FILES,VERBOSE_MODE,INPUT_PATH,OUTPUT_PATH):
    if DECOMPRESS == False:
        files = selectFiles("iso",INPUT_PATH,VERBOSE_MODE,LANGUAGE,SELECT_FILES,RECURSIVE)
        convert(files,REMOVE,COMPRESSLVL,"cso","iso",OUTPUT_PATH,DECOMPRESS)
    else:
        files = selectFiles("cso",INPUT_PATH,VERBOSE_MODE,LANGUAGE,SELECT_FILES,RECURSIVE)
        convert(files,REMOVE,COMPRESSLVL,"iso","cso",OUTPUT_PATH,DECOMPRESS)

if RUN == True:
    main(REMOVE,COMPRESSLVL,RECURSIVE,SELECT_FILES,VERBOSE_MODE,INPUT_PATH,OUTPUT_PATH)
