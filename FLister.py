# -*- coding: utf-8 -*-
from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
import os

#Dizini belirtebilirsiniz
decompile_dizin = "/tmp/splunks/"
if not os.path.exists(decompile_dizin):
    os.makedirs(decompile_dizin)

def print_decompiled_function(islev):
    decomp_arayuzu = DecompInterface()
    decomp_arayuzu.openProgram(mevcut_prg)
    islev_kodu = decomp_arayuzu.decompileFunction(islev, 60, getMonitor())

    print("="*80)
    print("Ayristirilmis kod, islev %s icin 0x%s adresinde:" % (islev.getName(), islev.getEntryPoint()))
    print(islev_kodu.getCCodeMarkup())
    #export_decompiled_function("%s", "%s" % (islev_kodu.getCCodeMarkup(),islev.getName()))
    export_decompiled_function(islev, "%s" % (islev.getName()))


def export_decompiled_function(islev, output_file):
    decomp_arayuzu = DecompInterface()
    decomp_arayuzu.openProgram(mevcut_prg)
    islev_kodu = decomp_arayuzu.decompileFunction(islev, 60, getMonitor())

    if islev_kodu.getDecompiledFunction() is None:
        print("Hata: Kod decompile edilemedi ¯\_(ツ)_/¯  %s" % islev.getName())
        return

    dosya_cikis_dizini = os.path.join(decompile_dizin, output_file)
    with open(dosya_cikis_dizini, 'w') as f:
        f.write(islev_kodu.getDecompiledFunction().getC())

def print_xrefs(islev):
    print("="*80)
    print("islev %s icin xreferanslar, 0x%s adresinde:" % (islev.getName(), islev.getEntryPoint()))
    for referans in getReferencesTo(islev.getEntryPoint()):
        print("    Referans, 0x%s adresinde" % referans.getFromAddress())
        islev = getFunctionContaining(referans.getFromAddress())
        if islev is not None:
            print("="*80)
            print("Aranan islev %s, 0x%s adresinde:" % (islev.getName(), islev.getEntryPoint()))
            print_decompiled_function(islev)
            
def print_zafiyet(line, satir_numarasi):
    baslangic_indexi = line.find("(") + 1
    son_index = line.find(",")
    islev_adresi = line[baslangic_indexi:son_index].strip()

    islev = getFunctionContaining(toAddr(int(islev_adresi, 16)))
    if islev is not None:
        print("="*80)
        print("Aranan islev cagrisi, satir %d:" % satir_numarasi)
        print(line)

        decomp_arayuzu = DecompInterface()
        decomp_arayuzu.openProgram(mevcut_prg)
        islev_kodu = decomp_arayuzu.decompileFunction(islev, 60, getMonitor())
        c_code = islev_kodu.getCCodeMarkup()

	#Deneme alinti kod bloklari, yapisal bir yani yok.
	if "memcpy(" in line:
            src_index = c_code.find("=") + 1
            dest_end_index = c_code.find(",")
            src_index = c_code.find(",", dest_end_index + 1) + 1
            src_end_index = c_code.find(",", src_index)
            dest_size = c_code[dest_end_index+1:src_index-1].strip()
            src_size = c_code[src_end_index+1:].strip()
            if src_size.startswith("&") or src_size.isdigit():
                if int(src_size[1:]) > int(dest_size):
                    print("Zafiyet memcpy!")
            else:
                if "strlen(" in src_size:
                    src_str_index = src_size.find("(") + 1
                    src_str_end_index = src_size.find(")")
                    src_str_name = src_size[src_str_index:src_str_end_index]
                    for variable in islev_kodu.getGlobalVariables():
                        if variable.getName() == src_str_name:
                            src_str_size = variable.getLength()
                            if src_str_size > int(dest_size):
                                print("Zafiyet memcpy!")
                            break
	#Bitis

        print_xrefs(islev)

def satir_isle(satir, satir_numarasi):
    vulnerable_functions = ["memcpy", "strcpy", "strncpy", "sprintf", "vsprintf", "gets", "scanf", "fscanf", "sscanf", "read"]
    for function in vulnerable_functions:
        if "%s(" % function in satir:
            print_zafiyet(satir, satir_numarasi)

mevcut_prg = getCurrentProgram()

for islev in mevcut_prg.getFunctionManager().getFunctions(True):
    if islev.getName() in ["memcpy", "strcpy", "strncpy", "sprintf", "vsprintf", "gets", "scanf", "fscanf", "sscanf", "read"]:
        print("="*80)
        print("Aranan islev %s, 0x%s adresinde:" % (islev.getName(), islev.getEntryPoint()))
        print_decompiled_function(islev)
        print_xrefs(islev)

    for adres in islev.getBody().getAddresses(True):
        komut = mevcut_prg.getListing().getInstructionAt(adres)
        if komut is not None and komut.getMnemonicString() in ["mov", "lea", "push"]:
            operands = komut.getOpObjects(0)
            for operand in operands:
                if operand.toString().startswith("0x"):
                    line = komut.toString()
                    satir_isle(line, komut.getAddress().getOffset())
                    break
