from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface

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

    with open(output_file, 'w') as f:
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
        print_decompiled_function(islev)
        print_xrefs(islev)

def satir_isle(line, satir_numarasi):
    vulnerable_functions = ["memcpy", "strcpy", "strncpy", "sprintf", "vsprintf", "gets", "scanf", "fscanf", "sscanf", "read", "strcpyA", "strcpyW"]
    for function in vulnerable_functions:
        if "%s(" % function in line:
            print_zafiyet(line, satir_numarasi)

mevcut_prg = getCurrentProgram()

for islev in mevcut_prg.getFunctionManager().getFunctions(True):
    if islev.getName() in ["memcpy", "strcpy", "strncpy", "sprintf", "vsprintf", "gets", "scanf", "fscanf", "sscanf", "read", "strcpyA", "strcpyW"]:
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
