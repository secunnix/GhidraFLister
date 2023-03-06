# GhidraFLister


flister.py> Running...
================================================================================
Aranan islev strcpy, 0x00101f90 adresinde:
================================================================================
Ayristirilmis kod, islev strcpy icin 0x00101f90 adresinde:
/* WARNING: Unknown calling convention yet parameter storage is locked */char * strcpy(char *__dest,char *__src){char *pcVar1;pcVar1 = (char *)(*(code *)PTR_strcpy_00109eb8)();return pcVar1;}
================================================================================
islev strcpy icin xreferanslar, 0x00101f90 adresinde:
    Referans, 0x001045c8 adresinde
    Referans, 0x00105782 adresinde
    Referans, 0x00103fa8 adresinde
    Referans, 0x00104b22 adresinde
    Referans, 0x001030c8 adresinde
================================================================================
Aranan islev memcpy, 0x00102120 adresinde:
================================================================================
Ayristirilmis kod, islev memcpy icin 0x00102120 adresinde:
/* WARNING: Unknown calling convention yet parameter storage is locked */void * memcpy(void *__dest,void *__src,size_t __n){void *pvVar1;pvVar1 = (void *)(*(code *)PTR_memcpy_00109f80)();return pvVar1;}
================================================================================
islev memcpy icin xreferanslar, 0x00102120 adresinde:
    Referans, 0x00105602 adresinde
    Referans, 0x0010569b adresinde
================================================================================
Aranan islev memcpy, 0x0010d000 adresinde:
================================================================================
Ayristirilmis kod, islev memcpy icin 0x0010d000 adresinde:
/* WARNING: Control flow encountered bad instruction data *//* WARNING: Unknown calling convention yet parameter storage is locked */void * memcpy(void *__dest,void *__src,size_t __n){/* WARNING: Bad instruction - Truncating control flow here */halt_baddata();}
================================================================================
islev memcpy icin xreferanslar, 0x0010d000 adresinde:
    Referans, 0x00109f80 adresinde
    Referans, 0x00102120 adresinde
================================================================================
Aranan islev strcpy, 0x0010d098 adresinde:
================================================================================
Ayristirilmis kod, islev strcpy icin 0x0010d098 adresinde:
/* WARNING: Control flow encountered bad instruction data *//* WARNING: Unknown calling convention yet parameter storage is locked */char * strcpy(char *__dest,char *__src){/* WARNING: Bad instruction - Truncating control flow here */halt_baddata();}
================================================================================
islev strcpy icin xreferanslar, 0x0010d098 adresinde:
    Referans, 0x00109eb8 adresinde
    Referans, 0x00101f90 adresinde
flister.py> Finished!
