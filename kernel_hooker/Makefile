TITLE_ID = KHOOKER01
TARGET = kernel_hooker
PSVITAIP = 192.168.0.16

PLUGIN_OBJS = kernel.o
HEADERS = $(wildcard *.h)

PLUGIN_LIBS = -ltaihenForKernel_stub -ltaihenModuleUtils_stub -lSceThreadmgrForDriver_stub -lSceModulemgrForKernel_stub -lSceIofilemgrForDriver_stub -lSceSysmemForDriver_stub -lSceSysclibForDriver_stub -lSceSblAuthMgrForKernel_stub -lSceSblSsMgrForDriver_stub -lScePowerForDriver_stub -lSceSysrootForDriver_stub -lSceNpDrmForDriver_stub

PREFIX  = arm-vita-eabi
CC      = $(PREFIX)-gcc
CFLAGS  = -Wl,-q -Wall -O3 -Wno-implicit-function-declaration
ASFLAGS = $(CFLAGS)

all: kplugin.skprx

kplugin.skprx: kplugin.velf
	vita-make-fself -c $< $@

kplugin.velf: kplugin.elf
	vita-elf-create -e exports.yml $< $@

kplugin.elf: $(PLUGIN_OBJS)
	$(CC) $(CFLAGS) $^ $(PLUGIN_LIBS) -o $@ -nostdlib

clean:
	@rm -rf *.velf *.elf *.vpk *.skprx $(MAIN_OBJS) $(PLUGIN_OBJS) param.sfo eboot.bin

send: eboot.bin
	curl -T kplugin.skprx ftp://$(PSVITAIP):1337/ux0:/tai/
	@echo "Sent."
