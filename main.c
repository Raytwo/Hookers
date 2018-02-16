#include <psp2kern/kernel/modulemgr.h>
#include <taihen.h>

void _start() __attribute__ ((weak, alias("module_start")));
int module_start(SceSize argc, const void *args) {
	
  return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp) {
    return SCE_KERNEL_STOP_SUCCESS;
}