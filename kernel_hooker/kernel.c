#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/io/fcntl.h>

#include <taihen.h>


typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

#define DUMP_PATH "ur0:dump/"
#define LOG_FILE DUMP_PATH "kplugin-tester_idstorage_log.txt"

static void log_write(const char *buffer, size_t length);

#define LOG(...) \
	do { \
		char buffer[256]; \
		snprintf(buffer, sizeof(buffer), ##__VA_ARGS__); \
		log_write(buffer, strlen(buffer)); \
	} while (0)

/*
int idps_read(const char *file, char *buffer) {
	char idps_text[32];
	char temp_byte_string[2];
	int temp_byte_int = -1;
	SceUID fd = ksceIoOpen(file, SCE_O_RDONLY, 0);
	if (fd < 0)
		return fd;
	int read = ksceIoRead(fd, idps_text, 32);
	for (int i=0; i<32; i+=2) {
		snprintf(temp_byte_string, 2, "%c", idps_text[i]);
		snprintf(temp_byte_string+1, 2, "%c", idps_text[i+1]);
		log_write(temp_byte_string, 2);
		//char *end;
		temp_byte_int = strtol(temp_byte_string, &((char*){0}), 16);
		buffer[i/2] = temp_byte_int;
	}
	ksceIoClose(fd);
	return read;
}

// handle to our hook
SceUID _vshSblAimgrGetConsoleId_patched_hook = -1;
static tai_hook_ref_t _vshSblAimgrGetConsoleId_patched_ref;

// this function is in kernel space
SceUID _vshSblAimgrGetConsoleId_patched(char* CID) {
	LOG("Beginning of the CID hook.\n");
	int ret = TAI_CONTINUE(SceUID, _vshSblAimgrGetConsoleId_patched_ref, CID);
	//////////////////////SPYING PART/////////////////////////
	char oldCID[16];
	LOG("Reading current idps : ");
	ksceKernelMemcpyUserToKernel(oldCID, (uintptr_t)CID, 16);
	log_write(oldCID, 16);
	LOG("\n");
	///////////////////////////////////////////////////////////
	LOG("Reading idps from file :\n");
	char newCID[16];
	//char newCID[16] = {0x00, 0x00, 0x00, 0x01, 0x01, 0x04, 0x00, 0x10, 0x0C, 0x10, 0xF4, 0x03, 0x8B, 0x71, 0xA9, 0x85};
	int read_result = idps_read("ur0:idps.txt", newCID);
	if(read_result != 32) {// We check if 32 bytes have well been read from the file.
		LOG("No file found.\nAborting idps spoofing.\n");
	} else {
		log_write(newCID, 16);
		LOG("\n");
		//////////////////////SPOOFING PART////////////////////////
		LOG("Spoofing idps...\n");
		ksceKernelMemcpyKernelToUser((uintptr_t)CID, newCID, 16);
		LOG("idps sucessfully spoofed.\n");
		///////////////////////////////////////////////////////////
	}
	LOG("CID hook finished.\n");
	return ret;
}

// handle to our hook
SceUID ksceSblSsMgrGetConsoleId_patched_hook = -1;
static tai_hook_ref_t ksceSblSsMgrGetConsoleId_patched_ref;

// this function is in kernel space
SceUID ksceSblSsMgrGetConsoleId_patched(char* kCID) {
	LOG("Beginning of the kCID hook.\n");
	int ret = TAI_CONTINUE(SceUID, ksceSblSsMgrGetConsoleId_patched_ref, kCID);
	//////////////////////SPYING PART/////////////////////////
	char oldkCID[16];
	memset(oldkCID, 'Z', 16);
	LOG("Reading current kCID : ");
	//ksceKernelMemcpyUserToKernel(oldkCID, (uintptr_t)kCID, 16);
	memcpy(&oldkCID, kCID, 16);
	log_write(oldkCID, 16);
	LOG("\n");
	///////////////////////////////////////////////////////////
	LOG("Reading kCID from file :\n");
	char newkCID[16];
	//char newkCID[16] = {0x00, 0x00, 0x00, 0x01, 0x01, 0x04, 0x00, 0x10, 0x0C, 0x10, 0xF4, 0x03, 0x8B, 0x71, 0xA9, 0x85};
	int read_result = idps_read("ur0:idps.txt", newkCID);
	if(read_result != 32) {// We check if 32 bytes have well been read from the file.
		LOG("No file found.\nAborting kCID spoofing.\n");
	} else {
		log_write(newkCID, 16);
		LOG("\n");
		//////////////////////SPOOFING PART////////////////////////
		LOG("Spoofing kCID...\n");
		//ksceKernelMemcpyKernelToUser((uintptr_t)kCID, newkCID, 16);
		//ksceKernelMemcpyUserToKernel(kCID, (uintptr_t)newkCID, 16);
		//memcpy(&kCID, newkCID, 16);
		memcpy((uintptr_t)kCID, newkCID, 16);
		LOG("kCID sucessfully spoofed.\n");
		///////////////////////////////////////////////////////////
	}
	LOG("kCID hook finished.\n");
	return ret;
}*/

/*
const char launch_path_ux[] = "ux0:/data/bootstrap.self";
SceUID ksceAppMgrLaunchAppByPath_patched_hook = -1;
static tai_hook_ref_t ksceAppMgrLaunchAppByPath_patched_ref;
SceUID ksceAppMgrLaunchAppByPath_patched(const char *path, const char *cmd, int cmdlen, int zero, void *opt, void *unk) {
	LOG("Beginning of the Launch hook.\n");
	log_write(path, 4);
	LOG("\n%i\n", cmdlen);
	log_write(cmd, 10);
	LOG("\n");
	log_write(opt, 12);
	LOG("\n");
	char *newPath = "ux0:/data/MLCL00001/eboot.bin";
	memcpy((uintptr_t)path, &newPath, 4);
	LOG("\n");
	char prePath[16];
	memset(prePath, 'Z', 16);
	LOG("Reading pre path : ");
	memcpy(&prePath, path, 16);
	log_write(prePath, 4);
	uint32_t state;
	ENTER_SYSCALL(state);
	int ret = TAI_CONTINUE(SceUID, ksceAppMgrLaunchAppByPath_patched_ref, path, cmd, cmdlen, zero, opt, unk);
	char postPath[16];
	memset(postPath, 'Z', 16);
	LOG("Reading current path : ");
	memcpy(&postPath, path, 16);
	log_write(postPath, 16);
	LOG("\n");
	LOG("Launch hook finished.\n");
	EXIT_SYSCALL(state);
	return ret;
}
*/

SceUID ksceIdStorageLookup_patched_hook = -1;
static tai_hook_ref_t ksceIdStorageLookup_patched_ref;
static int ksceIdStorageLookup_patched(int key, int offset, char *buf, int len) {
	uint32_t state;
	LOG("ksceIdStorageLookup hook started.\n");
	LOG("%08X\n", key);
	LOG("%08X\n", offset);
	LOG("%08X\n", len);
	//log_write(text, strlen(text));
	LOG("\n");
	ENTER_SYSCALL(state);
	int ret = TAI_CONTINUE(int, ksceIdStorageLookup_patched_ref, key, offset, buf, len);
	LOG("ksceIdStorageLookup hook finished: %08X.\n", ret);
	EXIT_SYSCALL(state);
	return ret;
}


//static int (* appmgr)(const char* path, void* a2) = NULL;

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args) {
	//ksceIoRemove(LOG_FILE);
	LOG("kernel_hooker started.\n");
	//kscePowerRequestDisplayOff();
	//kscePowerRequestSoftReset();
	
	/*
	tai_module_info_t info;
	taiGetModuleInfoForKernel(KERNEL_PID, "SceAppMgr", &info);
	LOG("Installing appmgr hook...\n");
	appmgr_patched_hook = taiHookFunctionOffsetForKernel(KERNEL_PID, &appmgr_patched_ref, info.modid, 0, 0x1642C, 1, appmgr_patched);
	sub_810180E0_patched_hook = taiHookFunctionOffsetForKernel(KERNEL_PID, &sub_810180E0_patched_ref, info.modid, 0, 0x180E0, 1, sub_810180E0_patched);
	sub_810322E4_patched_hook = taiHookFunctionOffsetForKernel(KERNEL_PID, &sub_810322E4_patched_ref, info.modid, 0, 0x322E4, 1, sub_810322E4_patched);
	sub_8100B734_patched_hook = taiHookFunctionOffsetForKernel(KERNEL_PID, &sub_8100B734_patched_ref, info.modid, 0, 0xB734, 1, sub_8100B734_patched);
	*/
	
	// Get important function
	/*module_get_offset(KERNEL_PID, info.modid, 0, 0x1642D, (uintptr_t *)&appmgr);
	const char* path = "ux0:/license/app/PCSB00306/91fdc7aac6b061656b46d1516d6d0f46.rif";
	char buf[0xD0];
	int ret = appmgr(path, &buf);
	LOG("%08X\n", ret);
	log_write(buf, 0xD0);
	LOG("\n");*/
	
	ksceIdStorageLookup_patched_hook = taiHookFunctionExportForKernel(KERNEL_PID,      // Kernel process
							 &ksceIdStorageLookup_patched_ref,       // Output a reference
							 "SceIdStorage",  // Name of module being hooked
							 TAI_ANY_LIBRARY, // any library
							 0x6FE062D1,      // NID specifying `ksceIdStorageLookup`
							 ksceIdStorageLookup_patched); // Name of the hook function
	
	LOG("kernel_hooker module_start sucessfully ended.\n");
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args) {
	LOG("Stopping kernel_hooker...\n");

	//if (ksceAppMgrLaunchAppByPath_patched_hook >= 0) taiHookReleaseForKernel(ksceAppMgrLaunchAppByPath_patched_hook, ksceAppMgrLaunchAppByPath_patched_ref);
	//LOG("kCID hook stopped.\n");
	
	LOG("kernel_hooker module_stop sucessfully ended.\n");
	return SCE_KERNEL_STOP_SUCCESS;
}

SceUID fd;
void log_write(const char *buffer, size_t length) {
	fd = ksceIoOpen(LOG_FILE, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 6);
	if (fd < 0)
		return;
	ksceIoWrite(fd, buffer, length);
	ksceIoClose(fd);
}