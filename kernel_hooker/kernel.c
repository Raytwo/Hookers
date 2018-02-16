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

typedef struct process_auth_id_ctx //size is 0x90
{
   uint32_t unk_8;
   uint32_t unk_C;
   uint32_t unk_10[20];
   uint32_t unk_60;
   uint32_t unk_64;
   char klicensee[0x10]; // offset 0x68
   uint32_t unk_78;
   uint32_t unk_7C;
   uint32_t unk_80;
   uint32_t unk_84;
   uint32_t unk_88;
   uint32_t unk_8C;
   uint32_t unk_90;
   uint32_t unk_94;
}process_auth_id_ctx;

typedef struct header_ctx_response //size is 0x90
{  
   char data[0x90]; // offset 0x98
}header_ctx_response;

typedef struct header_ctx // size is 0x130. probably SceSblSmCommContext130
{
   uint32_t unk_0;
   uint32_t self_type; //used - user = 1 / kernel = 0
   process_auth_id_ctx auth_ctx; //size is 0x90 - can be obtained with ksceKernelGetProcessAuthid
   header_ctx_response resp; //size is 0x90
   uint32_t unk_128; // used - SceSblACMgrForKernel_d442962e related
   uint32_t unk_12C;
}header_ctx;

#define DUMP_PATH "ur0:dump/"
#define LOG_FILE DUMP_PATH "kplugin-tester_log.txt"

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

SceUID appmgr_patched_hook = -1;
static tai_hook_ref_t appmgr_patched_ref;
static int appmgr_patched(const char* path, char* info) {
	uint32_t state;
	LOG("appmgr hook started.\n");
	log_write(path, strlen(path));
	LOG("\n");
	ENTER_SYSCALL(state);
	int ret = TAI_CONTINUE(int, appmgr_patched_ref, path, info);
	LOG("appmgr hook finished: %08X.\n", ret);
	EXIT_SYSCALL(state);
	return ret;
}

SceUID sub_810180E0_patched_hook = -1;
static tai_hook_ref_t sub_810180E0_patched_ref;
static int sub_810180E0_patched(char* path, char* path2, int unk) {
	uint32_t state;
	LOG("sub_810180E0 hook started.\n");
	log_write(path, strlen(path));
	LOG("\n");
	log_write(path2, strlen(path2));
	LOG("\n%08X\n", unk);
	ENTER_SYSCALL(state);
	int ret = TAI_CONTINUE(int, sub_810180E0_patched_ref, path, path2, unk);
	LOG("sub_810180E0 hook finished: %08X.\n", ret);
	EXIT_SYSCALL(state);
	return ret;
}

SceUID sub_810322E4_patched_hook = -1;
static tai_hook_ref_t sub_810322E4_patched_ref;
static int sub_810322E4_patched(int flag, char* text) {
	uint32_t state;
	LOG("sub_810322E4 hook started.\n");
	LOG("%08X\n", flag);
	log_write(text, strlen(text));
	LOG("\n");
	ENTER_SYSCALL(state);
	int ret = TAI_CONTINUE(int, sub_810322E4_patched_ref, flag, text);
	LOG("sub_810322E4 hook finished: %08X.\n", ret);
	EXIT_SYSCALL(state);
	return ret;
}

SceUID sub_8100B734_patched_hook = -1;
static tai_hook_ref_t sub_8100B734_patched_ref;
static SceUID sub_8100B734_patched(char* pointer, int zero, char* text, int moinsun, int a1, int moinsun2) {
	uint32_t state;
	LOG("sub_8100B734 hook started.\n");
	LOG("%08X\n%08X\n%08X\n%08X\n%08X\n", pointer, a1, moinsun, a1, moinsun2);
	//log_write(text, strlen(text));
	//LOG("\n");
	ENTER_SYSCALL(state);
	SceUID ret = TAI_CONTINUE(SceUID, sub_8100B734_patched_ref, pointer, zero, text, moinsun, a1, moinsun2);
	LOG("sub_8100B734 hook finished: %08X.\n", ret);
	log_write(pointer, 0x10);
	LOG("\n");
	EXIT_SYSCALL(state);
	return ret;
}

SceUID ksceSysrootGetSystemSwVersion_patched_hook = -1;
static tai_hook_ref_t ksceSysrootGetSystemSwVersion_patched_ref;
SceUID ksceSysrootGetSystemSwVersion_patched() {
	LOG("Beginning of the Get Version hook.\n");
	return 0x3650000;
}

SceUID ksceSblAuthMgrCompareSwVersion_patched_hook = -1;
static tai_hook_ref_t ksceSblAuthMgrCompareSwVersion_patched_ref;
SceUID ksceSblAuthMgrCompareSwVersion_patched(int version) {
	LOG("Beginning of the ksceSblAuthMgrCompareSwVersion hook.\n");
	SceUID ret = TAI_CONTINUE(SceUID, ksceSblAuthMgrCompareSwVersion_patched_ref, version);
	LOG("version :%08X\nret:%08X\n", version, ret);
	return 0;
}

SceUID kscePfsMgrMount_patched_hook = -1;
static tai_hook_ref_t kscePfsMgrMount_patched_ref;
SceUID kscePfsMgrMount_patched(char *original_path, char *mount_point, void *klicensee, unsigned int type) {
	LOG("Beginning of the kscePfsMgrMount hook.\n");
	SceUID ret = TAI_CONTINUE(SceUID, kscePfsMgrMount_patched_ref, original_path, mount_point, klicensee, type);
	LOG("klic:\n");
	log_write(klicensee, 0x10);
	LOG("\n");
	LOG("%s\n%s\n", original_path, mount_point);
	LOG("type:%08X\nret:%08X\n", type, ret);
	return ret;
}
SceUID kscePfsMgrMountWithAuthId_patched_hook = -1;
static tai_hook_ref_t kscePfsMgrMountWithAuthId_patched_ref;
SceUID kscePfsMgrMountWithAuthId_patched(char *original_path, char *mount_point, SceUInt64 authid, void *klicensee, unsigned int type) {
	LOG("Beginning of the kscePfsMgrMountWithAuthId hook.\n");
	SceUID ret = TAI_CONTINUE(SceUID, kscePfsMgrMountWithAuthId_patched_ref, original_path, mount_point, authid, klicensee, type);
	LOG("authid:\n");
	log_write(&authid, 0x8);
	LOG("\n");
	LOG("klic:\n");
	log_write(klicensee, 0x10);
	LOG("\n");
	LOG("orig_path:%s\nMP:%s\n", original_path, mount_point);
	LOG("type:%08X\nret:%08X\n", type, ret);
	return ret;
}
SceUID kscePfsMgrUnmount_patched_hook = -1;
static tai_hook_ref_t kscePfsMgrUnmount_patched_ref;
SceUID kscePfsMgrUnmount_patched(char *mount_point) {
	LOG("Beginning of the kscePfsMgrUnmount hook.\n");
	SceUID ret = TAI_CONTINUE(SceUID, kscePfsMgrUnmount_patched_ref, mount_point);
	LOG("MP:%s\nret:%08X\n", mount_point, ret);
	return ret;
}


SceUID module_start_patched_hook = -1;
static tai_hook_ref_t module_start_patched_ref;
SceUID module_start_patched(int a1, int a2) {
	LOG("Beginning of the module_start hook.\n");
	SceUID ret = TAI_CONTINUE(SceUID, module_start_patched_ref, a1, a2);
	//LOG("MP:%s\nret:%08X\n", mount_point, ret);
	return ret;
}


int offset = 0;
void* out_buf;
uint32_t total = 0;
uint32_t length = 0;

SceUID ksceSblAuthMgrParseSelfHeader_patched_hook = -1;
static tai_hook_ref_t ksceSblAuthMgrParseSelfHeader_patched_ref;
static int ksceSblAuthMgrParseSelfHeader_patched(int ctx, const void *self_header, size_t length, header_ctx *buffer) {
	uint32_t state;
	ENTER_SYSCALL(state);
	//LOG("Start of ksceSblAuthMgrParseSelfHeader hook.\n");
	//LOG("%i\n", ctx);
	//log_write(self_header, length);
	//LOG("\n");
	LOG("self hdr length:%i\n", length);
	//log_write(buffer, 0x130);
	//LOG("\n");
	int ret = TAI_CONTINUE(int, ksceSblAuthMgrParseSelfHeader_patched_ref, ctx, self_header, length, buffer);
	/*process_auth_id_ctx auth_ctx = buffer->auth_ctx;
	log_write(auth_ctx.klicensee, 0x10);
	//log_write(buffer, 0x130);
	LOG("\n");*/
	//LOG("End of ksceSblAuthMgrParseSelfHeader hook.\n");
	EXIT_SYSCALL(state);
	return ret;
}

SceUID ksceSblAuthMgrSetupOutputBuffer_patched_hook = -1;
static tai_hook_ref_t ksceSblAuthMgrSetupOutputBuffer_patched_ref;
static int ksceSblAuthMgrSetupOutputBuffer_patched(int ctx, int seg_num, int seg_length, void *out_buffer, uint32_t filesz) {
	uint32_t state;
	ENTER_SYSCALL(state);
	//LOG("Beginning of ksceSblAuthMgrSetupOutputBuffer hook.\n");
	//LOG("%i\n", ctx);
	int ret = TAI_CONTINUE(int, ksceSblAuthMgrSetupOutputBuffer_patched_ref, ctx, seg_num, seg_length, out_buffer, filesz);
	LOG("seg%i\n", seg_num);
	//LOG("%X\n", seg_length);
	//LOG("%X\n", filesz);
	out_buf = out_buffer;
	total = 0x1000;
	length = 0x1000;
	//LOG("End of ksceSblAuthMgrSetupOutputBuffer hook.\n");
	EXIT_SYSCALL(state);
	return ret;
}

SceUID ksceSblAuthMgrCopyToOutputBuffer_patched_hook = -1;
static tai_hook_ref_t ksceSblAuthMgrCopyToOutputBuffer_patched_ref;
static int ksceSblAuthMgrCopyToOutputBuffer_patched(int ctx, char* data_buf_aligned, int off) {
	uint32_t state;
	ENTER_SYSCALL(state);
	//LOG("Beginning of ksceSblAuthMgrSetupOutputBuffer hook.\n");
	//LOG("%i\n", ctx);
	//LOG("off:%i\n", off);
	int ret = TAI_CONTINUE(int, ksceSblAuthMgrCopyToOutputBuffer_patched_ref, ctx, data_buf_aligned, off);
	LOG("off2:%i\n", off);
	total -= off;
	offset = off;
	LOG("total:%i\n", total);
	//if (total <= 100) {
		log_write(out_buf+offset, 0x1000);
		LOG("\n\n");
	//}
	//LOG("End of ksceSblAuthMgrSetupOutputBuffer hook.\n");
	EXIT_SYSCALL(state);
	return ret;
}

static int (* appmgr)(const char* path, void* a2) = NULL;

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args) {
	ksceIoRemove("ur0:dump/kplugin-tester_log.txt");
	LOG("kplugin-tester started.\n");
	//kscePowerRequestDisplayOff();
	//kscePowerRequestSoftReset();
	
	/*LOG("Installing LaunchByPath hook...\n");
	ksceAppMgrLaunchAppByPath_patched_hook = taiHookFunctionExportForKernel(KERNEL_PID,      // Kernel process
                                 &ksceAppMgrLaunchAppByPath_patched_ref,       // Output a reference
                                 "SceAppMgr",  // Name of module being hooked
                                 TAI_ANY_LIBRARY, // library : SceVhBridge
                                 0xB0A37065,      // NID specifying `ksceAppMgrLaunchAppByPath`
                                 ksceAppMgrLaunchAppByPath_patched); // Name of the hook function*/
	
	tai_module_info_t info;
	taiGetModuleInfoForKernel(KERNEL_PID, "SceAppMgr", &info);
	LOG("Installing appmgr hook...\n");
	appmgr_patched_hook = taiHookFunctionOffsetForKernel(KERNEL_PID, &appmgr_patched_ref, info.modid, 0, 0x1642C, 1, appmgr_patched);
	sub_810180E0_patched_hook = taiHookFunctionOffsetForKernel(KERNEL_PID, &sub_810180E0_patched_ref, info.modid, 0, 0x180E0, 1, sub_810180E0_patched);
	sub_810322E4_patched_hook = taiHookFunctionOffsetForKernel(KERNEL_PID, &sub_810322E4_patched_ref, info.modid, 0, 0x322E4, 1, sub_810322E4_patched);
	sub_8100B734_patched_hook = taiHookFunctionOffsetForKernel(KERNEL_PID, &sub_8100B734_patched_ref, info.modid, 0, 0xB734, 1, sub_8100B734_patched);
	
	// Get important function
	/*module_get_offset(KERNEL_PID, info.modid, 0, 0x1642D, (uintptr_t *)&appmgr);
	const char* path = "ux0:/license/app/PCSB00306/91fdc7aac6b061656b46d1516d6d0f46.rif";
	char buf[0xD0];
	int ret = appmgr(path, &buf);
	LOG("%08X\n", ret);
	log_write(buf, 0xD0);
	LOG("\n");*/
	
	ksceSysrootGetSystemSwVersion_patched_hook = taiHookFunctionExportForKernel(KERNEL_PID,      // Kernel process
							 &ksceSysrootGetSystemSwVersion_patched_ref,       // Output a reference
							 "SceSysmem",  // Name of module being hooked
							 TAI_ANY_LIBRARY, // any library
							 0x67AAB627,      // NID specifying `ksceSysrootGetSystemSwVersion`
							 ksceSysrootGetSystemSwVersion_patched); // Name of the hook function
	int swVersion = ksceSysrootGetSystemSwVersion();
	LOG("%08X\n", swVersion);
	ksceSblAuthMgrCompareSwVersion_patched_hook = taiHookFunctionExportForKernel(KERNEL_PID,      // Kernel process
							 &ksceSblAuthMgrCompareSwVersion_patched_ref,       // Output a reference
							 "SceSblAuthMgr",  // Name of module being hooked
							 TAI_ANY_LIBRARY, // any library
							 0xABAB8466,      // NID specifying `ksceSysrootGetSystemSwVersion`
							 ksceSblAuthMgrCompareSwVersion_patched); // Name of the hook function
							 
	kscePfsMgrMount_patched_hook = taiHookFunctionExportForKernel(KERNEL_PID,      // Kernel process
							 &kscePfsMgrMount_patched_ref,       // Output a reference
							 "ScePfsMgr",  // Name of module being hooked
							 TAI_ANY_LIBRARY, // any library
							 0x2D48AEA2,      // NID specifying `kscePfsMgrMount`
							 kscePfsMgrMount_patched); // Name of the hook function
	kscePfsMgrMountWithAuthId_patched_hook = taiHookFunctionExportForKernel(KERNEL_PID,      // Kernel process
							 &kscePfsMgrMountWithAuthId_patched_ref,       // Output a reference
							 "ScePfsMgr",  // Name of module being hooked
							 TAI_ANY_LIBRARY, // any library
							 0xA772209C,      // NID specifying `kscePfsMgrMountWithAuthId`
							 kscePfsMgrMountWithAuthId_patched); // Name of the hook function
	kscePfsMgrUnmount_patched_hook = taiHookFunctionExportForKernel(KERNEL_PID,      // Kernel process
							 &kscePfsMgrUnmount_patched_ref,       // Output a reference
							 "ScePfsMgr",  // Name of module being hooked
							 TAI_ANY_LIBRARY, // any library
							 0x680BC384,      // NID specifying `kscePfsMgrUnmount`
							 kscePfsMgrUnmount_patched); // Name of the hook function
							 
	module_start_patched_hook = taiHookFunctionExportForKernel(KERNEL_PID,      // Kernel process
							 &module_start_patched_ref,       // Output a reference
							 "SceDriverUser",  // Name of module being hooked
							 TAI_ANY_LIBRARY, // any library
							 0x935cd196,      // NID specifying `module_start`
							 module_start); // Name of the hook function
	
	LOG("Installing ksceSblAuthMgrParseSelfHeader hook...\n");
	/*ksceSblAuthMgrParseSelfHeader_patched_hook = taiHookFunctionExportForKernel(KERNEL_PID,      // Kernel process
                                 &ksceSblAuthMgrParseSelfHeader_patched_ref,       // Output a reference
                                 "SceSblAuthMgr",  // Name of module being hooked
                                 TAI_ANY_LIBRARY, // library : any
                                 0xF3411881,      // NID specifying `ksceSblAuthMgrParseSelfHeader`
                                 ksceSblAuthMgrParseSelfHeader_patched); // Name of the hook function*/
	
	/*ksceSblAuthMgrParseSelfHeader_patched_hook = taiHookFunctionImportForKernel(KERNEL_PID, 
                                              &ksceSblAuthMgrParseSelfHeader_patched_ref, 
                                              "SceKernelModulemgr",
                                              0x7ABF5135, // SceSblAuthMgrForKernel
                                              0xF3411881,
                                              ksceSblAuthMgrParseSelfHeader_patched);*/
	/*ksceSblAuthMgrSetupOutputBuffer_patched_hook = taiHookFunctionImportForKernel(KERNEL_PID, 
                                              &ksceSblAuthMgrSetupOutputBuffer_patched_ref, 
                                              "SceKernelModulemgr",
                                              0x7ABF5135, // SceSblAuthMgrForKernel
                                              0x89CCDA2C,
                                              ksceSblAuthMgrSetupOutputBuffer_patched);
	ksceSblAuthMgrCopyToOutputBuffer_patched_hook = taiHookFunctionImportForKernel(KERNEL_PID, 
                                              &ksceSblAuthMgrCopyToOutputBuffer_patched_ref, 
                                              "SceKernelModulemgr",
                                              0x7ABF5135, // SceSblAuthMgrForKernel
                                              0xBC422443,devilkazuya751995
                                              ksceSblAuthMgrCopyToOutputBuffer_patched);*/
											  
	LOG("idps-spoofer_kernel module_start sucessfully ended.\n");
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args) {
	LOG("Stopping idps-spoofer_kernel...\n");

	if (ksceAppMgrLaunchAppByPath_patched_hook >= 0) taiHookReleaseForKernel(ksceAppMgrLaunchAppByPath_patched_hook, ksceAppMgrLaunchAppByPath_patched_ref);
	LOG("kCID hook stopped.\n");
	
	LOG("kplugin-tester module_stop sucessfully ended.\n");
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