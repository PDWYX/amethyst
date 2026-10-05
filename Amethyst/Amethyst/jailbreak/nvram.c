#include "jailbreak.h"
#include "utils.h"
#include "nvram.h"

void nvram_close(nvram_handle_t *handle) {
    if (handle == NULL) return;
    if (MACH_PORT_VALID(handle->ap_client)) {
        mach_port_deallocate(mach_task_self(), handle->ap_client);
    }
    
    if (MACH_PORT_VALID(handle->ap_service)) {
        mach_port_deallocate(mach_task_self(), handle->ap_service);
    }
    
    if (MACH_PORT_VALID(handle->dt_service)) {
        mach_port_deallocate(mach_task_self(), handle->dt_service);
    }
    
    remove_cs_flag(getpid(), CS_NVRAM_UNRESTRICTED);
    free(handle);
}

nvram_handle_t *nvram_open(void) {
    nvram_handle_t *handle = calloc(1, sizeof(nvram_handle_t));
    if (handle == NULL) return NULL;
    
    add_cs_flag(getpid(), CS_NVRAM_UNRESTRICTED);
    handle->dt_service = IOServiceGetMatchingService(0, IOServiceMatching("IODTNVRAM"));
    if (!MACH_PORT_VALID(handle->dt_service)) {
        nvram_close(handle);
        return NULL;
    }
    
    handle->ap_service = IOServiceGetMatchingService(0, IOServiceMatching("AppleMobileApNonce"));
    if (!MACH_PORT_VALID(handle->ap_service)) {
        nvram_close(handle);
        return NULL;
    }
    
    IOServiceOpen(handle->ap_service, mach_task_self(), 0, &handle->ap_client);
    if (!MACH_PORT_VALID(handle->ap_client)) {
        nvram_close(handle);
        return NULL;
    }
    
    uint64_t dt_port_addr = find_ipc_port(handle->dt_service);
    if (dt_port_addr != 0) {
        handle->dt_object_addr = kread64(dt_port_addr + koffsetof(ipc_port, ip_kobject));
    }
    
    uint64_t ap_port_addr = find_ipc_port(handle->ap_service);
    if (ap_port_addr != 0) {
        handle->ap_object_addr = kread64(ap_port_addr + koffsetof(ipc_port, ip_kobject));
    }
    
    if (handle->dt_object_addr == 0 || handle->ap_object_addr == 0) {
        nvram_close(handle);
        return NULL;
    }
    return handle;
}

int nvram_normalize_generator(char *generator, char *output) {
    if (generator == NULL || output == NULL || strnlen(generator, 18) != 18) return -1;
    if (generator[0] != '0' || generator[1] != 'x') return -1;
    for (int i = 2; i < 18; i++) {
        if (!isxdigit(generator[i])) return -1;
    }
    
    CFStringRef str = CFStringCreateWithCString(NULL, generator, kCFStringEncodingUTF8);
    if (str == NULL) return -1;
    
    CFMutableStringRef output_str = CFStringCreateMutableCopy(NULL, CFStringGetLength(str), str);
    CFStringLowercase(output_str, CFLocaleCopyCurrent());
    CFRelease(str);
    
    int status = CFStringGetCString(output_str, output, 20-1, kCFStringEncodingUTF8) ? 0 : -1;
    CFRelease(output_str);
    return status;
}

int nvram_create_generator(nvram_handle_t *handle) {
    if (handle == NULL) return -1;
    uint8_t value[48] = {0};
    size_t size = sizeof(value);
    return IOConnectCallStructMethod(handle->ap_client, 200, NULL, 0, value, &size);
}

int nvram_sync(nvram_handle_t *handle) {
    if (handle == NULL) return -1;
    usleep(100000);

    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    CFDictionarySetValue(dict, CFSTR("temp_amethyst"), CFSTR("0x1337"));
    CFDictionarySetValue(dict, CFSTR("IONVRAM-DELETE-PROPERTY"), CFSTR("temp_amethyst"));
    CFDictionarySetValue(dict, CFSTR("IONVRAM-FORCESYNCNOW-PROPERTY"), CFSTR("com.apple.System.boot-nonce"));
    
    int status = IORegistryEntrySetCFProperties(handle->dt_service, dict);
    CFRelease(dict);
    return status;
}

uint64_t nvram_find_key(nvram_handle_t *handle, uint64_t key) {
    if (handle == NULL || key == 0) return 0;
    uint64_t nvram_dict = kread64(handle->dt_object_addr + 0xc0);
    if (nvram_dict == 0) return 0;

    uint32_t dict_count = kread32(nvram_dict + 0x14);
    if (dict_count == 0) return 0;
    
    uint64_t dict_entry = kread64(nvram_dict + 0x20);
    if (dict_entry == 0) return 0;

    nvram_entry_t *entry_list = calloc(1, sizeof(nvram_entry_t) * (dict_count + 1));
    if (entry_list == NULL) return 0;
    
    kread_buf(dict_entry, entry_list, sizeof(nvram_entry_t) * dict_count);
    uint64_t value = 0;
    
    for (uint32_t i = 0; i < dict_count; i++) {
        if (entry_list[i].key == key) {
            value = entry_list[i].value;
            if (value != 0) break;
        }
    }
    
    free(entry_list);
    return value;
}

// The boot nonce lives in the kernel's Open Firmware variable table
// (xnu: iokit/Kernel/IONVRAM.cpp, "OFVariable gOFVariables[]") where it is
// declared as
//     {"com.apple.System.boot-nonce", kOFVariableTypeString, kOFVariablePermKernelOnly, -1},
// and IODTNVRAM::setPropertyInternal() refuses a userspace write unless the
// entry allows kOFVariablePermUserWrite. Relaxing that single entry lets the
// regular IOKit property path perform the write, so we never have to guess where
// the value bytes live inside the OSString object (the previous implementation
// wrote to "kread64(generator_entry + 0x10)" and could therefore corrupt kernel
// memory, which is what makes the device panic a few seconds after booting).

#define NV_OF_VAR_PERM_USER_WRITE 2
// const char *variableName; UInt32 variableType; UInt32 variablePerm; SInt32 variableOffset;
#define NV_OF_VAR_ENTRY_SIZE 24

static bool nvram_kernel_section(const char *segment_name, const char *section_name, uint64_t *addr, uint64_t *size) {
    if (kinfo == NULL || kinfo->kernel_base == 0) return false;

    struct mach_header_64 *hdr = calloc(1, 0x4000);
    if (hdr == NULL) return false;

    kread_buf(kinfo->kernel_base, hdr, 0x4000);

    bool found = false;
    if (hdr->magic == MH_MAGIC_64) {
        struct load_command *load_cmd = (struct load_command *)(hdr + 1);
        for (uint32_t i = 0; i < hdr->ncmds; i++) {
            if (load_cmd->cmdsize < sizeof(struct load_command)) break;
            if (load_cmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *segment = (struct segment_command_64 *)load_cmd;
                if (strcmp(segment->segname, segment_name) == 0) {
                    struct section_64 *section = (struct section_64 *)(segment + 1);
                    for (uint32_t j = 0; j < segment->nsects; j++) {
                        if (strcmp(section[j].sectname, section_name) == 0) {
                            *addr = section[j].addr;
                            *size = section[j].size;
                            found = true;
                            break;
                        }
                    }
                }
            }
            if (found) break;
            load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
        }
    }

    free(hdr);
    return found;
}

static uint64_t nvram_find_kernel_string(uint64_t addr, uint64_t size, const char *needle) {
    size_t needle_length = strlen(needle);
    if (addr == 0 || needle_length == 0 || size < needle_length) return 0;

    size_t chunk_size = 0x10000;
    uint8_t *buf = malloc(chunk_size + needle_length);
    if (buf == NULL) return 0;

    uint64_t found = 0;
    for (uint64_t offset = 0; offset + needle_length <= size; offset += chunk_size) {
        size_t read_size = chunk_size;
        if (size - offset < read_size) read_size = (size_t)(size - offset);
        if (read_size < needle_length) break;

        memset(buf, 0, chunk_size + needle_length);
        kread_buf(addr + offset, buf, (uint32_t)read_size);

        for (size_t i = 0; i + needle_length <= read_size; i++) {
            if (memcmp(buf + i, needle, needle_length) == 0) {
                found = addr + offset + i;
                break;
            }
        }
        if (found != 0) break;
    }

    free(buf);
    return found;
}

static uint64_t nvram_find_pointer(uint64_t addr, uint64_t size, uint64_t value) {
    if (addr == 0 || size < sizeof(uint64_t)) return 0;

    size_t chunk_size = 0x10000;
    uint8_t *buf = malloc(chunk_size + sizeof(uint64_t));
    if (buf == NULL) return 0;

    uint64_t found = 0;
    for (uint64_t offset = 0; offset + sizeof(uint64_t) <= size; offset += chunk_size) {
        size_t read_size = chunk_size;
        if (size - offset < read_size) read_size = (size_t)(size - offset);

        memset(buf, 0, chunk_size + sizeof(uint64_t));
        kread_buf(addr + offset, buf, (uint32_t)read_size);

        for (size_t i = 0; i + sizeof(uint64_t) <= read_size; i += sizeof(uint64_t)) {
            uint64_t candidate = 0;
            memcpy(&candidate, buf + i, sizeof(candidate));
            if (candidate == value) {
                found = addr + offset + i;
                break;
            }
        }
        if (found != 0) break;
    }

    free(buf);
    return found;
}

static int nvram_relax_boot_nonce_perm(void) {
    uint64_t cstring_addr = 0;
    uint64_t cstring_size = 0;
    if (!nvram_kernel_section("__TEXT", "__cstring", &cstring_addr, &cstring_size)) return -1;

    // gOFVariables starts with {"little-endian?", ...}: find that string and the
    // only pointer to it inside the kernel's data segments to locate the table
    // without depending on any symbol offset.
    uint64_t string_addr = nvram_find_kernel_string(cstring_addr, cstring_size, "little-endian?");
    if (string_addr == 0) return -1;

    uint64_t table = 0;
    const char *segments[] = { "__DATA", "__DATA_CONST", NULL };
    const char *sections[] = { "__data", "__const", NULL };
    for (int s = 0; segments[s] != NULL && table == 0; s++) {
        for (int t = 0; sections[t] != NULL && table == 0; t++) {
            uint64_t addr = 0;
            uint64_t size = 0;
            if (!nvram_kernel_section(segments[s], sections[t], &addr, &size)) continue;
            table = nvram_find_pointer(addr, size, string_addr);
        }
    }
    if (table == 0) return -1;

    for (uint32_t i = 0; i < 128; i++) {
        uint64_t entry = table + ((uint64_t)i * NV_OF_VAR_ENTRY_SIZE);
        uint64_t name = kread64(entry + 0);
        uint32_t type = kread32(entry + 8);
        uint32_t perm = kread32(entry + 12);

        // Only continue while every entry still looks like OFVariable: names
        // inside __cstring, known type/perm values and a NUL terminated table.
        if (name == 0) return -1;
        if (name < cstring_addr || name >= (cstring_addr + cstring_size)) return -1;
        if (type < 1 || type > 4) return -1;
        if (perm > 3) return -1;

        char variable_name[64] = {0};
        kread_buf(name, variable_name, sizeof(variable_name) - 1);
        if (i == 0 && strcmp(variable_name, "little-endian?") != 0) return -1;

        if (strcmp(variable_name, "com.apple.System.boot-nonce") == 0) {
            if (perm != NV_OF_VAR_PERM_USER_WRITE) {
                kwrite32(entry + 12, NV_OF_VAR_PERM_USER_WRITE);
            }
            return 0;
        }
    }

    return -1;
}

int nvram_set_generator(char *generator) {
    char new_generator[20] = {0};
    if (nvram_normalize_generator(generator, &new_generator[0]) != 0) return -1;

    // Fail closed: if we cannot prove that the permission of the boot nonce
    // entry was relaxed, do not touch the nonce at all.
    if (nvram_relax_boot_nonce_perm() != 0) return -1;

    nvram_handle_t *handle = nvram_open();
    if (handle == NULL) return -1;

    int status = -1;
    CFStringRef value = CFStringCreateWithCString(NULL, new_generator, kCFStringEncodingUTF8);
    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    if (value != NULL && dict != NULL) {
        CFDictionarySetValue(dict, CFSTR("com.apple.System.boot-nonce"), value);

        if (IORegistryEntrySetCFProperties(handle->dt_service, dict) == KERN_SUCCESS) {
            // Report success only when the value really is the requested one.
            CFTypeRef readback = IORegistryEntryCreateCFProperty(handle->dt_service, CFSTR("com.apple.System.boot-nonce"), NULL, 0);
            if (readback != NULL) {
                if (CFGetTypeID(readback) == CFStringGetTypeID()) {
                    char current_generator[20] = {0};
                    if (CFStringGetCString(readback, current_generator, sizeof(current_generator), kCFStringEncodingUTF8) &&
                        strcasecmp(current_generator, new_generator) == 0) {
                        status = 0;
                    }
                }
                CFRelease(readback);
            }
            if (status == 0) nvram_sync(handle);
        }
    }

    if (dict != NULL) CFRelease(dict);
    if (value != NULL) CFRelease(value);
    nvram_close(handle);
    return status;
}
