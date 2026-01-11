#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdbool.h>


int foreach_phdr(void *map_start, void (*func)(Elf32_Phdr *, int), int arg);
void print_phdr(Elf32_Phdr *phdr, int counter);
void print_phdr_detailed(Elf32_Phdr *phdr, int fd);
void load_phdr(Elf32_Phdr *phdr, int fd);
void print_mmap_flags(int prot_flags);
int validate_elf32(Elf32_Ehdr *hdr);
void check_usage(int argc, char **argv);
void unreachable();
extern void startup(int argc, char **argv, void (*entry)());

static void *entry_point = NULL;

// Convert ELF p_flags to mmap protection flags
int get_prot_flags(Elf32_Word flags) {
    int prot = 0;
    if (flags & PF_R) prot |= PROT_READ;
    if (flags & PF_W) prot |= PROT_WRITE;
    if (flags & PF_X) prot |= PROT_EXEC;
    return prot;
}

// Convert flag bits into readable R/W/E string
const char *flag_str(Elf32_Word flags) {
    static char out[4];
    out[0] = (flags & PF_R) ? 'R' : ' ';
    out[1] = (flags & PF_W) ? 'W' : ' ';
    out[2] = (flags & PF_X) ? 'E' : ' ';
    out[3] = '\0';
    return out;
}

// Convert segment type to human-readable string
const char *type_str(Elf32_Word type) {
    switch (type) {
        case PT_NULL: return "NULL";
        case PT_LOAD: return "LOAD";
        case PT_DYNAMIC: return "DYNAMIC";
        case PT_INTERP: return "INTERP";
        case PT_NOTE: return "NOTE";
        case PT_PHDR: return "PHDR";
        case PT_TLS: return "TLS";
        default: return "UNKNOWN";
    }
}

// Print human-readable description of protection flags
void print_mmap_flags(int prot_flags) {
    printf("  -> mmap mapping flags: MAP_PRIVATE | MAP_FIXED\n");
    printf("  -> mmap protection flags: ");
    if (prot_flags & PROT_READ)   printf("PROT_READ ");
    if (prot_flags & PROT_WRITE)  printf("PROT_WRITE ");
    if (prot_flags & PROT_EXEC)   printf("PROT_EXEC ");
    printf("\n");
}

// Print memory address of a program header
void print_phdr(Elf32_Phdr *phdr, int counter) {
    printf("Program header number %d at address %p\n", counter, phdr);
}

// Print full details for each program header
void print_phdr_detailed(Elf32_Phdr *phdr, int fd) {
    static bool first = true;  
    (void)fd;
    if (first) {
        printf("Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align\n");
        first = false;
    }
    printf("%-14s 0x%06x 0x%08x 0x%08x 0x%05x 0x%05x %s 0x%x\n",
           type_str(phdr->p_type),
           phdr->p_offset,
           phdr->p_vaddr,
           phdr->p_paddr,
           phdr->p_filesz,
           phdr->p_memsz,
           flag_str(phdr->p_flags),
           phdr->p_align);

    if (phdr->p_type == PT_LOAD) {
        int prot = get_prot_flags(phdr->p_flags);
        print_mmap_flags(prot);
    }
}


// Map a loadable segment to memory using mmap
void load_phdr(Elf32_Phdr *phdr, int fd) {
    if (phdr->p_type != PT_LOAD) {
        return;
    }

    Elf32_Addr vaddr_page = phdr->p_vaddr & 0xfffff000;
    Elf32_Off  offset_page = phdr->p_offset & 0xfffff000;
    int pad = phdr->p_vaddr & 0xfff;
    int prot = get_prot_flags(phdr->p_flags);

    printf("Loading segment: VirtAddr=0x%08x, Size=0x%05x, Flags=%s\n",
           phdr->p_vaddr, phdr->p_memsz, flag_str(phdr->p_flags));

    void *segment_ptr = mmap((void *)vaddr_page,
                             phdr->p_memsz + pad,
                             prot,
                             MAP_PRIVATE | MAP_FIXED,
                             fd,
                             offset_page);

    if (segment_ptr == MAP_FAILED) {
        perror("mmap failed");
        exit(1);
    }

    printf("Successfully mapped segment at 0x%08x\n", (unsigned int)segment_ptr);

    if (phdr->p_memsz > phdr->p_filesz) {
        void *gap = (char *)phdr->p_vaddr + phdr->p_filesz;
        memset(gap, 0, phdr->p_memsz - phdr->p_filesz);
    }
}

// Iterate over all program headers and call handler
int foreach_phdr(void *map_start, void (*func)(Elf32_Phdr *, int), int arg) {
    Elf32_Ehdr *hdr = (Elf32_Ehdr *)map_start;
    if (!validate_elf32(hdr)) {
        printf("Error: Invalid ELF32 file\n");
        return -1;
    }
    Elf32_Phdr *table = (Elf32_Phdr *)((char *)map_start + hdr->e_phoff);
    for (int i = 0; i < hdr->e_phnum; i++) {
        func(&table[i], arg);
    }
    return 0;
}

// Validate ELF32 format and architecture
int validate_elf32(Elf32_Ehdr *hdr) {
    return memcmp(hdr->e_ident, ELFMAG, SELFMAG) == 0 && hdr->e_ident[EI_CLASS] == ELFCLASS32;
}

// Check command-line arguments
void check_usage(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <elf_file> [args...]\n", argv[0]);
        exit(1);
    }
}

// Called if loaded program returns unexpectedly
void unreachable() {
    printf("Error: Returned from loaded program\n");
    exit(1);
}

int main(int argc, char **argv) {
    check_usage(argc, argv);

    const char *file = argv[1];
    int fd_in = open(file, O_RDONLY);
    if (fd_in == -1) {
        perror("Failed to open file");
        return 1;
    }

    off_t size = lseek(fd_in, 0, SEEK_END);
    if (size == -1) {
        perror("Failed to get file size");
        close(fd_in);
        return 1;
    }

    lseek(fd_in, 0, SEEK_SET);
    void *elf_data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd_in, 0);
    if (elf_data == MAP_FAILED) {
        perror("Failed to map file");
        close(fd_in);
        return 1;
    }

    Elf32_Ehdr *hdr = (Elf32_Ehdr *)elf_data;
    entry_point = (void *)hdr->e_entry;

    printf("=== ELF File Information ===\n");
    printf("Number of program headers: %d\n", hdr->e_phnum);
    printf("Program header offset: 0x%08x\n", hdr->e_phoff);
    printf("Entry point: 0x%08x\n\n", hdr->e_entry);

    printf("=== Program Headers ===\n");
    foreach_phdr(elf_data, print_phdr_detailed, fd_in);
    printf("\n");

    printf("=== Loading Program ===\n");
    foreach_phdr(elf_data, load_phdr, fd_in);
    printf("\n");

    munmap(elf_data, size);

    printf("=== Transferring Control ===\n");
    printf("Jumping to entry point: 0x%08x\n", (unsigned int)entry_point);

    int child_argc = argc - 1;
    char **child_argv = &argv[1];
    startup(child_argc, child_argv, (void (*)(void))entry_point);

    unreachable();
    close(fd_in);
    return 1;
}
