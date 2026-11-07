#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>

int n1a_fstat(int, struct stat *);
int n1a_fstatat(int, const char *, struct stat *, int);
int n1a_close_fd(int);
void *n1a_dlsym(void *, const char *);

// Define after the system declarations (close has a Darwin asm alias). The
// function-like macro leaves the Objective-C -close selector unchanged.
#define fstat n1a_fstat
#define fstatat n1a_fstatat
#define close(fd) n1a_close_fd(fd)
#define dlsym n1a_dlsym
