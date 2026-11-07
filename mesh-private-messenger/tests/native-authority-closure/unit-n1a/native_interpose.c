#include <dispatch/dispatch.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>

// Compiled only into the instrumented driver. Every wrapper performs the real
// syscall unchanged; the stat barrier parks after its result, inside the real
// production currentLocked call. No policy result or runtime counter is faked.
static dispatch_semaphore_t stat_ready, stat_resume, closed_event, released_event;
static atomic_int remaining_stats, directory_fd, lock_fd;
static atomic_int watched_directory, watched_lock, closes, releases, total_closes;

__attribute__((constructor)) static void initialize(void) {
    stat_ready = dispatch_semaphore_create(0);
    stat_resume = dispatch_semaphore_create(0);
    closed_event = dispatch_semaphore_create(0);
    released_event = dispatch_semaphore_create(0);
    atomic_store(&directory_fd, -1);
    atomic_store(&lock_fd, -1);
    atomic_store(&watched_directory, -1);
    atomic_store(&watched_lock, -1);
}
int n1a_fstat(int fd, struct stat *value) {
    int result = fstat(fd, value);
    if (result == 0) {
        if (S_ISDIR(value->st_mode)) atomic_store(&directory_fd, fd);
        if (S_ISREG(value->st_mode)) atomic_store(&lock_fd, fd);
    }
    return result;
}
int n1a_fstatat(int fd, const char *path, struct stat *value, int flags) {
    int result = fstatat(fd, path, value, flags);
    int count = atomic_load(&remaining_stats);
    if (count > 0 && atomic_fetch_sub(&remaining_stats, 1) == 1) {
        dispatch_semaphore_signal(stat_ready);
        dispatch_semaphore_wait(stat_resume, DISPATCH_TIME_FOREVER);
    }
    return result;
}
int n1a_close_fd(int fd) {
    int result = close(fd);
    atomic_fetch_add(&total_closes, 1);
    if (fd == atomic_load(&watched_directory) || fd == atomic_load(&watched_lock)) {
        atomic_fetch_add(&closes, 1);
        dispatch_semaphore_signal(closed_event);
    }
    return result;
}
struct MeshNativeGeneration;
extern void mesh_authority_generation_release_v2(const struct MeshNativeGeneration *);
void n1a_generation_release(const struct MeshNativeGeneration *node) {
    mesh_authority_generation_release_v2(node);
    atomic_fetch_add(&releases, 1);
    dispatch_semaphore_signal(released_event);
}
void *n1a_dlsym(void *handle, const char *symbol) {
    if (strcmp(symbol, "mesh_authority_generation_release_v2") == 0) return (void *)n1a_generation_release;
    return dlsym(handle, symbol);
}
void n1a_arm_stat(int count) { atomic_store(&remaining_stats, count); }
int n1a_wait_stat(void) {
    return dispatch_semaphore_wait(stat_ready, dispatch_time(DISPATCH_TIME_NOW, 8*NSEC_PER_SEC)) == 0;
}
void n1a_resume_stat(void) { dispatch_semaphore_signal(stat_resume); }
int n1a_directory_fd(void) { return atomic_load(&directory_fd); }
int n1a_lock_fd(void) { return atomic_load(&lock_fd); }
void n1a_watch_closes(void) {
    atomic_store(&watched_directory, atomic_load(&directory_fd));
    atomic_store(&watched_lock, atomic_load(&lock_fd));
    atomic_store(&closes, 0);
}
int n1a_close_count(void) { return atomic_load(&closes); }
int n1a_total_closes(void) { return atomic_load(&total_closes); }
int n1a_release_count(void) { return atomic_load(&releases); }
int n1a_wait_release(void) {
    return dispatch_semaphore_wait(released_event, dispatch_time(DISPATCH_TIME_NOW, 8*NSEC_PER_SEC)) == 0;
}
int n1a_wait_disposed(void) {
    while (atomic_load(&closes) < 2) {
        if (dispatch_semaphore_wait(closed_event, dispatch_time(DISPATCH_TIME_NOW, 8*NSEC_PER_SEC))) return 0;
    }
    return atomic_load(&closes) == 2;
}
