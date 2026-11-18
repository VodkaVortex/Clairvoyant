#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>

static int create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, __u32 flags) {
    return syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

static int add_rule(int ruleset, const struct landlock_path_beneath_attr *attr) {
    return syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, attr, 0);
}

static int restrict_self(int ruleset) {
    return syscall(SYS_landlock_restrict_self, ruleset, 0);
}

static __u64 base_rights(void) {
    return LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
           LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
           LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
           LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
           LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
           LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
           LANDLOCK_ACCESS_FS_MAKE_SYM;
}

static void add_path(int ruleset, const char *path, __u64 access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "landlock-run: cannot open %s: %s\n", path, strerror(errno));
        exit(70);
    }
    struct stat status;
    if (fstat(fd, &status) < 0) {
        fprintf(stderr, "landlock-run: cannot stat %s: %s\n", path, strerror(errno));
        close(fd);
        exit(70);
    }
    if (!S_ISDIR(status.st_mode)) {
        __u64 file_access = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                             LANDLOCK_ACCESS_FS_READ_FILE;
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
        file_access |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
        file_access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
#endif
        access &= file_access;
    }
    struct landlock_path_beneath_attr rule = {
        .allowed_access = access,
        .parent_fd = fd,
    };
    if (add_rule(ruleset, &rule) < 0) {
        fprintf(stderr, "landlock-run: cannot allow %s: %s\n", path, strerror(errno));
        close(fd);
        exit(70);
    }
    close(fd);
}

int main(int argc, char **argv) {
    int abi = create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) {
        fprintf(stderr, "landlock-run: Landlock is unavailable; refusing unsafe execution\n");
        return 70;
    }
    __u64 handled = base_rights();
#ifdef LANDLOCK_ACCESS_FS_REFER
    if (abi >= 2) handled |= LANDLOCK_ACCESS_FS_REFER;
#endif
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
    if (abi >= 3) handled |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
    if (abi >= 5) handled |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
#endif
    struct landlock_ruleset_attr ruleset_attr = {.handled_access_fs = handled};
    int ruleset = create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset < 0) {
        fprintf(stderr, "landlock-run: create ruleset failed: %s\n", strerror(errno));
        return 70;
    }

    int index = 1;
    __u64 readonly = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
                     LANDLOCK_ACCESS_FS_READ_DIR;
    while (index < argc && strcmp(argv[index], "--") != 0) {
        if (index + 1 >= argc) {
            fprintf(stderr, "usage: landlock-run [--ro PATH|--rw PATH]... -- COMMAND [ARG...]\n");
            return 64;
        }
        if (strcmp(argv[index], "--ro") == 0) {
            add_path(ruleset, argv[index + 1], readonly);
        } else if (strcmp(argv[index], "--rw") == 0) {
            add_path(ruleset, argv[index + 1], handled);
        } else {
            fprintf(stderr, "landlock-run: unknown option %s\n", argv[index]);
            return 64;
        }
        index += 2;
    }
    if (index >= argc || index + 1 >= argc) {
        fprintf(stderr, "usage: landlock-run [--ro PATH|--rw PATH]... -- COMMAND [ARG...]\n");
        return 64;
    }
    close(ruleset);
    /* Re-create after validating paths so the descriptor remains available. */
    ruleset = create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset < 0) {
        fprintf(stderr, "landlock-run: recreate ruleset failed: %s\n", strerror(errno));
        return 70;
    }
    /* The first pass validated paths but rules belonged to the closed set. Add again. */
    int replay = 1;
    while (replay < index) {
        add_path(ruleset, argv[replay + 1], strcmp(argv[replay], "--rw") == 0 ? handled : readonly);
        replay += 2;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 || restrict_self(ruleset) < 0) {
        fprintf(stderr, "landlock-run: restrict failed: %s\n", strerror(errno));
        return 70;
    }
    close(ruleset);
    execvp(argv[index + 1], &argv[index + 1]);
    fprintf(stderr, "landlock-run: exec %s failed: %s\n", argv[index + 1], strerror(errno));
    return 70;
}
