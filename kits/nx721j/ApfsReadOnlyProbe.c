// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

// The 21H461 restore helper passes the device pointer, flags and live-volume
// mode. The matching kernel copies 0x144 bytes after the device pointer.
struct MountArguments {
    const char *device;
    uint64_t flags;
    uint16_t mode;
    unsigned char reserved[0x144 - sizeof(uint64_t) - sizeof(uint16_t)];
};

_Static_assert(offsetof(struct MountArguments, flags) == 8, "64-bit APFS mount ABI");
_Static_assert(offsetof(struct MountArguments, mode) == 16, "APFS live-volume mode offset");

static const char mount_point[] = "/mnt";
static const char version_path[] = "/mnt/System/Library/CoreServices/SystemVersion.plist";
static const unsigned char expected[CC_SHA256_DIGEST_LENGTH] = {
    0xe5, 0xed, 0xe4, 0x60, 0xe1, 0xc3, 0xdc, 0x8d,
    0x43, 0x3f, 0xc1, 0x3d, 0x9c, 0xfc, 0x14, 0xaf,
    0x1e, 0xc5, 0x94, 0xe8, 0x9b, 0x5d, 0x47, 0x88,
    0x8a, 0x37, 0x00, 0x31, 0xcd, 0x58, 0x7e, 0x14,
};

static int verify_file(int fd)
{
    struct statfs volume;
    struct stat file;
    if (fstatfs(fd, &volume) || fstat(fd, &file)) {
        perror("NX721J probe file metadata");
        return 1;
    }
    if (!(volume.f_flags & MNT_RDONLY) || strcmp(volume.f_fstypename, "apfs") ||
        strcmp(volume.f_mntonname, mount_point) || !S_ISREG(file.st_mode) || file.st_size != 574) {
        fprintf(stderr, "NX721J probe file, filesystem, or size mismatch\n");
        return 1;
    }

    unsigned char data[574];
    size_t done = 0;
    while (done < sizeof(data)) {
        ssize_t count = read(fd, data + done, sizeof(data) - done);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            fprintf(stderr, "NX721J probe file read stopped at %zu bytes\n", done);
            return 1;
        }
        done += (size_t)count;
    }

    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data, sizeof(data), digest);
    if (memcmp(digest, expected, sizeof(digest))) {
        fprintf(stderr, "NX721J SystemVersion.plist SHA-256 mismatch\n");
        return 1;
    }
    puts("NX721J SystemVersion.plist length and SHA-256 verified");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2 || strncmp(argv[1], "/dev/disk", 9) ||
        !argv[1][9] || strspn(argv[1] + 9, "0123456789s") != strlen(argv[1] + 9)) {
        fprintf(stderr, "usage: %s /dev/diskNsNsN\n", argv[0]);
        return 2;
    }
    struct stat node;
    struct statfs covered;
    if (lstat(argv[1], &node) || !S_ISBLK(node.st_mode)) {
        fprintf(stderr, "NX721J expected an APFS block device\n");
        return 2;
    }
    if (lstat(mount_point, &node) || !S_ISDIR(node.st_mode) ||
        statfs(mount_point, &covered) || !strcmp(covered.f_mntonname, mount_point)) {
        fprintf(stderr, "NX721J /mnt must be an available directory\n");
        return 2;
    }

    const int flags = MNT_RDONLY | MNT_NODEV | MNT_NOSUID | MNT_NOEXEC | MNT_DONTBROWSE;
    struct MountArguments args = { .device = argv[1], .flags = (uint64_t)flags, .mode = 1 };
    if (mount("apfs", mount_point, flags, &args)) {
        perror("NX721J APFS mount");
        return 3;
    }
    puts("NX721J APFS mounted");

    int result = 1;
    int fd = open(version_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) {
        result = verify_file(fd);
        close(fd);
    } else {
        perror("NX721J SystemVersion.plist open");
    }
    if (unmount(mount_point, 0)) {
        perror("NX721J APFS unmount");
        return 5;
    }
    puts("NX721J APFS unmounted");
    return result ? 4 : 0;
}
