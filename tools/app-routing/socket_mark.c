/* Проверка ранней маркировки сокетов внутри отдельного тестового ядра. */
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int is_lab_guest(void)
{
    char buffer[4096];
    FILE *file = fopen("/proc/cmdline", "r");
    if (!file)
        return 0;
    int read_ok = fgets(buffer, sizeof(buffer), file) != NULL;
    fclose(file);
    if (!read_ok)
        return 0;
    char *save = NULL;
    for (char *token = strtok_r(buffer, " \n", &save); token;
         token = strtok_r(NULL, " \n", &save)) {
        if (strcmp(token, "aivpn.app-routing-lab=1") == 0)
            return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: socket_mark CGROUP MARK\n");
        return 2;
    }
    if (getuid() != 0 || !is_lab_guest() || access("/lab/.app-routing-guest", R_OK) != 0 ||
        strcmp(argv[1], "/sys/fs/cgroup/aivpn-selected") != 0) {
        fprintf(stderr, "Этот инструмент разрешен только внутри отдельного тестового guest\n");
        return 2;
    }
    char *end = NULL;
    errno = 0;
    unsigned long mark = strtoul(argv[2], &end, 0);
    if (errno || end == argv[2] || *end || mark > 0xffffffffUL)
        return 2;
    struct bpf_insn insns[] = {
        { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_2, .imm = (int)mark },
        { .code = BPF_STX | BPF_MEM | BPF_W, .dst_reg = BPF_REG_1,
          .src_reg = BPF_REG_2, .off = offsetof(struct bpf_sock, mark) },
        { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 1 },
        { .code = BPF_JMP | BPF_EXIT },
    };
    char log[65536] = {0};
    struct bpf_prog_load_opts opts = {
        .sz = sizeof(opts),
        .expected_attach_type = BPF_CGROUP_INET_SOCK_CREATE,
        .log_level = 1,
        .log_size = sizeof(log),
        .log_buf = log,
    };
    int group = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (group < 0) {
        perror("open cgroup");
        return 1;
    }
    int program = bpf_prog_load(BPF_PROG_TYPE_CGROUP_SOCK, "aivpn_mark", "MIT",
        insns, sizeof(insns) / sizeof(insns[0]), &opts);
    if (program < 0) {
        perror("load BPF");
        fprintf(stderr, "%s", log);
        close(group);
        return 1;
    }
    int result = bpf_prog_attach(program, group, BPF_CGROUP_INET_SOCK_CREATE, 0);
    if (result)
        perror("attach BPF");
    close(program);
    close(group);
    return result ? 1 : 0;
}
