/* OVERLORD launcher.
 *
 * AppArmor attaches profiles to the executed binary, not to interpreter
 * scripts — a profile on a #!/usr/bin/python3 script never attaches. This
 * tiny ELF exists solely to be the attachment point for the profile in
 * packaging/apparmor/overlord, which grants the `userns` capability the
 * kernel backend needs on Ubuntu 24.04+.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define SCRIPT "/usr/local/lib/overlord/overlord.py"

int main(int argc, char **argv) {
    char *args[argc + 3];
    args[0] = "python3";
    args[1] = SCRIPT;
    for (int i = 1; i < argc; i++)
        args[i + 1] = argv[i];
    args[argc + 1] = NULL;
    execvp("python3", args);
    perror("overlord: exec python3 failed");
    return 127;
}
