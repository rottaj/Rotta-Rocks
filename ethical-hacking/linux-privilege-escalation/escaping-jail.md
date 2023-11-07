---
description: >-
  We know the feeling of popping a shell just to discover we're inside a docker
  container or a restricted bash session.
---

# Escaping Jail

## Escaping Restricted Bash

### SSH

If we have access to a username & password we can try to force a bash session.

```shell-session
ssh user@IP -t "bash --noprofile"
ssh user@IP -t "/bin/sh"
```

### Other Resources

Here are some more great resources on escaping rBash

{% embed url="https://0xffsec.com/handbook/shells/restricted-shells/" %}
