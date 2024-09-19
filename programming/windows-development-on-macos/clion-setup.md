# CLion Setup



## x86\_x64 Development on ARM

All my development is done in a Windows VM w/ CLion. I then upload my binaries to a Windows host that I RDP into.

Here are my CLion configurations for building to x86\_x64.&#x20;

<figure><img src="../../.gitbook/assets/Screenshot 2024-09-11 at 3.16.10 PM.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/Screenshot 2024-09-11 at 3.18.09 PM.png" alt=""><figcaption></figcaption></figure>



## Deploying to remote host

I like to deploy my builds to my home lab and can do so easily with CMake and a quick batch script.

### Batch Script

```batch
@echo off
net use \\DEVBOX\NetworkShare\ <password> /user:<user>
copy C:\Users\dev\CLionProjects\Beacond\release\Beacond.exe \\DEVBOX\NetworkShare\
```

### Update CMakeLists.txt

Add the following to your CMakeLists.txt

```cmake
add_custom_command(
        TARGET Beacond
        POST_BUILD
        COMMAND "C:\\DevTools\\deploy.bat"
        COMMENT "Running deploy.bat"
)
```



### Update CMake Build Profile (optional)

We can optionally add this functionality when we run the program in Clion (shift+fn+10)

<figure><img src="../../.gitbook/assets/Screenshot 2024-09-18 at 10.26.31 PM.png" alt=""><figcaption></figcaption></figure>

