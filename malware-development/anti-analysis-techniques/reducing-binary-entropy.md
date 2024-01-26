# Reducing Binary Entropy

## Introduction

Entry is the amount of randomness within a data set. As randomness increases, so does entropy. There are many type of entropy. In cybersecurity, we're focused on Shannon's entropy.

The image shows how to utilize entropy while threat hunting.

<figure><img src="../../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://practicalsecurityanalytics.com/file-entropy/" %}

## Measuring Entropy

Several tools can determine the entropy of a given file such as [pestudio](https://www.winitor.com/download) and [Sigcheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck).

We can use SciPy's [`scipy.stats.entropy`](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.entropy.html) combined with matplotlib to create a visual of entropy.

```python
def calc_entropy(buffer):
    if isinstance(buffer, str):
        buffer = buffer.encode()
    entropy = 0
    for x in range(256):
        p = (float(buffer.count(bytes([x])))) / len(buffer)
        if p > 0:
            entropy += - p * math.log(p, 2)
    return entropy
```



## Choosing an Encryption Algorithm

When picking an encryption, encoding, or any other obfuscation algorithm. It's important to keep entropy in mind, that includes choosing the corrent algorithm but one that isn't too weak.

Another effective method to keeping entropy low is using the obfuscation algorithms.

<mark style="color:yellow;">**IPv4fuscation, IPv6fuscation, Macfuscation, and UUIDfuscation**</mark>** instead of using encryption algorithms**



## Inserting English Strings

Another method we can use to reduce entropy is inserting english strings into the final implementation.  <mark style="color:yellow;">**It's recommended to use either all lower case or all upper case strings**</mark>** to reduce the number of possibilities for every byte.**



## Padding by Bytes

An easy way to reduce entropy is to pad the payloads ciphertext with the same byte repeatedly. Here is a MsfVenom payload before and after appending it with 285 bytes of **`0xEA.`**

drastically dropping entropy from `5.88325` to `3.77597.`

<figure><img src="../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

## CRT Library Independant

The CRT, or C Runtime Library, is a standard interface for the C programming language. The CRT contains a collection of functions & macros. These functions are meant for managing memory, opening and manipulating files, etc. (memcpy, fopen, strcpy).

<mark style="color:yellow;">**Removing CRT can drastically reduce the entropy of the final implementation.**</mark>

<figure><img src="../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>



## Tool - EntropyReducer&#x20;

It's also possible to reduce a payload's entropy using [EntropyReducer](https://github.com/Maldev-Academy/EntropyReducer), a tool developed by the MalDev Academy team.&#x20;

EntropyReducer uses a custom algorithm that utilizes [linked lists](https://www.learn-c.org/en/Linked\_lists) to insert [null bytes](https://github.com/Maldev-Academy/EntropyReducer/blob/main/EntropyReducer/Common.h#L14) between each [BUFF\_SIZE](https://github.com/Maldev-Academy/EntropyReducer/blob/main/EntropyReducer/Common.h#L13) byte chunk of the payload.
