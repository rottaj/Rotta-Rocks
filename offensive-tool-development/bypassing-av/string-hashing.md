---
description: >-
  String hashing is a useful approach for hiding strings, as strings can be used
  as signatures to help security vendors detect malicious binaries.
---

# String Hashing

{% embed url="https://github.com/vxunderground/VX-API" %}
There are many string hashing algorithms available at VX APi.
{% endembed %}

## Stack Strings

Stack strings can help evade string based detection. However, stack strings are not sufficient to hide the string from some debuggers and reverse engineering tools as they can contain plugins to detect them.\
Stack string of NtCreateUserProcess:

```
char stackString[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c'. 'e', 's', 's', '\0' };
```

## Djb2

[Djb2](https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringDjb2.cpp) works by iterating over the characters in the input string and using each one to update a running hash value according to a specific algorithm.

```c
DWORD HashStringDjb2W(_In_ LPCWSTR String)
{
	ULONG Hash = 5381;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}
```

`hash` is the current hash value, `c` is the current character in the input string, and `<<` is the bitwise left shift operator.

## JenkinsOneAtATime32Bit

[JenkinsOneAtATime32bit](https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringJenkinsOneAtATime32Bit.cpp) works by iterating over the characters of the input string and incrementally updating a running hash value according to the value of each character.

```c
UINT32 HashStringJenkinsOneAtATime32BitW(_In_ LPCWSTR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = StringLengthW(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << 10;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}
```

`hash` is the current hash value and `c` is the current character in the input string. JenkinsOneAtATime32Bit is known to produce relatively good distributions of hash values with low probability of collions between different strings.



## LoseLose

[LoseLose](https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringLoseLose.cpp) calculates the hash value of an input string by iterating over each character in the string and summing the ASCII values of each character.

```c
DWORD HashStringLoseLoseW(_In_ PWCHAR String)
{
	ULONG Hash = 0;
	INT c;

	while (c = *String++) {
		Hash += c;
		Hash *= c + INITIAL_SEED;	// update
	}

	return Hash;
}
```
