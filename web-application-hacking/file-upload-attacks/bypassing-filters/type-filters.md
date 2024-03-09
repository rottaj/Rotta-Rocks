---
description: >-
  Modern web servers and web applications test the content of the uploaded file
  to ensure it matches the specified type.
---

# Type Filters

There are two common methods for validating the file content: _**Content-Type Header or File Content.**_





### Content-Type

We can fuzz the Content-Type header with SecLists' Content-Type Wordlist through Intruder.

We can reduce the wordlist by type if we grep what we're looking for, in this case we only want Images.

```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Miscellaneous/web/content-type.txt
cat content-type.txt | grep 'image/' > image-content-types.txt
```

We then fuzz the application through Intruder with the above wordlist.





### Upload via Content-Type Bypass & Path Traversal

_<mark style="color:green;">**Try:**</mark>_ Web servers often use the `filename` field in `multipart/form-data` requests to determine the name and location where the file should be saved.

_**Adding ../ and other path traversal commands to change location.**_

```
Content-Disposition: form-data; filename="../shell.php"
```

U_**RL Encoded:**_

```
Content-Disposition: form-data; filename="%2e%2e%2fshell.php"
```

Trying changing Content-Type to: _**Content-Type: multipart/form-data**_

_<mark style="color:red;">**NOTE:**</mark>_ A directory which user-supplied files are uploaded will likely have much stricter controls than other locations on the filesystem that are assumed to be out of reach for end users. If you can find a way to upload a script to a different directory that's not supposed to contain user-supplied files, the server may execute your script after all.



### MIME-Type

The second and more common type of file content validation is testing through the Uploaded file's MIME-Type. Multipurpose Internet Mail Extensions (MIME). Is an internet statndard that determines the type of file through it's general format and bytes structure.

We can check a files MIME Type by looking at the first bytes of it's content.

_**File Signatures**_ - [https://en.wikipedia.org/wiki/List\_of\_file\_signatures](https://en.wikipedia.org/wiki/List\_of\_file\_signatures)

_**Magic Bytes**_ - [https://opensource.apple.com/source/file/file-23/file/magic/magic.mime](https://opensource.apple.com/source/file/file-23/file/magic/magic.mime)



We can add spoof a files MIME Type to appear as a JPG file:

```
echo -ne "\xFF\xD8\xFF\xEE" > test.jpg
```



_<mark style="color:green;">**READ:**</mark>_ We can use a combination of the two methods discussed in this section, which may help us bypass some more robust content filters. For example, we can try using an `Allowed MIME type with a disallowed Content-Type`, an `Allowed MIME/Content-Type with a disallowed extension`, or a `Disallowed MIME/Content-Type with an allowed extension`, and so on. Similarly, we can attempt other combinations and permutations to try to confuse the web server, and depending on the level of code security, we may be able to bypass various filters.
