The main purpose of this tool is to find a webshell uploaded by a hacker or a malicious internal user.

This tools use two method to find a webshell. One is to use string signatures and the other is to use a fingerprint of files.

There are three mode to find web backdoors(in other words 'webshell') using this tool.

  1. **l** mode: this mode prints the list of files which the tool will find at current option.
  1. **w** mode: this mode checks the files to find a webshell
  1. **f** mode: this mode prints the hash list and dates(ctime, mtime) to find what difference exits. Once you save fingerprints of files, you can compare the difference between old and current fingerprints.

The general usage is below.

  * Find a webshell which extension is .php on /var/httpd/htdocs(Default option is not to check specific files but to check all files. If you want check only specific files, use -e option.)
```
./bwfinder.pl -m w -t php -e -d /var/httpd/htdocs
```
  * Please refer the help of this tool if you want more detail options.

Welcome to participate in this project! I hope your kind help.

If you are Korean and you need to get more information, please refer the documentation(http://bar4mi.tistory.com/attachment/cfile29.uf@1269B1124B7B62E12A72BF.pdf).