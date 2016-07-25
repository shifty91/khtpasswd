# Khtpasswd #

## About ##

Khtpasswd is a simple tool to generate or update .htpasswd files. It does more
or less the same job as htpasswd from Apache's webserver. However, if you don't
use Apache you won't have that tool installed. Thus, you can simply use this
tool for generating or updating your .htpasswd file for your webserver
(e.g. Nginx).

This tool is written in Perl and needs the following Perl modules:

  - IO::Prompt
  - Crypt::PasswdMD5
  - MIME::Base64
  - Digest::SHA

## Usage ##

    usage: khtpasswd.pl [options] <file> <user>
    options:
      -v, --verbose: enable verbose output
      -a, --apr1   : use apr1 as hash
      -s, --ssha1  : use salted sha1 as hash
    khtpasswd version 1.0 (C) Kurt Kanzenbach <kurt@kmk-computers.de>

Example: Add/Update password for user 'kurt'

    $ ./khtpasswd.pl -v .htpasswd kurt
    Password:
    Re-enter password:
    Updating hash of user 'kurt'...
    Writing file '.htpasswd'...

## Author ##

(C) Kurt Kanzenbach 2016 <kurt@kmk-computers.de>

## License ##

BSD 2-clause
