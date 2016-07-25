#!/usr/bin/env perl
#
# Time-stamp: <2016-07-26 18:02:49 kurt>
#
# khtpasswd - Simple dropin replacement for Apache's htpasswd
#
# Copyright (c) 2016, Kurt Kanzenbach <kurt@kmk-computers.de>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

use strict;
use warnings;
use Getopt::Long;
use IO::Prompt;
use Crypt::PasswdMD5;
use MIME::Base64;
use Digest::SHA qw(sha1);

my ($verbose, $apr1, $ssha1, $file, $user);

sub print_usage_and_die
{
    print STDERR << "EOF";
usage: $0 [options] <file> <user>
options:
  -v, --verbose: enable verbose output
  -a, --apr1   : use apr1 as hash
  -s, --ssha1  : use salted sha1 as hash
khtpasswd version 1.0 (C) Kurt Kanzenbach <kurt\@kmk-computers.de>
EOF

    exit -1;
}

sub get_args
{
    GetOptions("verbose" => \$verbose,
               "apr1"    => \$apr1,
               "ssha1"   => \$ssha1
              ) || print_usage_and_die();
    print_usage_and_die() unless @ARGV == 2;
    ($file, $user) = (shift @ARGV, shift @ARGV);

    print_usage_and_die() unless defined $file;
    print_usage_and_die() unless defined $user;
    $apr1 = 1 if (!$apr1 && !$ssha1);
    print_usage_and_die() if ($apr1 && $ssha1);

    return;
}

sub vprint
{
    my ($msg) = @_;

    chomp $msg;
    print "$msg\n" if $verbose;

    return;
}

sub kurt_err
{
    my ($msg) = @_;

    chomp $msg;
    print "ERROR: $msg\n";

    exit -1;
}

sub get_password
{
    my ($pw0, $pw1);

    $pw0 = prompt("Password: ", -e => "");
    $pw1 = prompt("Re-enter password: ", -e => "");

    kurt_err("Better not use an empty password") if (!$pw0 || $pw0 eq "");
    kurt_err("Password mismatch") unless ($pw0 eq $pw1);

    return $pw0;
}

sub hash_pw
{
    my ($pw) = @_;

    return hash_pw_apr1($pw)  if $apr1;
    return hash_pw_ssha1($pw) if $ssha1;

    return;
}

sub hash_pw_apr1
{
    my ($pw) = @_;
    my ($salt, $hash);

    $salt = gen_rnd_salt();
    $hash = apache_md5_crypt($pw, $salt);

    return $hash;
}

sub hash_pw_ssha1
{
    my ($pw) = @_;
    my ($salt, $hash);

    $salt = gen_rnd_salt();
    $hash = MIME::Base64::encode(sha1($pw . $salt) . $salt, '');

    return "{SSHA}" . $hash;
}

sub gen_rnd_salt
{
    my ($length) = @_;
    my (@chars, $salt);

    $length = 8 if !defined $length || $length <= 0;
    @chars  = ( '.', '/', '0'..'9', 'A'..'Z', 'a'..'z' );
    $salt   = "";

    srand(time ^ $$ ^ unpack "%L*", `ps axww | gzip`);
    $salt .= $chars[rand @chars] for (1..$length);

    return $salt;
}

sub update_file
{
    my ($fh, $pw, $hash, @lines, $line, $found);

    $pw    = get_password();
    $hash  = hash_pw($pw);
    $found = 0;

    # new file
    unless (-f $file) {
        vprint "File '$file' does not exist, creating it...";
        open $fh, ">", $file or kurt_err("Failed to open file '$file': $!");
        print $fh "$user:$hash\n";
        close $fh;
        return;
    }

    # update file
    open $fh, "<", $file or kurt_err("Failed to open file '$file': $!");
    while ($line = <$fh>) {
        if ($line =~ /^ \s* \Q$user\E/x) {
            vprint "Updating hash of user '$user'...";
            push @lines, "$user:$hash\n";
            $found = 1;
            next;
        }
        push @lines, $line;
    }
    close $fh;
    push @lines, "$user:$hash\n" unless $found;

    # write it back
    vprint "Writing file '$file'...";
    open $fh, ">", $file or kurt_err("Failed to open file '$file': $!");
    print $fh join "", @lines;
    close $fh;

    return;
}

get_args();
update_file();

exit 0;
