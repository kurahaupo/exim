#!/usr/bin/env perl

use 5.020;
use strict;
use warnings;

use File::Find;

my @dirs = grep { m{^/} && -d } split(/:/, $ENV{PATH}), qw(
  /bin
  /usr/bin
  /usr/sbin
  /usr/lib
  /usr/libexec
  /usr/local/bin
  /usr/local/sbin
  /usr/local
  /opt
);


my %k = map { ( $_ => 1 ) } @ARGV;

my %path;
find( {
        no_chdir => 1,
        wanted => sub {
                    my $p = $_;
                    my $r = $p =~ s{.*/}{}r;
                    $k{$r} && stat($p) && -f -x _
                    or return;
                    $path{$r} = $p;
                },
      },
    @dirs
);

-d $_ or mkdir $_ or die "$_: $!"
    for 'bin.sys';

foreach my $tool (keys %path) {
    next if ! exists $path{$tool};
    print "$tool $path{$tool}\n";

    my $bst = "bin.sys/$tool";

    unlink $bst;
    symlink $path{$tool}, $bst
      or warn "$bst -> $path{$tool}: $!\n";
}
