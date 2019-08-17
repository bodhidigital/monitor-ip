<!-- README.md -->

# monitor-ip: robust, efficient, hook-driven internet and remote IP monitoring using ICMP echo-request/reply.

## Description:

IP address monitoring for GNU/Linux written in C. It allows specifying a remote
address \(IPv4 or IPv6\) to monitor with ICMP echos. <code>monitor-ip</code> can
be given a configurable ping interval, reply timeout, and maximum number of
missed pings. Whenever the number of consecutive missed \(lost or expired\) pings
exceeds the configured value, <code>monitor-ip</code> will run the supplied
command.

## Writing notify command scripts:

<code>monitor-ip</code> will run the configured *hook command* with any provided
arguments using the exec family of functions \(see
[exec\(3\)](https://linux.die.net/man/3/exec)\). This means it **will not**
interpret the provided command as a shell command. It will search the PATH if
needed.

<code>monitor-ip</code> will export the following environment variables to the
*hook command*:

* <code>MONITOR\_NOTIFY\_MISSED\_PING\_COUNT</code>: a decimal integer
  representation of the current number of consecutively missed pings.
* <code>MONITOR\_NOTIFY\_REMOTE\_ADDRESS</code>: the configured remote IP
  address \(IPv4 or IPv6\) as formatted by
  [inet\_ntop\(3\)](https://linux.die.net/man/3/inet_ntop).

Treat any other environment variables prefixed by <code>MONITOR\_NOTIFY\_</code>
as reserved for future releases of <code>monitor-ip</code>.

## Building and installing:

* Ensure a recent version of glibc, glib-2.0, and pkgconf are installed.
* Run <code>make</code> or <code>make debug</code> to generate a binary with
  debugging symbols. The resulting executable will be named
  <code>monitor-ip</code>
* There is no install make target. Simply copy the executable to
  wherever you need it: it has not dependant files as part of this build.

## Gotchas:

* <code>monitor-ip</code> **DOES NOT** attempt to resolve DNS names, please
  provide an plain IP address. If you need to extend it to support DNS names,
  I recommend you attempt to script a solution using
  [dig\(1\)](https://linux.die.net/man/1/dig) or
  [host\(1\)](https://linux.die.net/man/1/host).
* By default, <code>monitor-ip</code> attempts to parse the provided address as
  an IPv4 address. To use IPv6, add the <code>-6</code> flag.
* Yes, you do need to run as root \(use <code>sudo</code>\). You can also use
  <code>setcap</code> to give the executable <code>cap\_net\_raw</code>, which
  is why you can use the ping command as a non-root user.
* By default, <code>monitor-ip</code> will block the main loop until the *hook
  command* exits. As a result, it must also clear the list of echos waiting for
  a reply. It will not however reset the count of consecutively missed pings by
  default, which means if the status condition remains, it will execute the
  *hook command* again after just one *interval*. Both of these behaviors are
  configurable.

## Help:

<pre><code>USAGE: monitor-ip [OPTIONS] &lt;address&gt; [&lt;hook command&gt; [&lt;arg&gt; [...]]

Send pings (echo requests) to &lt;address&gt;, excessive missed pongs (echo response)
results in &lt;hook command&gt; being run with provided arguments, if it is set.

OPTIONS:
    -h --help                   Print this message.
    -v --verbose                Be verbose (may be specified multiple times).
    -q --quiet                  Be less verbose (may be specified multiple times).
    -4 --ipv4                   Interpret &lt;address&gt; as an IPv4 address.
                                (default)
    -6 --ipv6                   Interpret &lt;address&gt; as an IPv6 address.
    -t --ttl &lt;ttl&gt;              Use &lt;ttl&gt; as IP(v6) TTL/Hop-Limit. (default: 64)
    -s --message-size &lt;size&gt;    Use &lt;size&gt; as ICMP message data size.
                                (default: 56)
    -i --interval &lt;interval&gt;    Use &lt;interval&gt; (may be decimal) as ping
                                interval in seconds. (default: 1.0)
    -W --expiration &lt;expire&gt;    Use &lt;expire&gt; (may be decimal) as ping expiration
                                time in seconds. (default: 1.99)
    -m --missed-max &lt;missed&gt;    Use &lt;missed&gt; as number of missed pongs
                                exceeding which triggers the &lt;hook command&gt;.
                                (default: 10)
    -b --notify-block           Block until &lt;hook command&gt; exits. (default)
    -B --no-notify-block        Don't block until &lt;hook command&gt; exits. May
                                result in multiple &lt;hook command&gt;s executing
                                simultaneously.
    -r --reset                  Reset missed ping count after successful run of
                                notify command. Only valid with --notify-block.
</code></pre>

## Contributors:

A special thanks to:

* Isabelle Erin Cowan-Bergman &lt;izzi\(åt\)izzette\(dòt\)com&gt; \(main
  author\) and her coworkers at Bodhi Digital for supporting this and other
  endeavors.

## Usage and licensing:

<pre><code>This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to &lt;http://unlicense.org&gt;
</code></pre>
