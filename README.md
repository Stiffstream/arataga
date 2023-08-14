# What is arataga?

*arataga* is a working prototype of socks5+http/1.1 proxy server. arataga was developed by [stiffstream](https://stiffstream.com) for a customer who then abandoned the project. So as not to throw away the result, the source code of arataga was opened under the GNU Affero GPL v3.

arataga was created under the following conditions:

* 5 to 10 thousand entry points on a single proxy server were required. Each entry point (called ACL) is a unique combination of IPv4 address and TCP/IP port;
* the proxy server had to be accessible to tens of thousands of users;
* tens of thousands (40,000 or more) of simultaneous connections had to be handled;
* frequent client connections/disconnections were required (at the rate of 1,000 new connections per second and above);
* bandwidth had to be limited for client connections (for example, all client connections per ACL could not consume more than 10MiB/s in total);
* was required to limit bandwidth for clients based on the target domain (for example, for a client there is a limit of 10MiB/s, but when accessing instagram.com this limit is reduced to 5MiB/s);
* the configuration and lists of users who are allowed to work with arataga must be received on a special HTTP entry point. Copies of the current configuration and user list should be stored locally and used during restarts.

At the moment arataga is in a working prototype state. This means that almost all of its functionality works and has been tested inside stiffstream within the resources we have available. From the originally planned features was not implemented only asynchronous work with DNS-servers, a list of which should have been specified in the configuration file.

Serious testing in conditions close to the "combat" was not carried out, because within stiffstream there were no resources to create a suitable test bed, which could open a sufficient number of IP-addresses and create a test traffic on 60-80 thousand simultaneous connections, and the customer, who had the necessary resources lost interest in the project without explanation.

# Why was arataga open-source?

There are two main reasons to open the sources of arataga.

The first reason: arataga is a great project to show what real code based on [SObjectizer](https://github.com/Stiffstream/sobjectizer) and [RESTinio](https://github.com/Stiffstream/restinio) looks like.

If anyone has heard of SObjectizer and/or RESTinio and wants to see any of these libraries in a real project, arataga is great for that purpose. arataga was developed with production use in mind, it's not a simple 100 line HelloWorld.

So if you want to get an idea of what code using SObjectizer and/or RESTinio might look like, you can take a look at the arataga sources.

Second reason: it's a shame to throw away a product that our hard work was put into. Maybe results of our work will be useful for somebody.

So if you are interested in the possibilities of arataga but something is missing, you can [contact us](mailto:info@stiffstream.com) and discuss the modification of arataga for your conditions, goals and objectives. Including in the form of a closed fork.

Well, we can also mention the third reason, although it's not the main one: we ourselves consider arataga to be an excellent testing ground for testing new versions of SObjectizer and RESTinio in real-life conditions.

# How to get and try?

You will need a compiler with more or less normal C++17 support (filesystem should be available "out of the box"), such as GCC-8 or newer.

A GNU/Linux operating system. We had no requirements to support other operating systems. We tested it on Ubuntu 18.04 and 20.04.

## The usage of demo Dockerfile

The easiest way is to use demo Dockerfile:

```sh
git clone https://github.com/Stiffstream/arataga
cd arataga
docker build -t arataga-ubuntu1804-gcc10 -f arataga-ubuntu1804-gcc10-local.Dockerfile .
docker run -p 5001:5001 -p 8088:8088 arataga-ubuntu1804-gcc10
```

The following commands can be used for checking:

```sh
# Try to load a Web-page via proxy.
curl -x localhost:5001 -U user:12345 https://ya.ru
```

or

```sh
# Access admin HTTP-entry to get list of ACLs.
curl -H "arataga-admin-token: arataga-admin-entry" http://localhost:8088/acls

# Access admin HTTP-entry to get the current stats.
curl -H "arataga-admin-token: arataga-admin-entry" http://localhost:8088/stats
```

## How to get and build manually?

This repository contains only the source code of the examples themselves. The source code for the dependencies (i.e., asio, fmtlib, sobjectizer, doctest, restinio, etc.) is not included in the repository. There are two ways to get the examples with their required dependencies.

### Download of a full archive

The Releases section contains the archives which contain all the source code: both arataga and all the dependencies. Therefore, the easiest way is to download the corresponding archive from Releases, unzip it, go into arataga and start compiling the examples.

### The usage of MxxRu::externals

In this case you need Ruby + MxxRu + various tools that Linux developers have out of the box (like git, tar, unzip, etc.). In this case:

* Install Ruby and RubyGems (usually RubyGems comes with Ruby, but somewhere you may have to install it separately).
* Install MxxRu: `gem install Mxx_ru`.
* Make a git clone: `git clone https://github.com/Stiffstream/arataga`.
* Go to the desired subdirectory: `cd arataga`.
* Run the command `mxxruexternals`.
* Wait for all dependencies to pick up.

After that, we can move on to the building.

### Building via MxxRu

At the moment only builds via MxxRu are supported. So before building you will need to install Ruby and RubyGems (usually RubyGems comes with Ruby, but somewhere you may have to install separately), then install MxxRu: `gem install Mxx_ru`.

To compile, go to the directory arataga and run the command `ruby build.rb`. The result of the build will be in `target/release/bin`.

If you want to run unit tests, run the command `ruby build_tests.rb`.

### Preparing to a launch

#### A path for holding local copies of the config

arataga will need a directory for storing local copies of the configuration and user list. This directory must be readable and writable for arataga.

The easiest way to create this directory is directly inside the arataga directory, e.g:

```
cd arataga
mkdir locals
```

#### An initial config file

You will need an initial configuration file, which will describe the basic parameters of arataga operation and the list of access points. For example, a file of the form:

```
log_level info

bandlim.in 50MiBps
bandlim.out 50MiBps

acl.max.conn 500
acl.io.chunk_size 4kib

acl auto, port=3000, in_ip=127.0.0.1, out_ip=192.168.1.1
acl auto, port=3001, in_ip=192.168.1.1, out_ip=192.168.1.1
```

#### An initial user-list file

You will need an initial file with a list of users allowed to access the proxy. For example, a file of the form:

```
127.0.0.1 3000 user 12345 = 0 0 0 1
192.168.1.1 3001 192.168.1.1 = 10MiBps 5MiBps 0 2
```

### The launch and handling via admin HTTP-entry

arataga can be launched in a console by a command:

```
./target/release/bin/arataga --no-daemonize \
  --admin-http-ip=127.0.0.1 --admin-http-port=8088 \
  --admin-http-token=54321 \
  --local-config-path=locals \
  --log-target=stdout \
  --log-level=debug
```

Then the arataga can be stopped by Ctrl+C.

Once arataga is started a new config and/or user-list can be passed to it via the following commands:

```
curl \
  -H "arataga-admin-token: 54321" \
  -H "Content-Type: text/plain" \
  -X POST \
  --data-binary @my-config.cfg \
  http://localhost:8088/config

curl \
  -H "arataga-admin-token: 54321" \
  -H "Content-Type: text/plain" \
  -X POST \
  --data-binary @my-users.cfg \
  http://localhost:8088/users
```

Arataga will create all necessary entry points and starts to access incoming connections.

### Running and working with a local copy of configs

After successfully accepting the configuration and user list, arataga creates two files in the directory named with the `--local-config-path` command line parameter: `local-config.cfg`, which contains a copy of the configuration, and `local-user-list.cfg`, which contains a copy of the user list. These local files are used by arataga during restarts -- if the files exist, arataga tries to read them at startup and, if it succeeds, uses their contents.

So if you don't want to issue control commands via curl after starting arataga, you can do something simpler: create `local-config.cfg` and `local-user-list.cfg` files immediately. For example:

```
cp my-config.cfg locals/local-config.cfg
cp my-users.cfg locals/local-user-list.cfg
./target/release/bin/arataga --no-daemonize \
  --admin-http-ip=127.0.0.1 --admin-http-port=8088 \
  --admin-http-token=54321 \
  --local-config-path=locals \
  --log-target=stdout \
  --log-level=debug
```

# Admin HTTP-entry

arataga creates an HTTP input on startup to get new configuration and updated user lists. The IP address and TCP port of this HTTP entry is specified by the command line arguments `--admin-http-ip` and `--admin-http-port`.

All requests that go to the administrative HTTP input must contain an HTTP field (HTTP header) named `Arataga-Admin-Token` and the same value that was passed to arataga in the `--admin-http-token` command line argument. Requests without such an HTTP field will be rejected.

## POST to /config

In order to load a new configuration into arataga, a POST request to `/config` must be made. The body of the request must contain the configuration as `text/plain`. The format of the configuration is described in README_CONFIG.md.

## POST to /users

In order to upload a new list of users to arataga, a POST request to `/users` has to be made. The body of the request must contain a list of users in `text/plain` form. The format of the list of users is described in README_USER_LIST.md.

## GET on /acls

A GET request to `/acls` allows you to retrieve as text a list of existing ACLs within arataga.

## GET on /stats

A GET request to `/stats` allows you to get some statistical data in text form about what's going on inside arataga.

# The working principle

## The use of multithreading

arataga is a multithreaded application that uses the power of multicore processors to handle a large number of entry points and connections to them.

On startup, arataga creates N worker threads, which will be used to handle network connections. The value of N is either specified on the command line by the `--io-threads` parameter, or it is calculated automatically as (nCPU-2), where nCPU is the number of available CPU cores. Thus, if you run arataga on an 8-core processor without hyperthreading, N will be 6 (assuming `--io-threads` is not set).

All ACLs specified in the configuration are evenly distributed across these N worker threads. That is, if N=6 and 3000 ACLs are specified in configuration, then each worker thread will have 500 ACLs.

Each ACL inside arataga is served by a separate agent object. The agent is created for the next ACL during configuration processing and is bound to a specific worker thread. Once an ACL agent is bound to a particular thread, it will remain running on that thread until arataga completes its work or the corresponding ACL is removed from the configuration.

### Locality of domain name resolution and client authentication operations

On each worker thread, arataga runs separate instances of two special agents: dns_resolver and authentificator. That is, if arataga started on 6 worker threads, there would be 6 dns_resolver agents and 6 authenticator agents inside arataga.

Each dns_resolver+authenticator pair is bound to its own worker thread. The ACL-agents that are bound to the same work thread communicate only with this pair of agents dns_resolver+authenticator. So practically all information exchange between entities serving client connections (i.e. ACL-agents, dns_resolver, authenticator) occurs only in their common work context.

The dns_resolver agent is responsible for domain name resolution operations (i.e. defining an IP address corresponding to a domain name).

The authentificator agent stores user lists and authenticates the next connected client.

## Change of the config during the work

### Change of the ACL list

While arataga is running, a new configuration can be passed to it through the admin HTTP-entry. In this case, arataga will pick up the new settings without having to restart the entire arataga.

When arataga receives the new configuration, it compares its current ACL list with the new ACL list. Any ACL agents that have disappeared from the new list will be destroyed. For new ACLs that are in the new list but were not in the old list, new ACL-agent will be created.

If an ACL changed its type (for example, initially it supported only HTTP protocol, then it was changed to socks5 protocol), then the old ACL-agent will be removed and the new one will be created in its place. Accordingly, all connections that were served through the agent will be broken.

When updating the configuration it is possible that on some working thread more old ACL agents will be removed than on the other ones. There will be a disproportion where one thread, for example, has 100 ACL-agents on it, and the others have 250 agents each.

In this case, arataga will not redistribute the remaining old ACL-agents between the threads in order to equalize the number of ACL-agents. Therefore, if the configuration update only deletes ACLs, such imbalances will occur and will persist until arataga restarts.

If, however, in addition to deleting old ACLs during reconfiguration, new ACLs are created, then arataga will create new ACL-agents so that the new agents bind to the worker threads with the smallest number of live ACL-agents.

### Change of the user-list

While arataga is running, a new user list can be passed to it via the admin HTTP-entry. This allows user lists to be updated without restarting arataga.

If a user's limits have been changed in the updated user list (for example, the limit has been reduced from 10MiB/s to 5MiB/s), the new limits will be applied to existing and new connections only when a client makes a new connection to the arataga. If the limits have been changed for a client, but the client hasn't made any new connections, then existing connections will be served with the limits. This is a defect of the current implementation that will need to be fixed if development of the project will be resumed.

In the current version of arataga, when the user list is changed, connections made by users who are not on the new list are not forced to terminate in the current version of arataga. This means that if a user created a long-lived connection to arataga and then that user was dropped from the list, his connection will continue to live and will be serviced by arataga. 

# Additional info

The command line parameters are described in the README_CMDLINE.md file.

The format and parameters of the configuration file are described in README_CONFIG.md.

The format of the user list is described in README_USER_LIST.md.

Examples of interaction with arataga via HTTP input are described in curl_examples.md.

To ask a question or report a problem, see the Issues section.

# License

Source code of arataga is distributed under [GNU Affero GPL v3](https://www.gnu.org/licenses/agpl-3.0.txt).

