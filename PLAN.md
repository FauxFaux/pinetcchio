tun: ip
tap: eth

### Net

Packets come in on tun.
 * New connection:
   * establishing connection comms
 * Existing connection:
   * store in log and ack

log[]:
  conn id: u64
  offset: u64
  len: u16
  data: u8[]

  or:
  new connection please
    conn id: u64
    type: tcp|udp|..
    dest: addr
    port: port
  connection response
    * established
    * timeout
    * refused
    * network error

both directions


log replicator:
  while there's unacked ranges:
    take the oldest range, and send it


reading the log:
  new connection:
    * store state
    * attempt to establish
    * write result to return log
  data packet:
    * send packet
    * replicate errors


### Dns

Allocate every name a different IP address,
resolve later. Hell, try and resolve now.
Does anything care? Probably a couple of things,
e.g. history of packing time into v4 dns addresses.
6to4 stuff probably breaks that anyway.

Only 16M addresses in 10.* to return. Return 60s
TTL, hope nobody does 16M lookups in a minute?
GC on 1/4th exhaustion, so we have a while to detect
people using the wrong IP?

### Icmp

If an address we don't like arrives, immediately return ICMP errors.
If any flags are wrong, can we return "fragmentation will happen"?
Different code (semantics?) in v6.
