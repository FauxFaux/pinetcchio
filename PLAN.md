tun: ip
tap: eth

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

