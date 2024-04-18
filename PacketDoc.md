# There and back again, a packets tale.

An explanation on the complete path of the packet from entering to the exit of the kernel extension.

## Entry

The packet entry point depends on the packet and the internal windows filter state:   

- First packet of outbound connection -> AleAuthConnect Layer
- First packet of inbound connection -> InboundIppacket Layer
- Rest of packets for a connection -> OutboundIppacket, InboundIppacket Layer respectively. 

### ALE layer
The ALE layer is going to make only one decision for a connection base on the first packet it sees.
For outgoing connections this logic fallows:
  - Packet enters
  - If Packet is not TCP/UDP forward to packet layer
  - Check if connection is in cache
    - In cache
      - Block/Drop verdict -> backed ends here (packet layer will not see it)
      - Allow verdict -> continue to packet layer
      - Undecided -> Save packet and absorb, Send an event and wait for Portmaster decision. (packet layer will not see it for now)
    - Not in cache
      1. Save packet and absorb.
      2. Send an event to Portmaster. 
      2. Create a cache entry.
      3. Wait for Portmasters decision.

For incoming connections the logic is the same with the exception of that the packet first comes to the packet layer.
The packet layer will see that there is no cache entry and will just allow the packet to continue and go to the ALE layer.

Fallowing specifics apply to the ALE layer:  
1. ALE is controlling connect/accept functions of a TCP socket creation.
  - This is true only if `reauthorize` flag is `false`. That means that the processed packet is the first packet of a connection.
  - If `reauthorize` is `true` there is no way to control the connect/accept function. If blocked on that stage the connection will timeout.
  - Payload is not present connection is Outgoing and reauthorize is `false` for TCP. 
2. If packet payload is present it is from the transport layer.
3. ALE filter will hold a state for all active connections:
  - Decision on a packet will be saved and applied to every other packet on the same connection while the filter is active.
  - Connections that where created before the filter was created will appears as reauthorize.
  - The decision for a new connection can be pended. Blocking of a pended connection will result into instant block. (not a timeout which is the alternative)
