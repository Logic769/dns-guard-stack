import struct

def dnssec_failure(wire, code=6):
    """Attach an explicit local-validator EDE to an existing SERVFAIL fixture."""
    h=list(struct.unpack("!HHHHHH",wire[:12]))
    h[5]+=1
    return (struct.pack("!HHHHHH",*h)+wire[12:]+b"\0"+
            struct.pack("!HHIH",41,1232,0x8000,6)+struct.pack("!HHH",15,2,code))
