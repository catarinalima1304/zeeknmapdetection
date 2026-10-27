@load base/frameworks/notice

redef enum Notice::Type += { Nmap_SYN_Scan, Nmap_Connect_Scan, Nmap_Version_Scan,
                             Nmap_UDP_Scan, Nmap_IPProto_Scan };

# thresholds
const thr_sS: count = 5;       # distinct open ports found by a SYN scan
const thr_sT: count = 5;       # distinct open ports found by a connect scan
const thr_sV: count = 3;       # distinct ports that received probe data
const thr_sU: count = 20;      # distinct UDP ports without reply
const thr_sO: count = 50;      # packets with an unknown IP protocol
const thr_sweep: count = 100;  # distinct closed ports before a source counts as scanner

global ports_seen: table[string] of set[port] &create_expire=5min;
global prev_notices: table[string] of count &default=0;
global sweep_ports: table[addr] of set[port] &create_expire=5min;
global scanners: set[addr] &create_expire=5min;
global proto_pkts: table[addr] of count &create_expire=5min &default=0;

function raise(scan: string, nt: Notice::Type, c: connection, n: count, what: string)
    {
    NOTICE([$note=nt, $conn=c, $suppress_for=0secs,
            $msg=fmt("%s from %s: %d %s. Previous notices for this scan: %d",
                     scan, c$id$orig_h, n, what, prev_notices[scan])]);
    ++prev_notices[scan];
    }

function record_hit(scan: string, nt: Notice::Type, thr: count, c: connection)
    {
    local key = fmt("%s|%s", scan, c$id$orig_h);

    if ( key !in ports_seen )
        ports_seen[key] = set();
    add ports_seen[key][c$id$resp_p];

    if ( |ports_seen[key]| >= thr )
        {
        raise(scan, nt, c, |ports_seen[key]|, "distinct ports");
        delete ports_seen[key];
        }
    }

event connection_state_remove(c: connection)
    {
    if ( ! c?$conn )
        return;

    local src = c$id$orig_h;

    # sO: Zeek keeps all packets of unknown IP protocols in one flow, so count packets
    if ( c$conn$proto == unknown_transport )
        {
        if ( c$conn?$orig_pkts )
            {
            proto_pkts[src] += c$conn$orig_pkts;
            if ( proto_pkts[src] >= thr_sO )
                {
                raise("sO", Nmap_IPProto_Scan, c, proto_pkts[src], "packets with an unknown IP protocol");
                delete proto_pkts[src];
                }
            }
        return;
        }

    if ( ! c$conn?$history )
        return;

    local h = c$conn$history;

    if ( c$conn$proto == tcp )
        {
        if ( h == "Sr" )
            {
            # closed port: many distinct ones mark the source as a scanner
            if ( src !in sweep_ports )
                sweep_ports[src] = set();
            add sweep_ports[src][c$id$resp_p];
            if ( |sweep_ports[src]| >= thr_sweep )
                add scanners[src];
            }
        else if ( h == "ShR" )
            record_hit("sS", Nmap_SYN_Scan, thr_sS, c);
        else if ( h == "ShAR" )
            record_hit("sT", Nmap_Connect_Scan, thr_sT, c);
        else if ( /^ShAD/ in h && src in scanners )
            record_hit("sV/sR", Nmap_Version_Scan, thr_sV, c);
        }
    else if ( c$conn$proto == udp && c$conn$conn_state == "S0" )
        record_hit("sU", Nmap_UDP_Scan, thr_sU, c);
    }
