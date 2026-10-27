redef enum Notice::Type += { Nmap_SYN_Scan, Nmap_Connect_Scan, Nmap_UDP_Scan };

# thresholds (distinct ports per source inside the time window)
const thr_sS: count = 5;
const thr_sT: count = 5;
const thr_sU: count = 20;

# ports seen per (scan, source). Entries expire after 5 minutes
global ports_seen: table[string] of set[port] &create_expire=5min;
# notices already raised per scan type
global prev_notices: table[string] of count &default=0;

function record_hit(scan: string, nt: Notice::Type, thr: count, c: connection)
    {
    local key = fmt("%s|%s", scan, c$id$orig_h);

    if ( key !in ports_seen )
        ports_seen[key] = set();
    add ports_seen[key][c$id$resp_p];

    if ( |ports_seen[key]| >= thr )
        {
        NOTICE([$note=nt, $conn=c, $suppress_for=0secs,
                $msg=fmt("%s from %s: %d distinct ports. Previous notices for this scan: %d",
                         scan, c$id$orig_h, |ports_seen[key]|, prev_notices[scan])]);
        ++prev_notices[scan];
        delete ports_seen[key];
        }
    }

event connection_state_remove(c: connection)
    {
    if ( ! c?$conn || ! c$conn?$history )
        return;

    local h = c$conn$history;

    if ( c$conn$proto == tcp )
        {
        if ( h == "ShR" )
            record_hit("sS", Nmap_SYN_Scan, thr_sS, c);
        else if ( h == "ShAR" )
            record_hit("sT", Nmap_Connect_Scan, thr_sT, c);
        }
    else if ( c$conn$proto == udp && c$conn$conn_state == "S0" )
        record_hit("sU", Nmap_UDP_Scan, thr_sU, c);
    }
