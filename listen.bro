@load ./common.bro
redef exit_only_after_terminate = T;

global base_port: count=4000 &redef;
global node_id: count=1 &redef;
function setup(node_id: count)
{
    local p = count_to_port(base_port + node_id, tcp);
    local e = fmt("bro/data/%d", node_id);
    print fmt("Listening on %s and Subscribing to event %s", p, e);

    Broker::enable();
    Broker::listen(p, "127.0.0.1");
    Broker::subscribe_to_events(e);
}

event Broker::incoming_connection_established(peer_name: string)
{
    print fmt("I am %s and I Got a connection from %s", peer_description, peer_name);
}

global scan_attacks: table[addr] of set[addr];
global scanners: set[addr];
event scan_attempt(attacker: addr, victim: addr, p: port)
{
    if (attacker in scanners)
        return;
    if (attacker !in scan_attacks)
        scan_attacks[attacker] = set();

    add scan_attacks[attacker][victim];
    if(|scan_attacks[attacker]| > 5) {
        print fmt("NOTICE: %s is port scanner", attacker);
        add scanners[attacker];
    }
}

event new_host(h: addr)
{
    if(h in known_hosts)
        return;
    add known_hosts[h];
    print fmt("Log New host: %s", h);
}

event bro_init()
{
    setup(node_id);    
}
