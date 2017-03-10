@load ./common.bro
redef exit_only_after_terminate = T;

global base_port: count=4000 &redef;
function make_conn(node_id: count)
{
    local p = count_to_port(base_port + node_id, tcp);
    print fmt("Connecting to localhost on %s", p);

    Broker::enable();
    Broker::connect("127.0.0.1", p, 1secs);
    Broker::publish_topic(fmt("bro/data/%d", node_id));
}

event Broker::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string)
{
    print fmt("I am %s and I got a connection to %s", peer_description, peer_name);
}


function check_new_host(h: addr)
{
    if(h in known_hosts)
        return;
    #this could be a bloom filter on the sending side
    add known_hosts[h];
    local args = Broker::event_args(new_host, h);
    send_event_hashed(h, args);
}

function send_scan_attempt()
{
    local a = random_src();
    local v = random_dst();
    local args = Broker::event_args(scan_attempt, a, v, 22/tcp);
    send_event_hashed(a, args);
}

event go()
{
    send_scan_attempt();
    check_new_host(random_dst(32));
    schedule 201msecs {go() };
}

event bro_init()
{
    local n = 0;
    while(n < node_count)
        make_conn(++n);
    schedule 1secs {go() };
}
