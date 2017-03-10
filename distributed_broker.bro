module Cluster;

redef datanode2manager_events += {"Notice::cluster_notice"};

export {
    global send_event_hashed: function (key: any, args: Broker::EventArgs);
}

# Figure out which data node I am
function datanode_index(): count
{
    # node is my name: datanode-0
    local parts = split_string(node, /-/);
    local id = parts[1];
    return to_count(id);
}

function get_datanode_count(): count
{
    for ( n in nodes ) {
        local nn = nodes[n];
        if(WORKER in nn$node_roles)
            return |nn$datanodes|;
    }
    Reporter::error(fmt("No data nodes?"));
    return 0;
}

@if ( local_node_type() == DATANODE )
event bro_init()
{
    Broker::enable();
    local node_id = datanode_index();
    local num = get_datanode_count();
    Reporter::info(fmt("Hello!  I am %s which is datanode %d out of %d", node, node_id, num));
    local e = fmt("bro/data/%d", node_id);
    Reporter::info(fmt("Subscribing to event %s", e));
    Broker::subscribe_to_events(e);
}
@endif

global datanode_count: count = 0;
event bro_init()
{
    datanode_count = get_datanode_count();
    local x = 0;
    while(x < datanode_count) {
        Broker::publish_topic(fmt("bro/data/%d", x));
        ++x;
    }
}

global hex_to: table[string] of count = table(
    ["0"] = 0,
    ["1"] = 1,
    ["2"] = 2,
    ["3"] = 3,
    ["4"] = 4,
    ["5"] = 5,
    ["6"] = 6,
    ["7"] = 7,
    ["8"] = 8,
    ["9"] = 9,
    ["a"] = 10,
    ["b"] = 11,
    ["c"] = 12,
    ["d"] = 13,
    ["e"] = 14,
    ["f"] = 15
);

function hex_to_count(c: string): count
{
    return hex_to[c];
}

function md5_hash_count(v: any): count
{
    local h = md5_hash(v);
    local hex_byte = h[0];
    return hex_to_count(hex_byte);
}

function send_event_hashed(key: any, args: Broker::EventArgs)
{
    local dest = md5_hash_count(key) % datanode_count;
    local queue = fmt("bro/data/%s", dest);
    #Reporter::info(fmt("Send hash(%s)=%s: %s", key, queue, args));
    Broker::send_event(queue, args);
}


event Broker::incoming_connection_established(peer_name: string)
{
    Reporter::info(fmt("I am %s and I Got a connection from %s", peer_description, peer_name));
}
