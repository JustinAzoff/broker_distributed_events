global scan_attempt: event(attacker: addr, victim: addr, p: port);
global new_host:  event(h: addr);
global known_hosts: set[addr];


function random_src(): addr
{
    local ip = fmt("10.1.%d.%d", rand(4), rand(4));
    return to_addr(ip);
}
function random_dst(max: count&default=255): addr
{
    local ip = fmt("192.168.1.%d", rand(max));
    return to_addr(ip);
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
