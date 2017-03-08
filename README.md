Bro example that shows how distributed broker events could work

to demo, run in separate shells 2+ listeners, and then one or more senders.

    # two receivers
    bro node_id=1 listen.bro
    bro node_id=2 listen.bro
    #one or more listener
    bro node_count=2 send.bro # one or more copies of this

To scale it up, this will work too

    # four receivers
    bro node_id=1 listen.bro
    bro node_id=2 listen.bro
    bro node_id=3 listen.bro
    bro node_id=4 listen.bro
    bro node_count=4 send.bro
    bro node_count=4 send.bro
    bro node_count=4 send.bro
    bro node_count=4 send.bro
