-- Simple Pktgen Lua script
-- Launch example: pktgen ... -- -f pktgen.lua

-- Map ports to cores; must match -m "1.0,2.1" etc in CLI
local tx_port = 0
local rx_port = 1

-- Option A) Synthetic flood (rate-limited)
pktgen.set(tx_port, "count", 0)        -- unlimited
pktgen.set(tx_port, "rate", 10)        -- % of line rate
pktgen.set(tx_port, "size", 512)       -- bytes
pktgen.dstip(tx_port, "all", "192.168.10.2")
pktgen.srcip(tx_port, "all", "192.168.10.1/24")
pktgen.dstmac(tx_port, "all", "90:e2:ba:xx:xx:xx") -- set NIC MAC (or use ARP)
pktgen.set(tx_port, "burst", 32)

-- Option B) PCAP replay (uncomment to use a capture)
-- pktgen.pcap(tx_port, "your_traffic.pcap")

pktgen.clr()
pktgen.start(tx_port)

print("Pktgen started")
-- run forever; Python will kill the process after simulation_time
while true do
  pktgen.delay(1000)
end
