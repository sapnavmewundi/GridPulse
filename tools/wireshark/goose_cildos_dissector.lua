-- goose_cildos_dissector.lua
-- Wireshark Lua Dissector for IEC 61850 GOOSE CIL-DoS Detection
--
-- Parses GOOSE frames (EtherType 0x88B8), tracks per-source state,
-- and flags Crypto-Induced Latency DoS flood patterns.
--
-- Install:
--   Copy to ~/.local/lib/wireshark/plugins/ (Linux/Mac)
--   or %APPDATA%\Wireshark\plugins\ (Windows)
--
-- Released as part of the GridPulse toolkit (MIT License)
-- https://github.com/sapnadfir-blip/gridpulse

-- Protocol declaration
local goose_cildos = Proto("goose_cildos", "GOOSE CIL-DoS Analyzer")

-- Protocol fields
local f_appid     = ProtoField.uint16("goose_cildos.appid", "APPID", base.HEX)
local f_length    = ProtoField.uint16("goose_cildos.length", "Length", base.DEC)
local f_gocbref   = ProtoField.string("goose_cildos.gocbref", "GoCB Reference")
local f_stnum     = ProtoField.uint32("goose_cildos.stnum", "State Number (stNum)")
local f_sqnum     = ProtoField.uint32("goose_cildos.sqnum", "Sequence Number (sqNum)")
local f_confrev   = ProtoField.uint32("goose_cildos.confrev", "Configuration Revision")
local f_ndsentries = ProtoField.uint32("goose_cildos.ndscom", "Number of Data Set Entries")
local f_timetolive = ProtoField.uint32("goose_cildos.ttl", "Time to Live (ms)")

local f_alert     = ProtoField.string("goose_cildos.alert", "CIL-DoS Alert")
local f_rate      = ProtoField.float("goose_cildos.rate", "Source Rate (pps)")
local f_verdict   = ProtoField.string("goose_cildos.verdict", "Verdict")

goose_cildos.fields = {
    f_appid, f_length, f_gocbref, f_stnum, f_sqnum, f_confrev,
    f_ndsentries, f_timetolive, f_alert, f_rate, f_verdict
}

-- Expert info
local ef_flood = ProtoExpert.new("goose_cildos.flood", "CIL-DoS Flood Detected",
    expert.group.SECURITY, expert.severity.ERROR)
local ef_burst = ProtoExpert.new("goose_cildos.burst", "Abnormal GOOSE Burst",
    expert.group.SECURITY, expert.severity.WARN)
local ef_stnum_regression = ProtoExpert.new("goose_cildos.stnum_regress",
    "stNum Regression (Possible Replay/Spoof)",
    expert.group.SECURITY, expert.severity.WARN)
local ef_stnum_jump = ProtoExpert.new("goose_cildos.stnum_jump",
    "stNum Large Jump (Possible State Injection)",
    expert.group.SECURITY, expert.severity.WARN)
local ef_unknown_src = ProtoExpert.new("goose_cildos.unknown_src",
    "Unknown GOOSE Source MAC",
    expert.group.SECURITY, expert.severity.NOTE)

goose_cildos.experts = {
    ef_flood, ef_burst, ef_stnum_regression, ef_stnum_jump, ef_unknown_src
}

-- Detection thresholds (configurable via preferences)
local RATE_FLOOD_THRESHOLD   = 1000   -- pps: above this = flood
local RATE_BURST_THRESHOLD   = 200    -- pps: above this = suspicious burst
local STNUM_JUMP_THRESHOLD   = 16     -- stNum jump > this = anomaly
local WINDOW_SECONDS         = 1.0    -- rate calculation window

-- Preferences
goose_cildos.prefs.flood_threshold = Pref.uint("Flood threshold (pps)",
    RATE_FLOOD_THRESHOLD, "Packets/sec above which a source is flagged as flood")
goose_cildos.prefs.burst_threshold = Pref.uint("Burst threshold (pps)",
    RATE_BURST_THRESHOLD, "Packets/sec above which a source is flagged as burst")
goose_cildos.prefs.stnum_window = Pref.uint("stNum plausibility window",
    STNUM_JUMP_THRESHOLD, "stNum jump larger than this triggers an alert")

-- Per-source tracking state
local source_state = {}
-- source_state[mac] = {
--   last_time = <epoch>,
--   pkt_count = <int>,
--   window_start = <epoch>,
--   last_stnum = <int>,
--   last_sqnum = <int>,
--   rate = <float>,
--   is_known = <bool>
-- }

-- Known MAC allowlist (user can extend via preferences or SCD import)
local known_macs = {}

-- ASN.1 BER tag parsing helpers
local function parse_ber_tag(buf, offset)
    if offset >= buf:len() then return nil, nil, offset end
    local tag = buf(offset, 1):uint()
    offset = offset + 1
    return tag, offset
end

local function parse_ber_length(buf, offset)
    if offset >= buf:len() then return 0, offset end
    local first = buf(offset, 1):uint()
    offset = offset + 1
    if first < 0x80 then
        return first, offset
    end
    local num_bytes = bit.band(first, 0x7F)
    if num_bytes == 0 or offset + num_bytes > buf:len() then
        return 0, offset
    end
    local length = 0
    for i = 0, num_bytes - 1 do
        length = length * 256 + buf(offset + i, 1):uint()
    end
    return length, offset + num_bytes
end

local function parse_ber_integer(buf, offset, len)
    if offset + len > buf:len() or len > 4 then return 0 end
    local val = 0
    for i = 0, len - 1 do
        val = val * 256 + buf(offset + i, 1):uint()
    end
    return val
end

local function parse_ber_string(buf, offset, len)
    if offset + len > buf:len() then return "" end
    return buf(offset, len):string()
end

-- Main dissector function
function goose_cildos.dissector(buffer, pinfo, tree)
    local buf_len = buffer:len()
    if buf_len < 8 then return end

    pinfo.cols.protocol = "GOOSE-CILDoS"

    local subtree = tree:add(goose_cildos, buffer(), "GOOSE CIL-DoS Analysis")

    -- Parse GOOSE header (after EtherType, which Wireshark already consumed)
    -- GOOSE PDU starts with: APPID (2) + Length (2) + Reserved1 (2) + Reserved2 (2)
    local appid = buffer(0, 2):uint()
    local pdu_length = buffer(2, 2):uint()

    subtree:add(f_appid, buffer(0, 2))
    subtree:add(f_length, buffer(2, 2))

    -- Get source MAC from Ethernet layer
    local src_mac = tostring(pinfo.dl_src)
    local dst_mac = tostring(pinfo.dl_dst)
    local pkt_time = pinfo.abs_ts

    -- Parse GOOSE PDU (ASN.1 BER encoded, starts at offset 8)
    local offset = 8
    local gocbref = ""
    local stnum = 0
    local sqnum = 0
    local confrev = 0
    local ttl = 0
    local nds = 0

    -- GOOSE PDU is wrapped in a constructed sequence (tag 0x61)
    if offset < buf_len then
        local tag
        tag, offset = parse_ber_tag(buffer, offset)
        if tag == 0x61 then
            local seq_len
            seq_len, offset = parse_ber_length(buffer, offset)

            local seq_end = offset + seq_len
            if seq_end > buf_len then seq_end = buf_len end

            while offset < seq_end do
                local field_tag
                field_tag, offset = parse_ber_tag(buffer, offset)
                if field_tag == nil then break end

                local field_len
                field_len, offset = parse_ber_length(buffer, offset)

                if field_tag == 0x80 then
                    -- gocbRef (VisibleString)
                    gocbref = parse_ber_string(buffer, offset, field_len)
                    subtree:add(f_gocbref, buffer(offset, field_len))
                elseif field_tag == 0x81 then
                    -- timeAllowedtoLive
                    ttl = parse_ber_integer(buffer, offset, field_len)
                    subtree:add(f_timetolive, buffer(offset, field_len))
                elseif field_tag == 0x83 then
                    -- stNum
                    stnum = parse_ber_integer(buffer, offset, field_len)
                    subtree:add(f_stnum, buffer(offset, field_len))
                elseif field_tag == 0x84 then
                    -- sqNum
                    sqnum = parse_ber_integer(buffer, offset, field_len)
                    subtree:add(f_sqnum, buffer(offset, field_len))
                elseif field_tag == 0x85 then
                    -- confRev
                    confrev = parse_ber_integer(buffer, offset, field_len)
                    subtree:add(f_confrev, buffer(offset, field_len))
                elseif field_tag == 0x8A then
                    -- numDatSetEntries
                    nds = parse_ber_integer(buffer, offset, field_len)
                    subtree:add(f_ndsentries, buffer(offset, field_len))
                end

                offset = offset + field_len
            end
        end
    end

    -- CIL-DoS detection logic
    local flood_threshold = goose_cildos.prefs.flood_threshold
    local burst_threshold = goose_cildos.prefs.burst_threshold
    local stnum_window = goose_cildos.prefs.stnum_window

    local state = source_state[src_mac]
    if state == nil then
        state = {
            last_time = pkt_time,
            pkt_count = 1,
            window_start = pkt_time,
            last_stnum = stnum,
            last_sqnum = sqnum,
            rate = 0,
            is_known = known_macs[src_mac] ~= nil
        }
        source_state[src_mac] = state

        if not state.is_known then
            subtree:add_proto_expert_info(ef_unknown_src,
                "First GOOSE from " .. src_mac .. " — not in known allowlist")
        end
    else
        state.pkt_count = state.pkt_count + 1
        local elapsed = pkt_time - state.window_start

        if elapsed >= WINDOW_SECONDS then
            state.rate = state.pkt_count / elapsed
            state.pkt_count = 0
            state.window_start = pkt_time
        end

        -- stNum analysis
        if stnum < state.last_stnum and state.last_stnum - stnum > 1 then
            subtree:add_proto_expert_info(ef_stnum_regression,
                string.format("stNum regression: %d → %d (Δ = %d) from %s",
                    state.last_stnum, stnum, stnum - state.last_stnum, src_mac))
            subtree:add(f_alert, buffer(0, 0),
                "STNUM_REGRESSION: possible replay or spoofing attack"):set_generated()
        end

        if stnum > state.last_stnum and (stnum - state.last_stnum) > stnum_window then
            subtree:add_proto_expert_info(ef_stnum_jump,
                string.format("stNum jump: %d → %d (Δ = %d, window = %d) from %s",
                    state.last_stnum, stnum, stnum - state.last_stnum,
                    stnum_window, src_mac))
            subtree:add(f_alert, buffer(0, 0),
                "STNUM_JUMP: possible state injection attack"):set_generated()
        end

        -- Rate-based flood detection
        if state.rate > flood_threshold then
            subtree:add_proto_expert_info(ef_flood,
                string.format("CIL-DoS FLOOD from %s: %.0f pps (threshold: %d pps)",
                    src_mac, state.rate, flood_threshold))
            subtree:add(f_alert, buffer(0, 0),
                string.format("CIL-DoS FLOOD DETECTED: %.0f pps from %s",
                    state.rate, src_mac)):set_generated()
            subtree:add(f_verdict, buffer(0, 0), "ATTACK — CIL-DoS Flood"):set_generated()
            pinfo.cols.info = string.format("[CIL-DoS FLOOD] %s → %.0f pps | stNum=%d",
                src_mac, state.rate, stnum)
        elseif state.rate > burst_threshold then
            subtree:add_proto_expert_info(ef_burst,
                string.format("Abnormal burst from %s: %.0f pps (threshold: %d pps)",
                    src_mac, state.rate, burst_threshold))
            subtree:add(f_verdict, buffer(0, 0), "SUSPICIOUS — Abnormal Burst"):set_generated()
            pinfo.cols.info = string.format("[BURST] %s → %.0f pps | stNum=%d",
                src_mac, state.rate, stnum)
        else
            subtree:add(f_verdict, buffer(0, 0), "NORMAL"):set_generated()
            pinfo.cols.info = string.format("GOOSE %s stNum=%d sqNum=%d %s",
                gocbref, stnum, sqnum, src_mac)
        end

        subtree:add(f_rate, buffer(0, 0), state.rate):set_generated()

        state.last_stnum = stnum
        state.last_sqnum = sqnum
        state.last_time = pkt_time
    end
end

-- Register for GOOSE EtherType (0x88B8)
local eth_table = DissectorTable.get("ethertype")
eth_table:add(0x88B8, goose_cildos)

-- Coloring rules hint (add to Wireshark coloring rules):
-- "goose_cildos.alert contains FLOOD" → Red background
-- "goose_cildos.alert contains BURST" → Yellow background
-- "goose_cildos.alert contains STNUM" → Orange background

-- Display filter examples:
--   goose_cildos.rate > 1000        (show only flood-rate sources)
--   goose_cildos.alert              (show only frames with alerts)
--   goose_cildos.stnum > 100        (high state numbers)
--   goose_cildos.verdict == "ATTACK — CIL-DoS Flood"
