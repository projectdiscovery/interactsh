package storage

import "github.com/redis/go-redis/v9"

// consumerReadScript atomically:
//   - returns the unseen interaction slice for the given consumer
//   - advances the consumer's offset and last-seen timestamp
//   - evicts other consumers that have been idle for longer than evictionTTL
//   - drops the data list when no live consumer remains
//   - enforces maxBuffer, adjusting every remaining consumer's offset
//
// Hash tag {id} is embedded in every key by the Go layer, so all reads/writes
// land on the same Redis slot under Redis Cluster.
//
// KEYS[1] = data:{<id>}        (LIST)
// KEYS[2] = consumers:{<id>}   (SET)
// ARGV[1] = consumerID
// ARGV[2] = nowUnixNano        (int)
// ARGV[3] = evictionTTLNanos   (int; 0 means no idle eviction)
// ARGV[4] = maxBuffer          (int; 0 means unlimited)
// ARGV[5] = offsetKeyPrefix    ("<prefix>off:{<id>}:")
// ARGV[6] = seenKeyPrefix      ("<prefix>seen:{<id>}:")
//
// Returns: array of strings (the unseen interactions, may be empty).
var consumerReadScript = redis.NewScript(`
local data_key      = KEYS[1]
local consumers_key = KEYS[2]
local consumer      = ARGV[1]
local now           = tonumber(ARGV[2])
local eviction_ttl  = tonumber(ARGV[3])
local max_buffer    = tonumber(ARGV[4])
local off_prefix    = ARGV[5]
local seen_prefix   = ARGV[6]

local off_key  = off_prefix .. consumer
local seen_key = seen_prefix .. consumer

local offset = tonumber(redis.call("GET", off_key) or "0")
local total  = redis.call("LLEN", data_key)
if offset > total then offset = total end

local unseen = redis.call("LRANGE", data_key, offset, -1)

redis.call("SET", off_key, total)
redis.call("SET", seen_key, now)
redis.call("SADD", consumers_key, consumer)

if eviction_ttl > 0 then
    local members = redis.call("SMEMBERS", consumers_key)
    for _, cid in ipairs(members) do
        local sk = seen_prefix .. cid
        local ls = tonumber(redis.call("GET", sk) or "0")
        if ls > 0 and (now - ls) > eviction_ttl then
            redis.call("SREM", consumers_key, cid)
            redis.call("DEL", sk)
            redis.call("DEL", off_prefix .. cid)
        end
    end
end

local live = redis.call("SCARD", consumers_key)
if live == 0 then
    redis.call("DEL", data_key)
    return unseen
end

if max_buffer > 0 then
    local cur_len = redis.call("LLEN", data_key)
    if cur_len > max_buffer then
        local trim = cur_len - max_buffer
        redis.call("LTRIM", data_key, trim, -1)
        local members = redis.call("SMEMBERS", consumers_key)
        for _, cid in ipairs(members) do
            local ok = off_prefix .. cid
            local cur_off = tonumber(redis.call("GET", ok) or "0")
            local new_off = cur_off - trim
            if new_off < 0 then new_off = 0 end
            redis.call("SET", ok, new_off)
        end
    end
end

return unseen
`)

// removeConsumerScript drops the given consumer, evicts other stale
// consumers, then compacts the data list to the minimum offset still in use.
// When the consumer set becomes empty the data list is deleted entirely.
//
// KEYS[1] = data:{<id>}        (LIST)
// KEYS[2] = consumers:{<id>}   (SET)
// ARGV[1] = consumerID
// ARGV[2] = nowUnixNano
// ARGV[3] = evictionTTLNanos
// ARGV[4] = maxBuffer
// ARGV[5] = offsetKeyPrefix
// ARGV[6] = seenKeyPrefix
//
// Returns: integer number of entries trimmed from the data list.
var removeConsumerScript = redis.NewScript(`
local data_key      = KEYS[1]
local consumers_key = KEYS[2]
local consumer      = ARGV[1]
local now           = tonumber(ARGV[2])
local eviction_ttl  = tonumber(ARGV[3])
local max_buffer    = tonumber(ARGV[4])
local off_prefix    = ARGV[5]
local seen_prefix   = ARGV[6]

redis.call("SREM", consumers_key, consumer)
redis.call("DEL", off_prefix .. consumer)
redis.call("DEL", seen_prefix .. consumer)

if eviction_ttl > 0 then
    local members = redis.call("SMEMBERS", consumers_key)
    for _, cid in ipairs(members) do
        local sk = seen_prefix .. cid
        local ls = tonumber(redis.call("GET", sk) or "0")
        if ls > 0 and (now - ls) > eviction_ttl then
            redis.call("SREM", consumers_key, cid)
            redis.call("DEL", sk)
            redis.call("DEL", off_prefix .. cid)
        end
    end
end

local live = redis.call("SCARD", consumers_key)
if live == 0 then
    redis.call("DEL", data_key)
    return 0
end

local members = redis.call("SMEMBERS", consumers_key)
local min_off = -1
for _, cid in ipairs(members) do
    local o = tonumber(redis.call("GET", off_prefix .. cid) or "0")
    if min_off < 0 or o < min_off then min_off = o end
end

local trimmed = 0
if min_off > 0 then
    redis.call("LTRIM", data_key, min_off, -1)
    for _, cid in ipairs(members) do
        local ok = off_prefix .. cid
        local cur_off = tonumber(redis.call("GET", ok) or "0")
        local new_off = cur_off - min_off
        if new_off < 0 then new_off = 0 end
        redis.call("SET", ok, new_off)
    end
    trimmed = min_off
end

if max_buffer > 0 then
    local cur_len = redis.call("LLEN", data_key)
    if cur_len > max_buffer then
        local extra = cur_len - max_buffer
        redis.call("LTRIM", data_key, extra, -1)
        for _, cid in ipairs(members) do
            local ok = off_prefix .. cid
            local cur_off = tonumber(redis.call("GET", ok) or "0")
            local new_off = cur_off - extra
            if new_off < 0 then new_off = 0 end
            redis.call("SET", ok, new_off)
        end
        trimmed = trimmed + extra
    end
end

return trimmed
`)
