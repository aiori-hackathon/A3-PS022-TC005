# Segfault — Pseudocode

Pseudocode for Segfault's datapath, as required by PS-022. Two eBPF programs run in the
kernel: an **XDP** program on ingress that admits, drops or slips each packet, and a
**TC** program on egress that observes the server's replies and learns who is real.

## 1. XDP ingress — admission

```
function on_ingress(packet):
    p = bounded_parse(packet)              # verifier-proven, fixed loop bounds
    if p.kind == NON_DNS:   return PASS
    if p.kind == TCP_53:    return PASS    # TCP already proves a return path
    if p.kind == FRAGMENT:  return PASS
    if p.kind == MALFORMED: return reject(p, DROP_MALFORMED, slippable=false)

    cfg = config();  now = ktime_ns()

    if p.src in allow_list: return PASS
    if p.src in deny_list:  return reject(p, DROP_DENY, slippable=false)

    cost = cost_of(cfg, p)                 # see §4
    tier = T0

    # --- proof of a real return path promotes to T2 (see §5) ---
    if cookie_valid(p):
        t2[p.src] = now + cfg.t2_ttl
        return PASS                        # proven: admit, bypass all limits

    if p.src in t2 and t2[p.src] > now:
        tier = T2
    else if p.src in t1:
        tier = T1
        if t1[p.src].banned_until > now: return reject(p, DROP_BANNED, slippable=false)

    # --- T0 heavy-hitter shedding, no per-source state (see §3) ---
    if tier == T0:
        est = count_min_estimate(p.src)
        if cfg.mode == CALM:
            maybe_promote_to_T1(p, est);  return PASS
        if est > cfg.t0_heavy:
            return reject(p, DROP_HEAVY, slippable=true)

    if cfg.mode == CALM: return PASS

    # --- per-source bucket (T1) ---
    if tier == T1:
        if not gcra_admit(t1[p.src].tat, now, cost * cfg.src_ns, cfg.src_burst):
            t1[p.src].strikes += 1
            if t1[p.src].strikes >= cfg.strikes_ban:
                t1[p.src].banned_until = now + cfg.ban_ns
            return reject(p, DROP_SOURCE, slippable=true)

    # --- per-prefix bucket (/24 or /64); bypassed for T2 ---
    if tier != T2 and cfg.pfx_ns > 0:
        if not gcra_admit(pfx[prefix(p.src)], now, cost * cfg.pfx_ns, cfg.pfx_burst):
            refund(source_bucket)          # don't double-charge
            return reject(p, DROP_PREFIX, slippable=true)

    # --- global per-tier pool ---
    if not gcra_admit(pool[tier], now, cost * cfg.pool_ns[tier], cfg.pool_burst[tier]):
        refund(source_bucket); refund(prefix_bucket)
        return reject(p, DROP_POOL, slippable=true)

    return PASS
```

## 2. reject() — drop or bounded slip (see §6)

```
function reject(p, reason, slippable):
    count(reason)
    if cfg.shadow: return PASS                     # shadow mode: log only, drop nothing
    if slippable and cfg.slip_k > 0:
        slip_ctr += 1
        if slip_ctr >= cfg.slip_k:
            slip_ctr = 0
            if send_truncated_reply(p) == OK:      # XDP_TX, truncated (TC=1)
                return TX
    return DROP
```

## 3. Count-Min sketch — T0 estimate in fixed memory

$$\hat{c}(x) = \min_{1 \le j \le d} C[j,\, h_j(x)]$$

The estimate never underflows and overshoots by at most $\varepsilon N$ with probability
$1-\delta$, using $d = \lceil \ln(1/\delta) \rceil$ hash rows of $w = \lceil e/\varepsilon \rceil$
counters each. Heavy hitters are shed before any per-source state is created.

## 4. Cost weighting

$$\text{cost}(q) = w_{\text{type}} \cdot w_{\text{zone}}(q)$$

`w_zone` is raised for zones showing a high NXDOMAIN ratio (water-torture targets), so
repeated random-subdomain queries are repriced upward automatically.

## 5. GCRA token bucket — leaky bucket, no timers

```
function gcra_admit(tat, now, increment, burst):   # tat = theoretical arrival time
    if now + burst >= tat:
        tat = max(tat, now) + increment            # lock-free CAS update
        return true
    return false
```

Admit iff $t + \tau \ge \text{TAT}$, then $\text{TAT} \leftarrow \max(\text{TAT}, t) + \text{cost}(q)\cdot I$.

## 6. Bounded slip — reflection control

A truncated reply is sent on only every $k$-th drop, so the reflection ratio is bounded:

$$R_{\text{refl}} \le \frac{1}{k}$$

This bounds amplification as the brief requires; it does not eliminate it.

## 7. TC egress — observer (never blocks)

```
function on_egress(packet):
    p = bounded_parse(packet)
    if p.kind == TCP_53 and p.has_payload:
        t2[p.dst] = now + cfg.t2_ttl               # TCP response proves the client -> T2
        return OK
    if p.kind == DNS_RESPONSE:
        count_response()
        if p.rcode == NXDOMAIN: zone_stats[p.zone].nx += 1
    return OK
```

## 8. Adaptive controller (userspace)

```
loop every tick:
    drop_fraction = recent_drops / recent_queries
    if drop_fraction < low  and mode > CALM:  mode = relax(mode)    # hysteresis
    if drop_fraction > high and mode < SIEGE: mode = tighten(mode)
    write_config(mode)                                              # CALM -> GUARD -> SIEGE
```

Proof — a valid RFC 9018 cookie (a SipHash-2-4 keyed MAC) or a completed TCP exchange —
is the one thing an off-path spoofer cannot forge, which is why admission is tied to it
rather than to a rate the attacker controls.
