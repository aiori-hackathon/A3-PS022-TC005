# Benchmark results

Raw per-run output from `lab/bench/run.sh`, stored under `raw/`. Each file corresponds to
one **(baseline × scenario)** run and contains the RESULT line (queries completed / p99
latency) together with the datapath counter snapshot for that run.

- **baselines:** `none`, `nftables`, `nft-netdev`, `fixed-xdp`, `segfault`
- **scenarios:** `single`, `distributed`, `pulse`, `adaptive`, `prefix-spoof`, `water-torture`

The summary tables in `docs/benchmarks.md` report the **median** over the repeats for each
cell. See that file for the metric definitions, the result matrix, and the integrity
checks. Regenerate everything with:

```bash
sudo SERVER_IP=10.53.0.10 PPS=200000 bash lab/bench/run.sh
```
