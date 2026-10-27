# PALLAS

C++ and P4 implementations of **PALLAS** and **OPT-PALLAS** for persistent flow detection.

**Paper:** PALLAS: A Data-Plane-Only Approach to Accurate Persistent Flow Detection on Programmable Switches in High-Speed Networks. IEEE ICNP 2025. [DOI](https://doi.org/10.1109/ICNP65844.2025.11192401).

## C++

Requires a C++11 compiler, make and libpcap. Add one PCAP path per line to `cpp/iptraces.txt`, then run from the repository root:

```bash
cd cpp
make
printf '64\n' | ./main_hitter
```

The input is the memory budget in KiB. Both variants run by default. To specify parameters:

```bash
./main_hitter --memory-kb 64 --rows 2 --windows 1500 \
  --gamma 0.4 --alpha 0.11 --variant both
```

Use `--variant pallas` or `--variant opt` to select one variant. Output includes precision, recall, F1, estimation error and throughput. Run `./main_hitter --help` for more options.

## P4

Requires Intel Tofino and a compatible SDE/TNA environment. Build `p4/src/pallas/pallas.p4` as program `pallas`, or `p4/src/opt-pallas/pallas_opt.p4` as `pallas_opt`, keeping the adjacent includes.

Generate the matching table script from the repository root:

```bash
cd p4
python3 scripts/generate_tables.py --variant pallas --output generated/program_pallas.py
python3 scripts/generate_tables.py --variant opt-pallas --output generated/program_opt_pallas.py
```

With the matching pipeline loaded, execute its generated script inside the SDE BFRT shell:

```python
exec(open('/absolute/path/to/generated/program_pallas.py').read())
```

Configure the experiment's ports and recirculation before replaying traffic. The parser expects IPv4 directly, the recirculation local port is 68, and the explicit post-recirculation output port is 292. Adapt these settings to your testbed.

Run the matching script in `p4/control_plane/` using the SDE Python environment with `SDE_INSTALL` set, pandas and gRPC available. Collectors connect to `localhost:50052`, read the second returned pipe value (`[1]`) and write a CSV in the current directory; adjust these assumptions for your setup.