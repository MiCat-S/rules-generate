# rules-generate

Fork of [Yuu518/rules-generate](https://github.com/Yuu518/rules-generate), licensed under AGPL-3.0.

This fork adds a `convert` command that reads a directory containing sing-box `rule_set_site` and `rule_set_ip` source files and writes a flat six-client tree:

```text
rules/
├── surge/
├── loon/
├── shadowrocket/
├── mihomo/
├── quantumult-x/
└── sing-box/
```

Files are prefixed with `site-` or `ip-` to avoid collisions while keeping every client directory flat. Existing non-prefixed files are preserved.

```bash
go run . convert \
  --datapath ./sing-box-rules \
  --output ./rules \
  --quantumult-policy proxy \
  --report ./conversion-report.json
```

Changes in this fork were made in August 2026 with permission from the upstream author. The original copyright notices and [`LICENSE`](LICENSE) are retained.
