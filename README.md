# mosdns

本仓库是 [IrineSistiana/mosdns](https://github.com/IrineSistiana/mosdns) 的 fork。

功能概述、配置方式、教程等，详见: [wiki](https://irine-sistiana.gitbook.io/mosdns-wiki/)

下载预编译文件、更新日志，详见: [release](https://github.com/IrineSistiana/mosdns/releases)

docker 镜像: [docker hub](https://hub.docker.com/r/irinesistiana/mosdns)

## Fork 变更

这个 fork 在上游 mosdns 的基础上增加了两个可执行插件，主要用于改写部分 CDN 解析结果：

- `fastly`: 识别 Fastly 相关的 CNAME 或地址段响应，将命中的 A/AAAA/CNAME 查询结果改写到一个偏好的 Fastly 域名。默认偏好域名是 `fastly.182682.xyz.`，默认匹配 `fastly.net.`、`fastlylb.net.` 以及常见 Fastly IPv4/IPv6 地址段。
- `cloudflare_ech`: 识别 Cloudflare 和 Meta 相关的 A/AAAA/HTTPS 响应。对 Cloudflare 地址响应可替换为偏好的 IP；对 HTTPS 记录可补写或替换 ALPN 和 ECHConfig。Cloudflare ECH 可从配置提供，也可通过 `cloudflare-ech.com.` 查询并缓存。

插件已加入默认启用列表，可直接在 `sequence` 中使用。

### `fastly` 示例

```yaml
plugins:
  - tag: prefer_fastly
    type: fastly
    args:
      preferred_domain: fastly.182682.xyz.
      cname_ttl: 60

  - tag: main_sequence
    type: sequence
    args:
      exec:
        - prefer_fastly
        - forward
```

也可以使用 quick setup：

```yaml
plugins:
  - tag: main_sequence
    type: sequence
    args:
      exec:
        - fastly fastly.182682.xyz.
        - forward
```

### `cloudflare_ech` 示例

```yaml
plugins:
  - tag: cf_ech
    type: cloudflare_ech
    args:
      ipv4:
        - 1.1.1.1
      ipv6:
        - 2606:4700:4700::1111
      preferred_ip_domain: cf.090227.xyz
      refresh_interval: 600
      cloudflare_ech_domain: cloudflare-ech.com.
      cloudflare_alpn:
        - h3
        - h2
      meta_alpn:
        - h3
        - h2

  - tag: main_sequence
    type: sequence
    args:
      exec:
        - cf_ech
        - forward
```
