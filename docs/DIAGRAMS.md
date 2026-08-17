# mail-kit — diagrams

The mermaid sources for this repo. They live here rather than in the
README because npm renders no mermaid: on the package page a fence
like this one ships as raw DSL. GitHub and the QuxKit docs site both
draw them. The README carries an ASCII equivalent of each.

## What mail-kit owns, and the seams it hands out

```mermaid
flowchart LR
    call(["send(tenantId, {from, to, subject, …})"])

    subgraph MK["mail-kit — Apache-2.0"]
        direction TB
        dom["domains<br/>DNS checklist · verify · DKIM key"]
        msg["messages<br/>validate · idempotency · suppression filter<br/>MIME · sign · queue · retry"]
        ev["events<br/>delivered · bounced · complained …"]
        sup["suppression<br/>tenant list + global list + per-list"]
        uns["unsubscribe<br/>HMAC token · RFC 8058 one-click"]
        wh["webhooks<br/>signed · retried · replayable"]
        msg --> dom
        msg --> sup
        msg --> uns
        uns --> sup
        ev --> sup
        ev --> wh
        msg --> wh
        dom --> wh
    end

    subgraph HOST["your app"]
        db[("your database<br/>mail schema")]
        tr["MailTransport<br/>ses · smtp · memory · yours"]
        dns["DnsResolver"]
        http["fetch"]
    end

    call --> msg
    MK -->|SqlExecutor| db
    msg -->|OutboundEnvelope| tr
    tr -.->|DeliveryEvent| ev
    dom --> dns
    wh --> http

    classDef own fill:#b91c1c,stroke:#7f1d1d,color:#ffffff;
    classDef host fill:#1e293b,stroke:#0f172a,color:#e2e8f0;
    class dom,msg,ev,sup,uns,wh own;
    class db,tr,dns,http,call host;
```

## Who signs

```mermaid
flowchart TB
    add["domains.add(name)"] --> q{"transport<br/>registerDomain?"}
    q -->|"yes (SES)"| t["transport returns CNAMEs<br/>signing = transport"]
    q -->|"no (SMTP, memory)"| l["mail-kit generates RSA key<br/>seals it under config.dkimKey<br/>publishes selector._domainkey TXT<br/>signing = local"]
    t --> v["verify: DNS ✓ and transport ✓"]
    l --> v2["verify: DNS ✓"]
    v --> s["send: transport signs"]
    v2 --> s2["send: mail-kit DKIM-signs, then transport"]
    classDef a fill:#b91c1c,stroke:#7f1d1d,color:#fff
    class add,l,s2 a
```

## The life of a message

```mermaid
stateDiagram-v2
    [*] --> suppressed: every recipient suppressed
    [*] --> scheduled: scheduledAt in the future
    [*] --> queued
    scheduled --> queued: due
    scheduled --> canceled: cancel()
    queued --> canceled: cancel()
    queued --> sent: transport accepted
    queued --> queued: retryable failure (30s · 2m · 10m · 30m · 1h)
    queued --> failed: permanent failure / attempts exhausted
    sent --> delivered: event
    sent --> delayed: event (soft bounce)
    delayed --> delivered: event
    sent --> bounced: event (hard) → tenant suppression
    delivered --> bounced: event (hard)
    sent --> complained: event → global suppression
    delivered --> complained: event
    bounced --> complained: event
```

## Where mail-kit sits in the family

```mermaid
flowchart TB
    ik["identity-kit<br/>who you are"] -->|"MailSender seam"| mk["mail-kit<br/>what you send, and what came back"]
    tk["tenant-kit<br/>what you belong to"] -->|tenantId| mk
    mk -->|"sends, per tenant"| bk["billing-kit<br/>what you owe"]
    classDef a fill:#b91c1c,stroke:#7f1d1d,color:#fff
    class mk a
```
