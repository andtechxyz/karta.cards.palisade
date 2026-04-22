# Internal ALB TLS — Stage D.1

Status: **Infrastructure provisioned; activation gated on Cloudflare DNS.**

## Why

Defence-in-depth for service-to-service traffic on the `vera-internal`
ALB (`internal-vera-internal-886106335.ap-southeast-2.elb.amazonaws.com`).
PCI DSS 4.1.x doesn't strictly require TLS for VPC-internal traffic
(it's not "open/public" by PCI's definition), but encrypting every
hop reduces blast radius if a node or VPC peering ever leaks.

## Current state (post-D.1 commit)

- HTTPS:443 listener exists on the internal ALB
  (`arn:aws:elasticloadbalancing:ap-southeast-2:600743178530:listener/app/vera-internal/f607108ee78ebe20/5f7541f413313cfb`)
- Cert: existing wildcard `*.karta.cards`
  (`arn:aws:acm:ap-southeast-2:600743178530:certificate/80fd420f-0b88-46a9-9234-8f449f467644`)
- SSL policy: `ELBSecurityPolicy-TLS13-1-2-2021-06`
- Default action: 503 fixed-response (no rules matched ⇒ no service)
- Sample listener rule (priority 10):
  Host header = `rca-internal.karta.cards` → forward to `palisade-rca` TG

The existing HTTP listeners on ports 80/3002/3004/3006/3007/3010 are
**unchanged**. All inter-service URLs continue to use them. This change
is purely additive.

## Why activation is gated on Cloudflare

`karta.cards` registrar NS = Cloudflare (`becky.ns.cloudflare.com`,
`kaiser.ns.cloudflare.com`). Records added to the AWS Route 53 hosted
zone for `karta.cards` are non-authoritative and not visible on the
public internet (or via VPC resolvers, which forward to public DNS for
this domain).

To activate `<service>-internal.karta.cards`, the CNAME must be added
in **Cloudflare DNS**:

```
Type:  CNAME
Name:  rca-internal
Value: internal-vera-internal-886106335.ap-southeast-2.elb.amazonaws.com
TTL:   Auto
Proxy: DNS only (orange cloud OFF — proxying breaks ALB SNI)
```

Once propagated (Cloudflare typically <30s), VPC resources resolve the
ALB private IPs and the wildcard `*.karta.cards` cert validates.

## Per-service migration playbook

For each service that wants to talk to another over HTTPS:

1. **Decide hostname**: convention is `<service>-internal.karta.cards`
   (matches the existing rca example). Single level under `karta.cards`
   so the wildcard cert applies.

2. **Cloudflare CNAME**: add per the section above. Must be DNS-only
   (proxying off) — Cloudflare's proxy terminates TLS itself, which
   strips the host header the ALB needs for SNI/host-routing.

3. **ALB listener rule**: add a host-based rule on the HTTPS:443
   listener forwarding to the target service's TG. Pick the next free
   priority number (current sample uses 10).

   ```bash
   aws elbv2 create-rule \
     --listener-arn arn:aws:…:listener/app/vera-internal/…/5f7541f413313cfb \
     --priority <N> \
     --conditions 'Field=host-header,HostHeaderConfig={Values=[<service>-internal.karta.cards]}' \
     --actions  'Type=forward,TargetGroupArn=<service-tg-arn>' \
     --region ap-southeast-2
   ```

4. **Update consumer env**: change the calling service's
   `<DEPENDENCY>_SERVICE_URL` from
   `http://internal-vera-internal-886106335…elb.amazonaws.com:<port>`
   to `https://<service>-internal.karta.cards`. Register a new task
   def revision + force-deploy.

5. **Verify** via a one-off ECS task:
   ```bash
   aws ecs run-task --cluster vera --task-definition <consumer>:<rev> \
     --launch-type FARGATE --network-configuration '…' \
     --overrides '{"containerOverrides":[{"name":"<consumer>","command":[
       "node","-e","
         import('node:https').then(({default:h})=>{
           const r=h.request('https://<service>-internal.karta.cards/api/health',
             {rejectUnauthorized:true},rs=>{
               console.log('status='+rs.statusCode);
               let d='';rs.on('data',c=>d+=c);
               rs.on('end',()=>console.log('body='+d));
             });
           r.on('error',e=>console.log('ERR '+e.message));
           r.end();
         });
         setTimeout(()=>process.exit(0),5000);
       "
     ]}]}'
   ```
   Expect `status=200` + the service's health body. `ERR self-signed`
   or similar means the cert/SNI host mismatch — re-check the
   listener rule's host header value.

6. **Remove the HTTP listener** once every consumer of that service
   has migrated to HTTPS. This is the "actually retire HTTP" step;
   defer until the matrix is clean.

## What remains unsafe to do without coordination

- **Don't** create a private hosted zone for `karta.cards` in Route 53
  attached to the VPC. It would shadow the entire public zone for VPC
  resources, breaking any service that calls e.g. `https://karta.cards`
  or `https://manage.karta.cards` from within the VPC.

- **Don't** delete or modify the existing HTTP listeners until at least
  one service has been migrated end-to-end and verified. Removing the
  HTTP path before the consumer migrates = silent service-to-service
  failure.

- **Don't** flip Cloudflare proxy mode on these records. The ALB needs
  the unmangled Host header to dispatch by listener rule.

## Reference

- ALB ARN: `arn:aws:elasticloadbalancing:ap-southeast-2:600743178530:loadbalancer/app/vera-internal/f607108ee78ebe20`
- HTTPS listener: `…:listener/app/vera-internal/f607108ee78ebe20/5f7541f413313cfb`
- Wildcard cert: `*.karta.cards` ISSUED, ARN
  `arn:aws:acm:ap-southeast-2:600743178530:certificate/80fd420f-0b88-46a9-9234-8f449f467644`
- Sample rule (priority 10): `rca-internal.karta.cards` → palisade-rca TG
