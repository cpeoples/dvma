Some vulnerabilities are, by definition, **cross-app**: the whole premise is a
*second co-resident app* crossing a trust boundary. Those cannot be
demonstrated inside DVMA alone, so `com.dvma.attacker` exists as the "malicious
co-resident app" the docs reference. It has its **own UID and signing key** and
requests **no dangerous permissions**, that is the point: it shows what an
*arbitrary* installed app can harvest from a vulnerable DVMA.

## The cleanest example, the cross-app OTP leak

- DVMA fires an **implicit broadcast** `com.dvma.action.OTP_ISSUED` with **no
  receiver permission** (the vulnerable path), or gated behind a signature-level
  permission (the fix).
- The attacker's `OtpLeakReceiver` (kept alive by a foreground
  `OtpHarvestService`) receives it, logs under the `DVMA-ATTACKER` tag, and
  writes a pullable capture file. On the secure path Android drops delivery,
  because the attacker cannot hold DVMA's signature-level permission.

## The other cross-app primitives

The same shape covers the other cross-app modules: `BroadcastForger` (spoof
exported receivers), `ComponentInvoker` (start DVMA's exported Activities by
name), `ServiceBinderClient` (bind the privileged Messenger service), and
`HijackActivity` (task-affinity reparenting). See
`companion/dvma-attacker/README.md` for the full trigger map and the
one-command demos (`automation/scripts/demo.sh <otp|broadcast|components>`).
