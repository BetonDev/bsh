# Public Security Audit Summary

## BETON and BSH Solana Programs

| Item                    | Detail                                                                                                                                                      |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Review date             | 2026-04-30                                                                                                                                                  |
| Review basis            | Private review of the closed-source on-chain repository snapshot current on the review date                                                                 |
| Systems in scope        | BETON mainnet program and BSH mainnet program                                                                                                               |
| Public program IDs      | BETON `BpwBgBZ8WFDk7BswjJNoepmisZS1KfuoKbybCLaF5Hj6`, BSH `91ahrFntCbnRAcJhsSQGd4j2QNdiUZTbESA6cJYKeovn`                                                    |
| Public disclosure model | This document is a public summary. Internal source paths, implementation excerpts, non-public constants, and reviewer workpapers are intentionally omitted. |

> This report is formatted for public disclosure while the source repository remains closed. It summarizes security conclusions and operating considerations without exposing non-public implementation detail.

---

## 1. Executive summary

The reviewed on-chain systems implement the BETON betting protocol and the BSH reward and swap companion program on Solana. The assessment focused on authority boundaries, settlement integrity, value movement controls, oracle-dependent logic, and cross-program interaction surfaces inside the private source tree in effect on 2026-04-30.

No critical, high, or medium severity issues were identified in the on-chain programs within scope. Four informational observations were recorded relating to governance, environment separation, interface stability, and operational monitoring. Based on the reviewed snapshot, the security posture was assessed as suitable for continued mainnet operation subject to standard deployment, key-management, and monitoring controls.

---

## 2. Findings overview

| Severity      | Count |
| ------------- | ----: |
| Critical      |     0 |
| High          |     0 |
| Medium        |     0 |
| Low           |     0 |
| Informational |     4 |

---

## 3. Scope and methodology

| Area                  | Coverage                                                                                                                                                    |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Included              | On-chain program logic, privileged instruction boundaries, settlement and reward flows, cross-program trust assumptions, and production build configuration |
| Excluded              | Frontend, indexer, infrastructure, RPC operations, deployment custody processes, marketing site content, and off-chain automation                           |
| Methods used          | Manual source review, account-model inspection, state-transition analysis, privilege-surface review, and deployment-configuration review                    |
| Disclosure constraint | Closed-source release. Public report intentionally excludes internal file names, exact operational thresholds, and non-public implementation evidence.      |

This publication is a public-facing summary of the review outcome, not a line-by-line technical workpaper. More granular evidence can be shared separately under controlled access if a diligence process requires it.

---

## 4. Security strengths observed

- **Conservative value movement controls.** The reviewed programs follow a defensive approach to fund movement and account mutation, with explicit validation around arithmetic, state transitions, and account safety assumptions.
- **Strong settlement integrity controls.** Settlement paths incorporate layered protections intended to reduce replay risk, duplicate execution risk, and invalid state progression.
- **Production-specific safety gates.** The reviewed deployment configuration differentiates production from non-production environments and applies stricter checks to live-network operation.
- **Minimal cross-program trust.** The trust relationship between BETON and BSH is intentionally narrow, reducing unnecessary write authority and limiting the shared attack surface.
- **Version-aware state evolution.** State handling reflects forward-compatibility planning, supporting safer upgrades and controlled interface changes over time.
- **Operational security posture is visible in the codebase.** The reviewed programs show deliberate attention to failure handling, privilege isolation, and deployment discipline rather than relying on optimistic assumptions.

---

## 5. Informational observations

### F-I-1 — Governance changes rely on controlled release management

Certain privileged configuration choices are intentionally tied to governed release workflows rather than open-ended runtime mutation. This reduces day-to-day authority surface area, but it also means administrative rotation and equivalent governance changes should follow a formal upgrade process.

### F-I-2 — Production validation is stricter than non-production validation

Mainnet operation applies stricter verification and environment checks than development or rehearsal environments. This is a positive design choice, but release teams should continue to verify that production artifacts are built with the intended configuration before deployment.

### F-I-3 — Cross-program compatibility is a governed interface

The reviewed architecture depends on a narrow, stable data contract between the two on-chain programs. Future protocol expansion should preserve that compatibility discipline or introduce controlled migration paths when interface changes become necessary.

### F-I-4 — Telemetry remains part of defense in depth

Some economically sensitive behaviors are acceptable on-chain by design but still benefit from off-chain monitoring, alerting, and operator review. Operational telemetry should remain part of the overall control environment even when no protocol-level finding is recorded.

---

## 6. Residual risk and operator guidance

- **Verify deployed bytes against reviewed artifacts.** Closed-source operation increases the importance of release governance and artifact verification.
- **Protect upgrade and treasury authorities.** Key custody, approval workflows, and change management remain foundational controls outside the program logic itself.
- **Continue production monitoring.** Settlement anomalies, value flow irregularities, and reward-distribution outliers should be monitored as routine operating controls.
- **Reassess after material changes.** Governance changes, major feature additions, tokenomic updates, or interface changes should trigger a fresh security review.

---

## 7. Conclusion

Based on the private source snapshot reviewed on 2026-04-30, no issues requiring immediate mainnet suspension, rollback, or emergency remediation were identified in the on-chain programs within scope. The reviewed release demonstrated a sound security posture for continued operation, with the remaining observations falling into governance and operational-discipline categories rather than exploit-blocking defects.

---

## 8. Disclosure note and disclaimer

This publication is a public summary prepared from a closed-source review and is intentionally less detailed than the private review record. It does not disclose internal source organization, operational runbooks, exact configuration thresholds, or reviewer workpapers.

It is not a guarantee of correctness or absence of vulnerabilities, and it does not cover off-chain services, hosting, RPC providers, wallet software, custody procedures, or downstream integrations unless expressly stated. Operators remain responsible for release verification, key management, monitoring, and independent validation of deployed artifacts.
