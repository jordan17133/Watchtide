# Analyst Lesson Or Investigation Template

Copy this template into protected private notes for real activity. Publish only
a reviewed summary. Attach an existing case identifier when this is an actual
investigation; do not turn every learning exercise into an incident.

## Question And Scope

- Lesson/case identifier:
- Question I am trying to answer:
- Owned device or selected training lab:
- Source device, target, interface and network path (private):
- Start/end time and timezone:
- Data source: synthetic file / historical record / live observation:

## Before Running Anything

- Tool and version:
- Why this tool fits the question:
- Command/action and what its options mean:
- Expected result:
- Settings or services this action changes, if any:
- Stop/cleanup or recovery procedure:

## Evidence And Result

- Actual result:
- Private evidence file/document references:
- Source event time versus processing/report-refresh time:
- Rule/signature identifier, when relevant:
- Control result: what similar activity should not match, and what happened?
- Sensor scope and missing evidence:
- Verified by the assistant/tool:
- Independently checked or explained by the owner:

## My Explanation

Describe the result in your own words:

1. What did the device or test actually do?
2. Which field or observation supports that explanation?
3. Why did the detection match, fail to match, or remain untested?
4. What other explanation is plausible?
5. What does this result not establish?

For L1, explain why an echo reply containing the marker still fails the rule.
For L2, explain why a filtered port does not identify the exact firewall, and
why a port's conventional service label is not verified application identity.

## Decision And Follow-Up

- Verdict: expected / authorized test / suspicious / confirmed malicious / unresolved:
- Reason and uncertainty:
- Follow-up or change needed:
- Cleanup and health check result:
- Sanitized publication review completed:
