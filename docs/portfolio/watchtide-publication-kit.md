# Watchtide Publication Kit

Prepared October 11, 2026 for the separate portfolio/online-presence chat.
This SOC repository owns technical evidence; that chat owns website integration,
styling, hosting and search-indexing checks. No website setting was changed here.

## Project Listing Copy

**Title:** Watchtide

**Subtitle:** An evidence-led home SOC built with Wazuh, SQL Server and Power BI.

**Short description:** A Windows-to-Wazuh security pipeline with investigated
alerts, scoped detection tuning, controlled Suricata tests, SQL reporting and
documented recovery checks. Explore sanitized historical data and the evidence
behind each result, without connecting to the private lab.

**Primary link:** [Explore the console](https://jordan17133.github.io/Watchtide/).

**Secondary link:** [Source and evidence](https://github.com/jordan17133/Watchtide).

**Technical stack:** Windows 11, Sysmon, Wazuh, Ubuntu, Hyper-V, Suricata,
SQL Server, Power BI, Python, PowerShell and Tailscale.

## Feature Article

Use the [case study](watchtide-case-study.md) as the evidence-backed article.
[watchtide-content.json](watchtide-content.json) supplies structured listing,
result and metadata fields. Do not manufacture current metrics from the older
console image or turn prepared controls into validated detections.

Suggested sections: overview, architecture, selected investigations, reporting/
recovery, skills demonstrated, and limits/continuation. Link each result to its
technical report. This is a home-lab portfolio, not a claim of enterprise SOC
employment, certification, complete protection or paid-service capability.

## Website Metadata Handoff

- Suggested route: `/projects/watchtide`. First check the existing site's routes;
  merge with an existing project entry rather than create a duplicate.
- Page title: `Watchtide Home SOC | Jordan Carven-Bellace`.
- Description: `An evidence-led home SOC with Wazuh, Sysmon, SQL Server, Power BI and controlled Suricata tests. Explore investigations, recovery checks and clear limits.`
- Social image: `https://jordan17133.github.io/Watchtide/console/og-image.png`
  (1200 x 630). Caption the October 3 snapshot date; do not call it live.
- Author: Jordan Carven-Bellace. Content update: October 11, 2026. The website
  chat must use the actual web publication date, not invent an earlier launch.

The supplied destination is `https://jordan-portfolio-alpha.vercel.app/`.
The proposed project URL is not verified as an existing or newly published page.
No canonical, metadata, route or robots change was applied on that website.

## Indexing Acceptance Checklist

The website chat owns these deployment checks. This kit is preparation, not
evidence that the project page is indexed or that rankings will improve.

1. Put readable project text and evidence links on the existing portfolio, with
   a discoverable internal link from Projects. Check the final page response and
   rendering; a JSON file alone is not the reader-facing project page.
2. Give the final public project page one self-referential canonical and align
   internal links with it. Do not canonicalize distinct project copy to the
   interactive console merely because both discuss Watchtide.
3. Include the final canonical URL in that website's sitemap, with a truthful
   significant-update date. Keep the sitemap, robots and canonical consistent;
   never add private SOC addresses or pretend a proposed route is already live.
4. Verify search access for the reviewed public page. Do not remove deployment
   protection globally or expose private dashboards in pursuit of indexing.
5. Use the owner's existing verified Search Console property to inspect the
   deployed URL and submit the sitemap where appropriate. Record indexing as
   observed, pending or unavailable; publishing/submission does not guarantee it.

Google describes canonical preferences as signals and recommends consistent
links rather than conflicting destinations. [Canonical guidance](https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls).
Sitemaps list preferred public URLs; their submission is a hint, not guaranteed
crawling or indexing. [Sitemap guidance](https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap).

## Publication Guardrails

Keep raw records, device/account inventory, private keys, passwords and captures
out of website copy and images. Use the existing sanitized preview and public
reports. Preserve historical dates and original sample sizes. Recheck technical
claims against [current status](../../STATUS.md#current-snapshot) before a later
update. Never infer a live case verdict or incident from a historical rule review.

The SOC continuation is unchanged: watchdog policy/read-scope review, bounded
offline TCP validation, then useful measured telemetry and later analyst lessons.
Website content is a supporting publication artifact, not a replacement project.
