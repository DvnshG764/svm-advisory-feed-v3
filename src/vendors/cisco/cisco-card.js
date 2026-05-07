import { valueOrFallback } from "../../shared/text.js";

const SEVERITY_COLORS = {
  Critical: "attention",
  High: "warning"
};

function buildCiscoToolData(record) {
  return [
    record.cves[0] || "",
    record.publishDate || new Date().toISOString().slice(0, 10),
    record.finalSelectedScore != null ? record.finalSelectedScore : "",
    record.severity || "",
    record.vendor,
    record.title,
    record.vendorLink || "",
    record.nvdLink || ""
  ].join("  \n");
}

function buildCiscoTrackerData(record) {
  return [
    record.cves[0] || "",
    record.publishDate || new Date().toISOString().slice(0, 10),
    record.finalSelectedScore != null ? record.finalSelectedScore : "",
    record.severity || "",
    record.vendor
  ].join("  \n");
}

export function buildCiscoTeamsCardPayload(record) {
  const cardStyle = SEVERITY_COLORS[record.severity || ""] || "default";
  const standardOs = Boolean(record.standardOs);

  const actions = [
    {
      type: "Action.OpenUrl",
      title: "Vendor Link",
      url: record.vendorLink
    },
    {
      type: "Action.OpenUrl",
      title: "NVD Link",
      url: record.nvdLink || record.vendorLink
    }
  ];

  if (standardOs) {
    actions.push({
      type: "Action.ShowCard",
      title: "Tool Data",
      card: {
        type: "AdaptiveCard",
        version: "1.4",
        body: [
          {
            type: "TextBlock",
            text: buildCiscoToolData(record),
            wrap: true,
            fontType: "Monospace"
          }
        ]
      }
    });

    actions.push({
      type: "Action.ShowCard",
      title: "Tracker Data",
      card: {
        type: "AdaptiveCard",
        version: "1.4",
        body: [
          {
            type: "TextBlock",
            text: buildCiscoTrackerData(record),
            wrap: true,
            fontType: "Monospace"
          }
        ]
      }
    });
  }

  return {
    attachments: [
      {
        contentType: "application/vnd.microsoft.card.adaptive",
        content: {
          type: "AdaptiveCard",
          version: "1.4",
          body: [
            {
              type: "Container",
              style: cardStyle,
              items: [
                {
                  type: "TextBlock",
                  text: `🚨 ${record.heading}`,
                  size: "Large",
                  weight: "Bolder"
                },
                {
                  type: "TextBlock",
                  text: `Severity: ${record.severityLine}`,
                  wrap: true
                },
                {
                  type: "TextBlock",
                  text: record.subheading,
                  italic: true,
                  isSubtle: true,
                  wrap: true
                }
              ]
            },
            {
              type: "TextBlock",
              text: `**Title:** ${record.title}`,
              wrap: true
            },
            {
              type: "TextBlock",
              text: `**Affected OS:** ${record.affectedOs.join(", ")}`,
              wrap: true
            },
            {
              type: "TextBlock",
              text: `**CVEs:** ${
                record.cves.length ? record.cves.join(", ") : "None"
              }`,
              wrap: true
            },
            {
              type: "TextBlock",
              text: `**Cisco CVSS v3.x Score:** ${valueOrFallback(
                record.vendorCvssV3Score
              )}`,
              wrap: true
            },
            {
              type: "TextBlock",
              text: `**NVD CVSS v3.x Score:** ${valueOrFallback(
                record.nvdCvssV3Score
              )}`,
              wrap: true
            },
            {
              type: "TextBlock",
              text: `**Final Selected Score:** ${valueOrFallback(
                record.finalSelectedScore
              )}`,
              wrap: true
            }
          ],
          actions
        }
      }
    ]
  };
}

export function buildCiscoDispatchEnvelope(record) {
  return {
    schemaVersion: 1,
    source: "cisco-advisory-pipeline",
    vendor: record.vendor,
    advisorySlug: record.advisorySlug,
    dedupKey: `${record.vendor}:${record.advisorySlug}`,

    createdAt: new Date().toISOString(),
    publishDate: record.publishDate || null,

    severity: record.severity,
    finalSelectedScore: record.finalSelectedScore,

    standardOs: Boolean(record.standardOs),
    title: record.title,
    affectedOs: record.affectedOs || [],
    cves: record.cves || [],

    vendorLink: record.vendorLink || null,
    nvdLink: record.nvdLink || null,

    teamsPayload: buildCiscoTeamsCardPayload(record)
  };
}
