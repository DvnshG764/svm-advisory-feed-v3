const STANDARD_OS_PATTERNS = [
  /^Cisco ASA\b/i,
  /^Cisco FPR\b/i
];

const CISCO_OS_RULES = [
  {
    label: "Cisco ASA",
    patterns: [
      /\badaptive security appliance\b/i,
      /\bsecure firewall asa\b/i,
      /\bcisco asa\b/i,
      /\basa\b/i
    ]
  },
  {
    label: "Cisco FPR",
    patterns: [
      /\bfirepower threat defense\b/i,
      /\bsecure firewall ftd\b/i,
      /\bcisco fpr\b/i,
      /\bftd\b/i,
      /\bfpr\b/i
    ]
  },
  {
    label: "Cisco IOS XE Software",
    patterns: [/\bcisco ios xe software\b/i, /\bios xe software\b/i]
  },
  {
    label: "Cisco IOS XR Software",
    patterns: [/\bcisco ios xr software\b/i, /\bios xr software\b/i]
  },
  {
    label: "Cisco IOS Software",
    patterns: [/\bcisco ios software\b/i, /\bios software\b/i]
  },
  {
    label: "Cisco NX-OS Software",
    patterns: [/\bcisco nx-os software\b/i, /\bnx-os software\b/i]
  },
  {
    label: "Cisco Webex Services",
    patterns: [/\bcisco webex services\b/i, /\bwebex services\b/i]
  },
  {
    label: "Cisco Identity Services Engine",
    patterns: [/\bcisco identity services engine\b/i, /\bidentity services engine\b/i]
  },
  {
    label: "Cisco Unity Connection",
    patterns: [/\bcisco unity connection\b/i, /\bunity connection\b/i]
  },
  {
    label: "Cisco Unified Communications Manager",
    patterns: [/\bcisco unified communications manager\b/i, /\bunified communications manager\b/i]
  },
  {
    label: "Cisco Secure Web Appliance",
    patterns: [/\bcisco secure web appliance\b/i, /\bsecure web appliance\b/i]
  },
  {
    label: "Cisco Secure Email Gateway",
    patterns: [/\bcisco secure email gateway\b/i, /\bsecure email gateway\b/i]
  },
  {
    label: "Cisco Umbrella",
    patterns: [/\bcisco umbrella\b/i, /\bumbrella\b/i]
  },
  {
    label: "Snort 3",
    patterns: [/\bsnort 3\b/i]
  },
  {
    label: "Cisco Snort",
    patterns: [/\bcisco snort\b/i]
  },
  {
    label: "Cisco ThousandEyes",
    patterns: [/\bcisco thousandeyes\b/i, /\bthousandeyes\b/i]
  },
  {
    label: "Cisco DNA Center",
    patterns: [/\bcisco dna center\b/i, /\bdna center\b/i]
  },
  {
    label: "Cisco Integrated Management Controller",
    patterns: [
      /\bcisco integrated management controller\b/i,
      /\bintegrated management controller\b/i
    ]
  },
  {
    label: "Cisco Smart Software Manager",
    patterns: [/\bcisco smart software manager\b/i, /\bsmart software manager\b/i]
  },
  {
    label: "Cisco Nexus Dashboard Insights",
    patterns: [/\bcisco nexus dashboard insights\b/i, /\bnexus dashboard insights\b/i]
  },
  {
    label: "Cisco Nexus Dashboard",
    patterns: [/\bcisco nexus dashboard\b/i, /\bnexus dashboard\b/i]
  },
  {
    label: "Cisco Nexus",
    patterns: [/\bcisco nexus\b/i, /\bnexus\b/i]
  },
  {
    label: "Cisco Catalyst",
    patterns: [/\bcisco catalyst\b/i, /\bcatalyst\b/i]
  },
  {
    label: "Cisco SD-WAN",
    patterns: [/\bcisco sd-wan\b/i, /\bsd-wan\b/i]
  },
  {
    label: "Cisco Meraki",
    patterns: [/\bcisco meraki\b/i, /\bmeraki\b/i]
  },
  {
    label: "Cisco Jabber",
    patterns: [/\bcisco jabber\b/i, /\bjabber\b/i]
  },
  {
    label: "Cisco Slido",
    patterns: [/\bcisco slido\b/i, /\bslido\b/i]
  },
  {
    label: "Cisco IoT Field Network Director",
    patterns: [/\bcisco iot field network director\b/i, /\biot field network director\b/i]
  },
  {
    label: "Cisco Managed Switches",
    patterns: [/\bmanaged switches\b/i, /\bmanaged switch\b/i]
  },
  {
    label: "Cisco Crosswork Network Controller (CNC)",
    patterns: [/\bcrosswork network controller\b/i, /\bcisco cnc\b/i]
  },
  {
    label: "Cisco Network Services Orchestrator (NSO)",
    patterns: [/\bnetwork services orchestrator\b/i, /\bcisco nso\b/i]
  }
];

export function detectCiscoOsList(titleText) {
  const t = String(titleText || "").toLowerCase();
  const out = [];

  for (const rule of CISCO_OS_RULES) {
    const matched = rule.patterns.some((pattern) => pattern.test(t));

    if (matched && !out.includes(rule.label)) {
      out.push(rule.label);
    }
  }

  if (!out.length) {
    out.push("Check Manually");
  }

  return out;
}

export function isStandardCiscoOs(osList) {
  return osList.some((os) =>
    STANDARD_OS_PATTERNS.some((pattern) => pattern.test(os))
  );
}
