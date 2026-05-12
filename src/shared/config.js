export const CONFIG = {
  appName: "svm-advisory-feed-v3",

  vendors: {
    cisco: {
      vendorName: "Cisco",
      vendorKey: "cisco",
      feedUrl:
        "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
      maxRecordsToCheck: 15,
      processedStatePath: "state/processed-cisco.json"
    },

    paloalto: {
      vendorName: "Palo Alto",
      vendorKey: "paloalto",
      feedUrl: "https://security.paloaltonetworks.com/rss.xml",
      maxRecordsToCheck: 7,
      processedStatePath: "state/processed-paloalto.json"
    },

    fortinet: {
    vendorName: "Fortinet",
    vendorKey: "fortinet",
    feedUrl:
    "https://www.fortiguard.com/psirt?filter=1&product=FortiOS-6K7K%2CFortiOS&product=FortiSwitchManager&product=FortiSwitch&product=FortiSwitchAXFixed&product=FortiAP&product=FortiAP-U&product=FortiAP-W2&product=FortiAP-C&product=FortiAP-S&product=FortiManager&product=FortiAnalyzer&product=FortiManager+Cloud&product=FortiAnalyzer-BigData&product=FortiAnalyzer+Cloud&product=FortiWeb&product=FortiWebManager&product=FortiSandbox&product=FortiExtender&product=FortiSandbox+PaaS&product=FortiSandbox+Cloud&version=&severity=5&severity=4&keyword=",
    maxRecordsToCheck: 10,
    processedStatePath: "state/processed-fortinet.json"
}
  },

  paths: {
    vendorTopRecords: "state/vendor-top-records.json",
    runControl: "state/run-control.json"
  },

  nvd: {
    apiBaseUrl: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=",
    delayMsNoKey: 6000,
    cacheMaxAgeDays: 7
  },

  /*
   * Processed advisory state should persist forever for all vendors.
   * Number.POSITIVE_INFINITY means pruneProcessedState() will not delete old records.
   */
  processedRetentionDays: Number.POSITIVE_INFINITY,

  teams: {
    webhookUrlEnvName: "TEAMS_WEBHOOK_URL"
  }
};
