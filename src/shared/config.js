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

  processedRetentionDays: 30,

  teams: {
    webhookUrlEnvName: "TEAMS_WEBHOOK_URL"
  }
};
