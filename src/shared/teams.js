import { CONFIG } from "./config.js";

export function getTeamsWebhookUrl() {
  const webhookUrl = process.env[CONFIG.teams.webhookUrlEnvName];

  if (!webhookUrl) {
    throw new Error(
      `Missing required environment variable: ${CONFIG.teams.webhookUrlEnvName}`
    );
  }

  return webhookUrl;
}

export async function sendTeamsPayload(payload) {
  const webhookUrl = getTeamsWebhookUrl();

  const response = await fetch(webhookUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  const responseText = await response.text();

  if (!response.ok) {
    throw new Error(
      `Teams webhook failed. HTTP ${response.status}. Response: ${responseText}`
    );
  }

  return {
    status: response.status,
    text: responseText
  };
}
