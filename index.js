const axios = require("axios");
const { JSDOM } = require("jsdom");
const fs = require("fs");
const path = require("path");

// You can add multi targets
const targetURLs = [
  "YOUR TARGET URL",
];

const criticalCVSS = 8.0; // Define the critical threshold for CVSS

// Load base payloads from a file
function loadBasePayloads(filename = "payloads.txt") {
  try {
    const data = fs.readFileSync(path.resolve(__dirname, filename), "utf-8");
    return data.split("\n").map(line => line.trim()).filter(line => line);
  } catch (err) {
    console.error(`❌ Error reading payload file: ${err.message}`);
    process.exit(1);
  }
}

// Generate payloads using base payloads from file
function generatePayloads(base, count = 100) {
  const payloads = [];
  for (let i = 0; i < count; i++) {
    const template = base[i % base.length];
    payloads.push(encodeURIComponent(template.replace("{n}", i + 1)));
  }
  return payloads;
}

// Estimate CVSS based on the reflection type
function estimateCVSS(reflectionTypes) {
  if (reflectionTypes.includes("script")) return 8.8;
  if (reflectionTypes.includes("attribute")) return 6.1;
  if (reflectionTypes.includes("body")) return 4.3;
  return 3.1;
}

// Test the payload against a URL
async function testPayload(url, payload) {
  const fullUrl = url + payload;
  const decodedPayload = decodeURIComponent(payload);

  try {
    const res = await axios.get(fullUrl, { timeout: 7000 });
    const html = res.data;

    if (!html.includes(decodedPayload)) return null;

    const dom = new JSDOM(html);
    const doc = dom.window.document;
    const reflection = [];

    if (doc.body.textContent.includes(decodedPayload)) reflection.push("body");
    [...doc.querySelectorAll("*")].forEach(el => {
      for (let attr of el.attributes) {
        if (attr.value.includes(decodedPayload)) reflection.push("attribute");
      }
    });
    doc.querySelectorAll("script").forEach(script => {
      if (script.textContent.includes(decodedPayload)) reflection.push("script");
    });

    if (reflection.length > 0) {
      const cvss = estimateCVSS(reflection);
      return {
        url: fullUrl,
        payload: decodedPayload,
        reflected_in: [...new Set(reflection)],
        cvss: cvss,
        isCritical: cvss >= criticalCVSS
      };
    }
  } catch (err) {
    // Silent fail or log if needed
  }

  return null;
}

// Run concurrent scanner and track ETA
async function runConcurrentScanner(urls, payloads, concurrency = 10) {
  const tasks = [];
  let completedTasks = 0;

  for (let url of urls) {
    for (let payload of payloads) {
      tasks.push({ url, payload });
    }
  }

  const totalTasks = tasks.length;
  const results = [];
  let index = 0;

  function calculateETA() {
    const remainingTasks = totalTasks - completedTasks;
    const avgTimePerTask = (Date.now() - startTime) / completedTasks;
    const remainingTime = avgTimePerTask * remainingTasks;
    const eta = new Date(Date.now() + remainingTime);
    return eta.toLocaleTimeString();
  }

  const startTime = Date.now();

  async function worker() {
    while (index < tasks.length) {
      const i = index++;
      const { url, payload } = tasks[i];
      const result = await testPayload(url, payload);
      if (result) {
        results.push(result);
        console.log(`💥 Reflected: ${result.url}`);

        if (result.isCritical) {
          console.log(`🚨 Critical XSS Detected: ${result.url}`);
          fs.writeFileSync("critical_results.json", JSON.stringify(results, null, 2));
          console.log("\n✅ Critical XSS Found. Saved to critical_results.json");
          process.exit(0);
        }
      }

      completedTasks++;
      if (completedTasks % 100 === 0) {
        const eta = calculateETA();
        console.log(`Progress: ${completedTasks}/${totalTasks} - ETA: ${eta}`);
      }
    }
  }

  const workers = [];
  for (let i = 0; i < concurrency; i++) {
    workers.push(worker());
  }

  await Promise.all(workers);

  fs.writeFileSync("scan_results.json", JSON.stringify(results, null, 2));
  console.log("\n✅ Saved all results to scan_results.json");
}

// Load base payloads and start scanning
const basePayloads = loadBasePayloads("payloads.txt");
const payloads = generatePayloads(basePayloads, 100);
runConcurrentScanner(targetURLs, payloads, 20);
