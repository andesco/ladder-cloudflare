#!/usr/bin/env node

const https = require('https');
const fs = require('fs');

// Get manifest URL from environment variable
const manifestUrl = process.env.RULESET_URL;

if (!manifestUrl) {
  console.error('Error: RULESET_URL environment variable is required');
  console.error('Usage: RULESET_URL=https://example.com/manifest.json npm run update-rules');
  process.exit(1);
}

console.log('Downloading from:', manifestUrl);

// Download manifest.json
https.get(manifestUrl, (res) => {
  let data = '';

  res.on('data', (chunk) => {
    data += chunk;
  });

  res.on('end', () => {
    try {
      const manifest = JSON.parse(data);

      // Save manifest.json
      fs.writeFileSync('manifest.json', JSON.stringify(manifest, null, 2));
      console.log('Downloaded manifest.json');

      // Prepare downloads for additional files
      const downloads = [];

      if (manifest.sites_aggregated_yaml?.url) {
        downloads.push({
          url: manifest.sites_aggregated_yaml.url,
          file: 'sites_aggregated.yaml'
        });
      }

      if (manifest.sites_aggregated_json?.url) {
        downloads.push({
          url: manifest.sites_aggregated_json.url,
          file: 'sites_aggregated.json'
        });
      }

      // Download each file
      downloads.forEach(({ url, file }) => {
        https.get(url, (res) => {
          let data = '';

          res.on('data', (chunk) => {
            data += chunk;
          });

          res.on('end', () => {
            fs.writeFileSync(file, data);
            console.log('Downloaded', file);
          });

          res.on('error', (err) => {
            console.error(`Error downloading ${file}:`, err.message);
          });
        });
      });

    } catch (err) {
      console.error('Error parsing manifest.json:', err.message);
      process.exit(1);
    }
  });

  res.on('error', (err) => {
    console.error('Error downloading manifest:', err.message);
    process.exit(1);
  });
}).on('error', (err) => {
  console.error('Error connecting to server:', err.message);
  process.exit(1);
});