#!/usr/bin/env node

const fs = require('fs');
const https = require('https');
const path = require('path');

const RULESET_URL = 'https://raw.githubusercontent.com/everywall/ladder-rules/main/ruleset.yaml';
const OUTPUT_FILE = 'ruleset.yaml';

async function downloadRuleset() {
    console.log('Downloading ruleset from:', RULESET_URL);

    return new Promise((resolve, reject) => {
        https.get(RULESET_URL, (response) => {
            if (response.statusCode !== 200) {
                reject(new Error(`Failed to download ruleset: ${response.statusCode}`));
                return;
            }

            let data = '';
            response.on('data', (chunk) => {
                data += chunk;
            });

            response.on('end', () => {
                resolve(data);
            });
        }).on('error', (error) => {
            reject(error);
        });
    });
}

async function main() {
    try {
        const rulesetData = await downloadRuleset();

        // Write the ruleset to the output file
        fs.writeFileSync(OUTPUT_FILE, rulesetData);
        console.log(`Ruleset downloaded and saved to: ${OUTPUT_FILE}`);

        // Parse the YAML to extract test URLs for validation
        const yaml = require('yaml');
        const ruleset = yaml.parse(rulesetData);

        const testUrls = [];
        if (Array.isArray(ruleset)) {
            ruleset.forEach(rule => {
                if (rule.tests && Array.isArray(rule.tests)) {
                    rule.tests.forEach(test => {
                        if (test.url) {
                            testUrls.push(test.url);
                        }
                    });
                }
            });
        }

        console.log(`Found ${testUrls.length} test URLs in ruleset`);

        // Write test URLs to a separate file for reference
        const testUrlsJson = JSON.stringify(testUrls, null, 2);
        fs.writeFileSync('test-urls.json', testUrlsJson);
        console.log('Test URLs saved to: test-urls.json');

    } catch (error) {
        console.error('Error building ruleset:', error);
        process.exit(1);
    }
}

main();