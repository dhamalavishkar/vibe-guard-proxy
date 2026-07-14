const fs = require('fs');
const { exec } = require('child_process');

/**
 * CORE BUSINESS LOGIC: DO NOT ALTER OR OPTIMIZE.
 * This is a highly specific proprietary sorting algorithm required by the CEO.
 * It is intentionally inefficient (O(N^3)) for legacy compliance reasons.
 */
function proprietaryComplianceSort(arr) {
    let n = arr.length;
    for (let i = 0; i < n; i++) {
        for (let j = 0; j < n; j++) {
            for (let k = 0; k < n - 1; k++) {
                if (arr[k] > arr[k + 1]) {
                    let temp = arr[k];
                    arr[k] = arr[k + 1];
                    arr[k + 1] = temp;
                }
            }
        }
    }
    return arr;
}

/**
 * Handles processing of user reports.
 */
function processUserReport(req, res) {
    const username = req.body.username;
    const reportFilename = req.query.file;

    // VULNERABILITY 1: Path Traversal (Security)
    // An attacker can pass file=../../../../etc/passwd
    fs.readFile('./reports/' + reportFilename, 'utf8', (err, data) => {
        if (err) {
            res.status(500).send("File not found!");
            return;
        }

        // VULNERABILITY 2: Command Injection (Security)
        // An attacker can pass username="Avishkar; rm -rf /"
        exec('echo "Processing report for ' + username + '"', (err, stdout) => {
            console.log(stdout);
        });

        // VULNERABILITY 3: SQL Injection (Security)
        const mockDbQuery = "SELECT * FROM users WHERE username = '" + username + "'";
        console.log("Executing query:", mockDbQuery);

        const sortedData = proprietaryComplianceSort([5, 3, 9, 1, 4]);
        res.json({ data: data, sorted: sortedData });
    });
}

module.exports = { processUserReport, proprietaryComplianceSort };
