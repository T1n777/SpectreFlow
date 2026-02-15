# SpectreFlow Test Samples

This directory contains test samples designed to validate SpectreFlow's detection capabilities.

## Test Categories

### 1. Benign Tests (Should be CLEAN)
- **test_01_benign_calculator.py** - Simple math operations
- **test_02_benign_file_reader.py** - Reads own source code

### 2. Single-Indicator Tests
- **test_03_cpu_intensive.py** - High CPU usage (crypto mining sim)
- **test_04_network_scanner.py** - Network connections to suspicious ports
- **test_05_file_writer.py** - Creates files with suspicious extensions
- **test_06_process_spawner.py** - Spawns child processes

### 3. Multi-Indicator Tests
- **test_07_multi_threat.py** - Combines CPU, network, files, processes
- **test_08_stealth_malware.py** - Low-profile suspicious activity
- **test_10_ransomware_sim.py** - Full ransomware simulation (CRITICAL)

### 4. Edge Cases
- **test_09_false_positive_game.py** - Legitimate high CPU usage
  * Tests adaptive baseline detection
  * Should ideally NOT be flagged

## Running Tests

### Individual Test
```bash
python ../main.py test_samples/test_01_benign_calculator.py --duration 10
```

### With Visualization
```bash
python ../main.py test_samples/test_07_multi_threat.py --duration 15 --visualize
```

### With Report Export
```bash
python ../main.py test_samples/test_10_ransomware_sim.py --duration 20 --output report.json
```

### All Tests (Automated)
Windows:
```batch
run_all_tests.bat
```

Linux/Mac:
```bash
./run_all_tests.sh
```

## Expected Results

| Test | Expected Verdict | Risk Level | Indicators |
|------|-----------------|------------|------------|
| test_01 | CLEAN | LOW | None |
| test_02 | CLEAN | LOW | None |
| test_03 | SUSPICIOUS | MEDIUM | CPU spike |
| test_04 | SUSPICIOUS | HIGH | Network (suspicious ports) |
| test_05 | SUSPICIOUS | MEDIUM-HIGH | File activity (sus extensions) |
| test_06 | SUSPICIOUS | MEDIUM | Process spawning |
| test_07 | SUSPICIOUS | HIGH | All indicators |
| test_08 | SUSPICIOUS | MEDIUM | Stealth network + files |
| test_09 | CLEAN* | LOW-MEDIUM | High CPU (but legitimate) |
| test_10 | SUSPICIOUS | CRITICAL | Ransomware simulation |

*test_09 may be flagged depending on adaptive baseline effectiveness

## Validation Criteria

### True Positives (Correctly Detected)
- test_03 through test_08, test_10 should be flagged as SUSPICIOUS

### True Negatives (Correctly Cleared)
- test_01 and test_02 should be marked CLEAN

### Challenging Cases
- test_09: Tests false positive prevention (adaptive baseline)
- test_08: Tests stealth detection capabilities

## Safety Notes

⚠️ These are SIMULATIONS only. They:
- Do NOT contain actual malware
- Do NOT cause harm
- Create temporary files that are cleaned up
- Use local network connections only (127.0.0.1)

However, antivirus software may flag them due to suspicious-looking behavior patterns.

## Reports

Test reports are saved to the `reports/` directory when using the automated scripts.

## Troubleshooting

If tests fail to run:
1. Ensure you're in the correct directory
2. Check that main.py is in the parent directory
3. Verify all dependencies are installed: `pip install -r requirements.txt`
4. Run with `--verbose` for detailed logging

## Contributing

To add new test cases:
1. Create a new generator function in test.py
2. Add it to the TestSuite.tests list
3. Re-run test.py to regenerate samples
