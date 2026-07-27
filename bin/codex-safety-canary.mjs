#!/usr/bin/env node
import { stdin as input, stdout as output } from 'node:process';
import {
  getAppRoot,
  getCodexInventory,
  getLatestReport,
  launchDetachedProcess,
  runExecpolicyCoverage,
  runSandboxProbes,
  safeRemoveRun,
  writeReport,
} from '../lib/core.mjs';
import { createCanaryCli } from '../lib/cli-flow.mjs';

const cli = createCanaryCli({
  appRoot: getAppRoot(),
  platform: process.platform,
  input,
  output,
  getInventory: getCodexInventory,
  runExecpolicyCoverage,
  runSandboxProbes,
  writeReport,
  getLatestReport,
  safeRemoveRun,
  launchDetachedProcess,
});

process.exitCode = await cli.run();
