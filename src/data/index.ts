import { phase1Templates } from './phase1';
import { phase2Templates } from './phase2';
import { phase3Templates } from './phase3';
import { phase4Templates } from './phase4';
import { phase5Templates } from './phase5';
import { phase6Templates } from './phase6';
import { phase7Templates } from './phase7';
import { phase8Templates } from './phase8';

export * from './types';
export * from './common';
export { phase1Templates, phase2Templates, phase3Templates, phase4Templates, phase5Templates, phase6Templates, phase7Templates, phase8Templates };

export const ALL_PHASE_TEMPLATES = [
  null,
  phase1Templates,
  phase2Templates,
  phase3Templates,
  phase4Templates,
  phase5Templates,
  phase6Templates,
  phase7Templates,
  phase8Templates
];

export const MAX_PHASE = ALL_PHASE_TEMPLATES.length - 1;
export const PHASE_NUMBERS = Array.from({ length: MAX_PHASE }, (_, i) => i + 1);
export const INITIAL_PHASE_MESSAGES = [
  "",
  "Initializing reconnaissance...",
  "Running vulnerability scans...",
  "Executing initial access...",
  "Escalating privileges...",
  "Injecting malicious code...",
  "Monitoring deployment...",
  "Clearing tracks and logging out...",
  "Executing SIGTERM-GLOBAL-INFRA..."
];
