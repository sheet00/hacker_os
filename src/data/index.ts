import { phase1Templates } from './phase1';
import { phase2Templates } from './phase2';
import { phase3Templates } from './phase3';
import { phase4Templates } from './phase4';
import { phase5Templates } from './phase5';
import { phase6Templates } from './phase6';
import { phase7Templates } from './phase7';

export * from './types';
export * from './common';
export { phase1Templates, phase2Templates, phase3Templates, phase4Templates, phase5Templates, phase6Templates, phase7Templates };

export const ALL_PHASE_TEMPLATES = [
  null,
  phase1Templates,
  phase2Templates,
  phase3Templates,
  phase4Templates,
  phase5Templates,
  phase6Templates,
  phase7Templates
];
