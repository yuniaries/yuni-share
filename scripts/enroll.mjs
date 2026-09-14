import path from 'node:path';
import { issueEnrollment } from '../enrollment.mjs';
const email = process.argv[2];
if (!email) { console.error('Usage: node scripts/enroll.mjs person@example.com'); process.exit(1); }
console.log('One-time registration code (15 minutes; share privately):',issueEnrollment(path.resolve(process.env.DATA_ROOT || './data'),email));
