import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { issueEnrollment, enrollmentRequest } from '../enrollment.mjs';
test('registration code is email-bound, single-use, and locked after five failures', () => {
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'share-enroll-test-'));
 try {
  const code=issueEnrollment(root,'a@example.com');
  assert.equal(enrollmentRequest(root,'verify','b@example.com',code).ok,false);
  assert.equal(enrollmentRequest(root,'verify','a@example.com',code).ok,true);
  assert.equal(enrollmentRequest(root,'verify','a@example.com',code).ok,false);
  const next=issueEnrollment(root,'a@example.com');
  for(let i=0;i<5;i++) assert.equal(enrollmentRequest(root,'verify','a@example.com','wrong!').ok,false);
  assert.equal(enrollmentRequest(root,'verify','a@example.com',next).ok,false);
  assert.equal(enrollmentRequest(root,'issue','a@example.com','').status,501);
 } finally {fs.rmSync(root,{recursive:true,force:true});}
});
