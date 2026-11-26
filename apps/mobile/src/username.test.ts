import assert from 'node:assert/strict';
import { test } from 'node:test';

import { usernameProblem } from './username.ts';

test('usernameProblem says what keeps a typed name from being registered', () => {
  assert.equal(usernameProblem('alice'), null);
  assert.equal(usernameProblem('maya_1987'), null);
  // A keyboard's trailing space is not part of the name.
  assert.equal(usernameProblem(' alice '), null);
  assert.equal(usernameProblem(''), 'short');
  assert.equal(usernameProblem('al'), 'short');
  assert.equal(usernameProblem('alice smith'), 'characters');
  assert.equal(usernameProblem('alice-smith'), 'characters');
  assert.equal(usernameProblem('Alice'), 'characters');
  assert.equal(usernameProblem('a'.repeat(32)), null);
  assert.equal(usernameProblem('a'.repeat(33)), 'long');
});
