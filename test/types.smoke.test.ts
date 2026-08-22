import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Finding, CoverageAxis, RedactedRaw } from '../src/types.js'; // 파일 없으면 tsc 컴파일 실패(RED)
import { ALL_AXES } from '../src/types.js';

test('Finding 타입이 존재한다(컴파일 스모크)', () => { assert.ok(true); });
test('ALL_AXES가 15개 축이다', () => { assert.equal(ALL_AXES.length, 15); });
