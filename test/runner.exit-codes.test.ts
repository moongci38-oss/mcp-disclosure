import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyScannerFailure } from '../src/runner.js';

// Task 8b 실측(2026-08-22, cisco-ai-mcp-scanner 4.8.3): 아래 exit code 표는 추정치가 아니라
// 격리 venv에 실제 설치 후 재현한 값이다(§8.5 Task 8b, runner.ts EXIT_CODE_MEANING 주석 참조).
test('exit 1 → 스캐너 치명적 오류로 분류되고 meaning 텍스트가 채워진다(실측)', () => {
  const r = classifyScannerFailure(1, 'FileNotFoundError: ...', '');
  assert.equal(r.reason, 'scanner_error');
  assert.ok(r.detail.length > 0);
  assert.ok(!r.detail.startsWith('unparsed stdout'), 'exit 1은 더 이상 미상 분류가 아니다 — 실측 meaning을 써야 한다');
});

test('exit 2 → 인자 파싱 오류로 분류되고 meaning 텍스트가 채워진다(실측)', () => {
  const r = classifyScannerFailure(2, 'error: unrecognized arguments: --version', '');
  assert.equal(r.reason, 'scanner_error');
  assert.ok(!r.detail.startsWith('unparsed stdout'), 'exit 2는 더 이상 미상 분류가 아니다 — 실측 meaning을 써야 한다');
});

test('미실측 exit code(예: 127)는 여전히 안전 기본값(원문 포함)으로 폴백한다', () => {
  const r = classifyScannerFailure(127, 'stderr-text', 'stdout-text');
  assert.equal(r.reason, 'scanner_error');
  assert.ok(r.detail.includes('exit=127'));
});
