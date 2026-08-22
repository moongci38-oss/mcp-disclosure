# 구현 중 발견 사항 (Spec과 어긋난 점, 있으면 기록)

- Task 8: Spec의 RED 테스트 스니펫(§8.5)은 "scanOne을 mock하여..."라는 주석뿐 실제 코드가 없었다.
  Task 7이 이미 `ScanDeps`(spawn 주입) 설계를 확립해 뒀으므로, 그 설계를 그대로 이어받아
  EventEmitter 기반 fake spawn으로 대체 구현(모킹 함정 회피, Task 7의 설계 의도와 일치).
