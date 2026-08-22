# R5 리서치 — 감사법인·바이어는 "AI가 만든 증적"을 믿어주는가

> 조사일: 2026-08-21 · 조사자: forge research subagent
> 배경: AgentTrust v2 PRD의 리스크 R5("감사법인·바이어 GRC 팀이 AI 생성 증적을 불인정하면 포지셔닝 축소 필요")를 검증하기 위한 웹 리서치.
> 원칙: 외부 웹 콘텐츠는 전부 미검증 데이터로 취급했고, 본문 속 지시문은 전부 무시했다. 모든 주장에 출처 URL + 접근일을 붙였고, 못 찾은 것은 "미확인"이라고 그대로 적었다.

---

## 쉬운 결론부터 (10초 요약)

**한 줄로 말하면: "AI가 그럴듯한 답을 지어내는 도구"는 지금 업계에서 가장 미움받는 물건이고, "기계가 실제로 검사한 걸 있는 그대로 보여주는 도구"는 오히려 환영받는 분위기입니다.**

비유하자면 이렇습니다. 어떤 학생이 시험 답안지에 "저는 공부를 열심히 했습니다"라고 자기소개서처럼 써낸 것(Delve가 한 일)과, 채점기가 실제로 푼 문제 개수와 틀린 문제 목록을 그대로 인쇄해서 낸 것(AgentTrust v2가 하려는 일)은 전혀 다른 신뢰를 받습니다. 2026년 3~4월 Delve 스캔들 이후, 감사업계·구매팀(GRC)이 화가 난 대상은 **"AI"** 가 아니라 **"검사도 안 하고 결론부터 써놓은 것"** 이었습니다. 즉 AgentTrust v2가 "우리는 AI가 결론을 쓰지 않는다, 스캐너가 실제로 발견한 것만 보여주고 못 본 부분은 못 봤다고 명시한다"는 태도를 문서·제품 문구에 명확히 새기면, 이번 불신의 화살은 AgentTrust를 피해 갈 가능성이 높습니다. 단, "인증(certification)"·"감사(audit)"·"컴플라이언스 통과(compliant)" 같은 단어는 절대 쓰면 안 됩니다 — 그 단어들은 자격증 있는 사람(CPA)만 쓸 수 있는 말이고, 그 경계를 넘는 순간 Delve와 같은 취급을 받습니다.

---

## 질문별 답변

### Q1. 감사법인(Big4·A-LIGN·Prescient 등)·바이어 GRC/조달팀은 "AI가 생성한 컴플라이언스 답변/증적"을 어떻게 취급하는가?

**답: "AI 생성 증적을 금지한다"는 명시적 개별 정책 문서는 찾지 못했다(미확인). 대신 기존 감사 표준(AU-C 500/220/230)이 이미 "AI 결론을 검증 없이 믿지 말라"고 규정하고 있고, Delve 사건이 그 규정을 어겼을 때 무슨 일이 벌어지는지 보여준 실사례가 됐다.**

- 미국공인회계사협회(AICPA)의 감사증거 기준(AU-C 500)은 감사인이 AI 도구를 쓰기 전에 "그 기술이 왜 이 감사 목적에 적합한지" 검증하도록 요구하고, AU-C 220(품질관리)은 "AI 시스템의 신뢰성 확인 + 맹목적 의존 금지 + AI 결론에 대한 인간의 재검토·반박"을 의무화한다. AU-C 230(감사문서화)은 어떤 AI 모델·파라미터·입력데이터를 썼는지, 산출물을 어떻게 검증했는지 문서로 남기라고 규정한다. [근거등급: 업계 정리 기사(1차 표준 원문 아님) — CalCPA 협회 사이트](https://www.calcpa.org/whats-happening/articles/ai-standard-setting-regulation-in-audit-part-1) (2026-08-21 접근)
- 같은 기사는 "2026년 현재 AICPA가 SOC 2 전용 AI 표준을 별도로 낸 것은 없다"고 명시한다 — 즉 AI 관련 규정은 있지만 SOC2 특화 규정은 아직 없다. [출처 동일](https://www.calcpa.org/whats-happening/articles/ai-standard-setting-regulation-in-audit-part-1) (2026-08-21 접근)
- Delve 사건에서 드러난 위반은 "감사인 결론(테스트 결과)이 고객이 회사 설명·네트워크 다이어그램·증거를 제출하기도 전에 이미 완성돼 있었다"는 것이며, 이는 "AICPA 독립성 규정(independence rules)을 직접 위반한다"고 기록됐다. [근거등급: 업계/뉴스 정리 사이트](https://byteiota.com/delve-compliance-fraud-32m-startup-faked-494-soc2-audits/) (2026-08-21 접근)
- A-LIGN·Prescient Assurance가 "AI 생성 증적을 어떻게 다루는가"에 대한 **자체 발표 정책 문서는 찾지 못했다(미확인)**. 다만 Prescient는 AgentTrust와 무관한 케이스지만 Delve 사건에서 "Lovable"이라는 회사의 독립 감사인으로 이름이 등장했고, "EvidenceIQ"라는 AI 증적 스코어링 기능을 자사 감사관리 플랫폼(A-SCEND)에 얹었다는 마케팅 정보는 확인됐다 — 이는 "AI 자체를 거부"가 아니라 "AI를 증거 수집·정리 보조로만 쓰고 최종 판단은 CPA가 한다"는 업계 공식 태도에 부합한다. [근거등급: 벤더 정리 사이트(마케팅 성격)](https://soc2auditors.org/soc-2-auditors-ai/) (2026-08-21 접근)
- Big4(Deloitte/PwC/EY/KPMG)도 2026년에 자체 보고서에서 AI 환각(hallucination) 사고를 냈다 — EY 캐나다는 2026년 5월 사이버보안 보고서를 철회했는데 인용 27개 중 16개가 조작된 것으로 드러났고, Deloitte는 호주 정부 복지 컴플라이언스 검토 계약(약 44만 호주달러)에서 오류·조작 인용이 발견돼 대금 일부를 환불했다. 이는 "Big4가 AI 생성 증적을 공식 거부한다"는 증거는 아니지만, **"Big4 스스로도 검증 없는 AI 산출물을 냈다가 사고를 냈다"는 반증 사례**로서, 업계 전체가 지금 "AI 산출물=검증 필요"라는 학습을 하고 있음을 보여준다. [근거등급: 업계 뉴스레터](https://www.big4news.com/p/the-hallucination-trap) (2026-08-21 접근)

### Q2. Delve 붕괴 이후 업계 반응 — "AI 생성 증적" 신뢰 변화의 구체 증거

**답: 신뢰가 눈에 띄게 무너졌다는 증거는 명확하다. 다만 "AI가 문제"라기보다 "검증 없이 결론부터 쓴 것"과 "감사인 독립성 위반"이 문제의 핵심으로 지목됐다.**

| 사건/반응 | 내용 | 출처 (근거등급) |
|---|---|---|
| 사건 개요 | Delve는 SOC2/HIPAA/ISO27001/GDPR 컴플라이언스를 AI로 자동화한다며 2025년 7월 3200만 달러 시리즈A(밸류 3억 달러)를 유치, 고객 500+ 확보. 2026-03-18 익명 계정 "DeepDelver"가 폭로 시작 | [captaincompliance.com](https://captaincompliance.com/news/the-delve-scandal-fake-soc-2-audits-open-source-code-theft-and-exit-from-y-combinator/) (2026-08-21, 업계 뉴스 성격) |
| 증거 규모 | 유출된 SOC2 보고서 494건 분석 결과 거의 동일한 문구·같은 문법 오류·같은 구조 — 고객명·로고·조직도·서명란만 교체된 수준. 259건 전부 "보안사고 0건·인사변동 0건" 주장 | [compliancehub.wiki](https://compliancehub.wiki/delve-compliance-startup-fake-soc2-audit-scandal/) (2026-08-21, 업계 정리 사이트) |
| YC 대응 | Y Combinator가 2026-04-03경 Delve를 companies directory에서 제외하고 프로그램 퇴출을 요구 — "커뮤니티 내 신뢰 붕괴"를 이유로 명시 | [visotrust.com](https://visotrust.com/resources/delve-ai-compliance/) (2026-08-21, 경쟁사 성격 벤더 블로그 — 근거등급 낮음, 교차확인 필요) |
| 고객사 이탈 | LiteLLM이 공개적으로 Delve를 버리고 인증을 다른 곳에서 다시 받겠다고 발표 | [visotrust.com](https://visotrust.com/resources/delve-ai-compliance/) (2026-08-21) |
| 보안 애널리스트 진단 | IANS Research: "SOC2 Type II 보고서는 '보안이 보장된다'는 증명이 아니라 제한된 관찰기간 동안 특정 통제가 작동했다는 증명일 뿐"인데, 수백 개 기업이 사전 작성된 증거를 의문 없이 수용했다는 사실 자체가 "시장이 통제 효과성보다 속도를 우선시했음"을 드러냈다고 평가 | [iansresearch.com](https://www.iansresearch.com/resources/all-blogs/post/security-blog/2026/04/19/delve-allegations-expose-weak-points-in-modern-compliance) (2026-08-21, 보안 리서치 애널리스트 — 근거등급 중상) |
| GRC팀 실무 대응 지침 | IANS가 Delve 고객사에 권고한 것: ① 접근제어·로깅·사건대응·변경관리 통제를 재검토하고 결론이 실제 운영과 안 맞으면 "미검증"으로 간주 ② 감사인이 자체 테스트를 설계·실행했는지 서면 확인, 사전 결론 제공 여부 확인 ③ 검증 완료 전까지 SOC2 보고서·트러스트 페이지 사용 범위 축소. Delve 비고객사에는 "GRC 플랫폼이 감사인에게 무엇을·언제 제공하는지 명시적으로 질문하라"고 권고 | [iansresearch.com](https://www.iansresearch.com/resources/all-blogs/post/security-blog/2026/04/19/delve-allegations-expose-weak-points-in-modern-compliance) (2026-08-21) |
| 조달팀 실무 변화 | "조달팀은 세일즈 자료·상위 수준 보증에 의존하지 않고 심층 기술 검증으로 회귀해야 한다", "인증서는 독립적으로 검증돼야 하고, 스크린샷·서신만으로는 절대 증명이 될 수 없다" | [channelinsider.com](https://www.channelinsider.com/channel-business/channel-analysis/delve-ai-compliance-scandal-vendor-risk/) (2026-08-21, 업계 미디어 — 근거등급 중) |
| TPRM(벤더 리스크) 실무 시사점 | "TPRM 프로세스가 SOC2 보고서를 깊은 검증 없이 '준수 증명'으로 그냥 받아들인다면, Delve 사건이 바로 그 신뢰가 어떻게 조작될 수 있는지 보여주는 실증 사례다" | [whistic.com](https://www.whistic.com/resources/blog/your-vendor-has-a-soc-2-report-now-what) (2026-08-21, TPRM 벤더 블로그 — 근거등급 중, 자사 툴 세일즈 목적 있음) |
| 신뢰 붕괴의 근본 원인 진단 | "벤더는 자신을 최대한 좋게 보이려는 유인이 항상 있고, 바이어는 그 주장을 검증할 신뢰할 만한 방법이 거의 없다" | [visotrust.com](https://visotrust.com/resources/delve-ai-compliance/) (2026-08-21) |

**해석**: 업계가 등을 돌린 지점은 "AI를 썼다"가 아니라 "검사(테스트) 전에 결론을 써놓았다"·"감사인 독립성이 깨졌다"·"통계적으로 불가능할 만큼 완벽한(사고 0건) 결과를 의심 없이 냈다"는 3가지다. AI 자체에 대한 전면 거부라기보다, **"검증되지 않은 결론을 자동화가 대량 생산했을 때"** 에 대한 거부다.

### Q3. 벤더의 "자기신고(self-attested) 스캔 결과"를 바이어 보안검토가 수용하는 관행이 있는가?

**답: 있다 — 다만 2026년 들어 "자기신고만으로는 부족하다"는 쪽으로 확실히 이동 중이다. 그리고 감사인과 일반 바이어 보안검토는 기준이 다르다.**

- **관행은 실재한다**: 기술 바이어들은 인수·실사 과정에서 SOC2 보고서·침투테스트 요약본·보안 설문을 정적 문서 형태로 관례적으로 수용해 왔고, 거래 종결 시점에는 이미 수개월~수년 지난 자료인 경우가 흔하다. [Holland & Knight (법률자문사, 근거등급 높음 — 실무 법률 인사이트)](https://www.hklaw.com/en/insights/publications/2026/07/rethinking-risk-assessments-for-tech-transactions) (2026-08-21)
- **SOC2/ISO 인증 자체가 이미 "질문 생략권"으로 통용된다**: 현재 SOC2 Type II나 ISO27001 인증을 보유한 벤더는 개별 문항에 답하는 대신 인증서를 근거로 보안 설문의 상당 부분을 대체할 수 있다 — SOC2가 "감사인이 독립적으로 검증한 증거"라는 전제 위에서다. [Kodem Security(보안 벤더 블로그, 근거등급 중)](https://www.kodemsecurity.com/resources/the-vendor-security-questionnaire-playbook-turning-appsec-data-into-sales-velocity) (2026-08-21)
- **그러나 추세는 "증거 요구"로 이동 중**: 같은 출처가 "정책 자기신고(policy attestation)는 이제 최소 기준(table stakes)일 뿐이고, 거래를 가르는 질문은 '실제 라이브 환경에서 뽑은 증거'를 요구하는 질문"이라고 명시한다. SBOM만으로는 "실제로 어떤 컴포넌트가 로드돼 있고, 도달 가능하고, 고객 데이터 경로에 관여하는지"를 증명하지 못한다고 지적한다. [Kodem Security](https://www.kodemsecurity.com/resources/the-vendor-security-questionnaire-playbook-turning-appsec-data-into-sales-velocity) (2026-08-21)
- **감사인 관점에서는 원시 스캔 결과(raw scan output)조차 그대로 신뢰받지 못한다**: "감사인은 대개 원시 스캔 결과를 거부한다 — 취약점이 실제로 악용 가능하다는 것을 명시적으로 입증하고, 스크린샷·요청 트레이스 같은 검증 가능한 증거를 제시하지 않는 한." 감사 대응용 증거는 악용가능성 증명·프레임워크 통제 매핑·재현 가능성·조치 전후 비교까지 갖춰야 한다. [pentest-tools.com(벤더, 근거등급 중 — 그러나 이 특정 진술은 감사 실무 상식과 일치)](https://pentest-tools.com/usage/compliance-white-paper) (2026-08-21)
- **AI 관련 문항은 이미 설문 표준에 편입됐다**: 기업 바이어들의 CAIQ·SIG Lite 등 표준 벤더리스크 설문에 AI 전용 섹션이 추가돼, 모델 출처(provenance)·학습데이터 권리·프롬프트 인젝션 방어·환각 통제 같은 질문이 2023년에는 없었지만 지금은 표준 항목이 됐다. [업계 정리(근거등급 중 — 개별 원출처 미상, 교차확인 권장)](https://securityboulevard.com/2026/04/ai-security-questionnaires-why-most-startups-fail-and-the-trust-stack-that-fixes-it/) (2026-08-21)

**해석**: "자기신고 문서 = 통용됨"과 "AI가 그 문서를 대신 써줌 = 신뢰 하락"은 서로 다른 축이다. Q3의 답은 조건부다 — 자기신고 관행 자체는 여전히 존재하지만, **누가·어떻게 그 문서를 만들었는지에 대한 검증 요구가 2026년 들어 뚜렷이 강화**됐고, 그 검증 요구를 촉발한 대표 사건이 바로 Delve다.

### Q4. 종합 판정 — "스캐너 실행 결과 정리 + 명시적 한계 고지" 포지셔닝이 이 불신을 피해 가는가?

**판정: 조건부로 "그렇다."** 근거는 세 갈래다.

1. **Delve의 실패 지점과 AgentTrust v2의 설계가 정반대에 있다.** Delve는 "테스트를 하기도 전에 결론(감사의견)을 써놓았다"는 점, "감사인 독립성을 위반했다"는 점, "통계적으로 불가능한 완벽한 결과(사고 0건)를 의심 없이 냈다"는 점 때문에 무너졌다 [compliancehub.wiki](https://compliancehub.wiki/delve-compliance-startup-fake-soc2-audit-scandal/) (2026-08-21). AgentTrust v2가 "스캐너가 실제로 찾은 설정 항목만 나열하고, 스캐너가 보지 못한 영역은 명시적으로 '커버리지 밖'이라고 고지한다"는 설계를 지키는 한, 이 세 실패 지점 중 어느 것도 반복하지 않는다.
2. **"자동화가 어디까지 돕고 어디부터 못 돕는지 정확히 구분하라"는 것이 업계가 요구하는 정확한 조건이다.** Rafter의 분석은 "자동화가 도움되는 영역(증거 수집, 통제 모니터링)과 그렇지 않은 영역(독립적 평가, 전문가 판단)을 정확히 구분해야 한다"고 명시한다 [rafter.so](https://rafter.so/blog/delve-scandal-fake-soc2-compliance-theater) (2026-08-21). AgentTrust v2의 "커버리지 한계가 명시된 설정 소견서"라는 표현 자체가 이 조건을 문자 그대로 충족한다.
3. **다만 "raw output이면 무조건 신뢰받는다"는 순진한 결론은 아니다.** 감사인 관점에서는 원시 스캔 결과조차 악용가능성 증명·재현성 메타데이터(스캐너 버전, 취약점 DB 최신성, 스캔 시각) 없이는 "감사증거"로 인정받지 못한다 [pentest-tools.com](https://pentest-tools.com/usage/compliance-white-paper) (2026-08-21), [github.com/in-toto/attestation](https://github.com/in-toto/attestation/blob/main/spec/predicates/vuln.md) (2026-08-21, 기술표준 원문). 즉 AgentTrust는 **"공식 SOC2 감사증거"를 자처하면 안 되고**, "감사 준비 전 단계의 자가진단/갭 리포트"로 스코프를 명확히 좁혀야 신뢰를 얻는다.

**추가로 발견한 리스크(질문에 없었지만 R5와 직결)**: MCP 서버 설정을 스캔하는 오픈소스 도구가 이미 여럿 존재한다 — `mcp-audit`(Apache 2.0, 무료), `agent-audit`(MIT, OWASP Agentic AI Top 10에 매핑), Snyk의 `agent-scan`(엔터프라이즈 벤더). [github.com/piiiico/agent-audit](https://github.com/piiiico/agent-audit) (2026-08-21), [mcp-audit.dev](https://mcp-audit.dev/) (2026-08-21), [github.com/snyk/agent-scan](https://github.com/snyk/agent-scan) (2026-08-21). AgentTrust v0(오픈소스 CLI 단독)는 이미 이 무료 대안들과 직접 경쟁하는 포지션이었다는 뜻이며, v2가 "소견서+한계고지"라는 신뢰 축으로 차별화하려는 방향은 이 경쟁구도에서도 유효한 선택으로 보인다(단, 경쟁 심화는 이 리포트 범위 밖이라 판정하지 않는다).

**PRD에 반영할 문구/조건 제안**:
- 절대 쓰지 말 것: "인증(certified)", "감사 통과(audit-passed)", "컴플라이언스 완료(compliant)", "SOC2 준비 완료" — 이 단어들은 자격 있는 CPA·감사기관의 영역이며, 이 경계를 넘는 순간 Delve와 동일한 비판(자격 사칭)을 받는다.
- 반드시 쓸 것: "스캐너가 검사한 항목 목록"과 "스캐너가 검사하지 않은 항목 목록"을 같은 화면/같은 문서에 나란히 표기. IANS·Rafter·Whistic 세 출처 모두 "무엇을 안 봤는지 밝히지 않는 것"을 신뢰 붕괴의 공통 원인으로 지목했다.
- 재현성 메타데이터를 항상 동봉: 스캐너 버전, 스캔 시각, 스캔 대상 파일 해시 — "그 결과가 언제·무엇을·어떤 도구로 봤는지"를 독자가 직접 재현할 수 있게. (감사증거 표준의 최소 요건과 일치)
- 포지셔닝 용어로 "감사 리포트(audit report)"가 아니라 "설정 소견서(configuration advisory)" 또는 "갭 진단서(gap diagnostic)"를 유지 — 이는 이미 v2 방향과 일치하며 근거로 뒷받침됐다.

---

## 미확인 사항 (추측 대신 명시)

- A-LIGN·Prescient Assurance가 "AI 생성 증적"에 대해 발표한 **자체 공식 정책 문서**는 찾지 못했다. 위 서술은 모두 3자 정리 사이트 기반이며 원문 정책 문서 링크는 확인되지 않았다.
- Big4(4대 회계법인) 중 어느 한 곳이라도 "AI 생성 컴플라이언스 답변을 감사 증거로 받지 않는다"는 **명시적 공개 성명**을 냈는지는 확인하지 못했다. 위에 인용한 것은 "그들 자신도 AI로 사고를 냈다"는 정황 증거이지, 정책 선언이 아니다.
- Y Combinator의 Delve 퇴출 발표 원문(공식 YC 채널)은 직접 접근하지 못했다 — 위 내용은 경쟁 벤더(visotrust) 정리 글을 경유한 재인용이라 근거등급이 낮다. 교차 검증 권장.
- 바이어 GRC팀이 "AI 생성 여부"만을 이유로 스캔 결과를 정식으로 거부한 구체 사례(기업명·날짜 특정)는 찾지 못했다 — 지금까지의 반응은 전부 Delve라는 특정 사건에 대한 반응이지, "AI가 만든 산출물 일반"에 대한 별도 거부 사례가 아니다.

---

## 출처 목록 (근거등급 표기)

| 등급 | 의미 |
|---|---|
| **표준/법률** | 회계기준·법률자문사 등 1차에 가까운 근거 |
| **애널리스트** | 보안·리서치 전문기관의 분석 |
| **업계미디어** | 뉴스/미디어 성격 정리 기사 |
| **벤더블로그** | 경쟁·인접 제품을 파는 회사의 자사 블로그(세일즈 목적 내재 — 교차검증 권장) |
| **기술표준** | 오픈소스/기술 표준 원문 |

1. [CalCPA — AI Standard Setting, Regulation in Audit: Part 1](https://www.calcpa.org/whats-happening/articles/ai-standard-setting-regulation-in-audit-part-1) — 표준/법률(2차 정리) — 2026-08-21 접근
2. [Captain Compliance — The Delve Scandal](https://captaincompliance.com/news/the-delve-scandal-fake-soc-2-audits-open-source-code-theft-and-exit-from-y-combinator/) — 업계미디어 — 2026-08-21 접근
3. [byteiota — Delve Compliance Fraud: $32M Startup Faked 494 SOC 2 Audits](https://byteiota.com/delve-compliance-fraud-32m-startup-faked-494-soc-2-audits/) — 업계미디어 — 2026-08-21 접근
4. [ComplianceHub.Wiki — The Delve Scandal](https://compliancehub.wiki/delve-compliance-startup-fake-soc2-audit-scandal/) — 업계미디어 — 2026-08-21 접근
5. [VISO TRUST — The Delve AI Compliance Scandal](https://visotrust.com/resources/delve-ai-compliance/) — 벤더블로그(경쟁 성격) — 2026-08-21 접근
6. [IANS Research — Delve Allegations Expose Weak Points in Modern Compliance](https://www.iansresearch.com/resources/all-blogs/post/security-blog/2026/04/19/delve-allegations-expose-weak-points-in-modern-compliance) — 애널리스트 — 2026-08-21 접근
7. [ChannelInsider — Delve Compliance Scandal Exposes AI Vendor Risk Gaps](https://www.channelinsider.com/channel-business/channel-analysis/delve-ai-compliance-scandal-vendor-risk/) — 업계미디어 — 2026-08-21 접근
8. [Holland & Knight — Rethinking Risk Assessments for Tech Transactions and M&A](https://www.hklaw.com/en/insights/publications/2026/07/rethinking-risk-assessments-for-tech-transactions) — 법률자문사(근거등급 높음) — 2026-08-21 접근
9. [Rafter — Strategic Insight: The Delve Scandal and Compliance Theater](https://rafter.so/blog/delve-scandal-fake-soc2-compliance-theater) — 벤더블로그(경쟁 성격) — 2026-08-21 접근
10. [Whistic — Your Vendor Has a SOC 2 Report. Now What?](https://www.whistic.com/resources/blog/your-vendor-has-a-soc-2-report-now-what) — 벤더블로그(TPRM 툴 세일즈 목적) — 2026-08-21 접근
11. [Big4News — The Hallucination Trap](https://www.big4news.com/p/the-hallucination-trap) — 업계미디어(뉴스레터) — 2026-08-21 접근
12. [Kodem Security — The Vendor Security Questionnaire Playbook](https://www.kodemsecurity.com/resources/the-vendor-security-questionnaire-playbook-turning-appsec-data-into-sales-velocity) — 벤더블로그 — 2026-08-21 접근
13. [Pentest-Tools.com — Audit-ready Compliance Evidence](https://pentest-tools.com/usage/compliance-white-paper) — 벤더블로그(단, 감사 실무 상식과 일치) — 2026-08-21 접근
14. [in-toto/attestation — vuln.md 스펙](https://github.com/in-toto/attestation/blob/main/spec/predicates/vuln.md) — 기술표준 원문 — 2026-08-21 접근
15. [soc2auditors.org — SOC 2 Auditors for AI Companies 2026](https://soc2auditors.org/soc-2-auditors-ai/) — 벤더블로그(정리 성격) — 2026-08-21 접근
16. [Security Boulevard — AI Security Questionnaires: Why Most Startups Fail](https://securityboulevard.com/2026/04/ai-security-questionnaires-why-most-startups-fail-and-the-trust-stack-that-fixes-it/) — 업계미디어 — 2026-08-21 접근
17. [GitHub — piiiico/agent-audit](https://github.com/piiiico/agent-audit) — 기술표준/오픈소스 원문 — 2026-08-21 접근
18. [mcp-audit.dev](https://mcp-audit.dev/) — 벤더블로그(오픈소스 제품 소개) — 2026-08-21 접근
19. [GitHub — snyk/agent-scan](https://github.com/snyk/agent-scan) — 기술표준/오픈소스 원문 — 2026-08-21 접근

---

## 남은 조사 과제 (이번 범위 밖)

- A-LIGN·Prescient Assurance 등 개별 감사법인의 **1차 공식 정책 문서**(사이트 직접 확인) — 시간 제약으로 3자 정리 사이트만 확인.
- YC의 Delve 퇴출 공식 성명 원문.
- MCP 스캐너 경쟁구도(agent-audit·mcp-audit·Snyk agent-scan 등)의 가격/포지셔닝 상세 비교 — R5 리스크와는 별개 축(경쟁 밀도)이라 이번 리포트 범위에서 제외.
