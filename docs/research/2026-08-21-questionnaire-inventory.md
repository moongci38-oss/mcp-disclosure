# 실물 AI 보안 질문지 인벤토리 — "38문항 중 12개" 가정 검증

> 작성일 2026-08-21 · 작성 배경: codex 적대적 검수가 "베타 게이트를 인터뷰 진술이 아니라 실제 질문지 + 바이어 수용 확인으로 격상하라"고 지적했고, 이 문서는 그 첫 단추 — **2차 인용("38문항이라더라")만 있던 상태에서 실물 문항지를 직접 구해온 결과**다.

## 결론부터 (쉽게 요약)

시험 문제를 소문으로만 듣다가, 이번에 실제 시험지를 구해서 채점기준표까지 만든 격입니다. 결과는 두 갈래로 갈렸습니다.

- **실물 질문지 4건을 확보**했습니다(전부 원문 그대로, 링크 접속·원문 대조까지 마침). 총 126문항.
- 그중 하나(우리가 기존 PRD에서 "38문항"이라 인용해온 그 DeepInspect 질문지)를 다시 세어보니, **설정/코드 스캔만으로 답할 수 있는 문항이 12개가 아니라 약 22개(38개 중 58%)**였습니다. 기존 가정은 실물보다 **과소평가**되어 있었습니다 — 나쁜 소식이 아니라 좋은 소식 쪽입니다.
- 하지만 **더 중요한 반전**이 있습니다. 같은 종류(벤더 마케팅 블로그가 만든 "AI 벤더 질문지") 3건은 전부 스캔 가능 비중이 51~58%로 높았는데, **실제 기업(마이크로소프트)이 공급업체에 요구하는 진짜 조달 문서(SSPA Section K)** 하나를 구해서 세어보니 **스캔으로 답할 수 있는 문항이 18개 중 0개**였습니다. 전부 "정책 문서를 보여달라" 또는 "그 활동을 실제로 했다는 걸 증명하라"는 유형이었습니다.
- 즉, **"몇 %를 스캔으로 답할 수 있나"라는 질문 자체가 "어떤 질문지를 받느냐"에 달려 있습니다.** 마케팅 성격 질문지를 받으면 스캔 자동응답이 많이 통하고, 실제 기업 감사·조달 질문지를 받으면 거의 안 통합니다 — 이 구분을 PRD의 클레임 온톨로지에 반드시 반영해야 합니다.

---

## 1. 확보 현황 요약표

| # | 질문지 | 발행처 | 발행일 | 문항수 | 공개 여부 | 접근일 | 원문 대조 |
|---|---|---|---|---|---|---|---|
| 1 | AI Vendor Security Questionnaire: 38 Questions | DeepInspect Inc. (Parminder Singh) | 2026-08-18 | 38 | 완전 무료(게이트 없음) | 2026-08-21 | raw HTML 대조 완료, 100% 일치 |
| 2 | AI Vendor Due Diligence Checklist: 30 Questions Your SIG and CAIQ Miss | DeepInspect Inc. (Parminder Singh) | 2026-08-18 | 30 | 완전 무료(게이트 없음) | 2026-08-21 | raw HTML 대조 완료, 100% 일치 |
| 3 | AI Vendor Security Questionnaire: 40 Questions to Assess Any AI Vendor | Reco AI (Gal Nakash) | 2026-07-15 | 40 | 완전 무료(게이트 없음) | 2026-08-21 | raw HTML 대조 완료, 100% 일치 |
| 4 | Microsoft Supplier Data Protection Requirements — Section K: AI Systems | Microsoft Corp. (SSPA 프로그램) | 2025-04 (v11) | 18 (AI 전용, 전체 67개 요건 중) | 완전 무료 PDF(게이트 없음, 직접 다운로드) | 2026-08-21 | 원본 PDF 27p 직접 열람 |
| **합계** | | | | **126** | | | |

**미확보(2차 인용과 구분)**

| 후보 | 상태 | 사유 |
|---|---|---|
| CSA AI-CAIQ (AI Consensus Assessments Initiative Questionnaire) v1.0.2 | **미확보 — 구조만 확인** | 페이지 자체는 "계정 없이 다운로드 가능"이라 표기하나, 실제 다운로드 링크가 정적 HTML에 없고 클라이언트 렌더링(JS)로만 노출됨 — 정적 fetch로 원문 미회수. 페이지에 실린 예시 2문항만 확보: "Establish audit policies"(통제 명세), "Are audit policies reviewed annually?"(자가평가 질문 예시). 공개 검색 결과상 v1.1은 320문항·18개 도메인이라는 2차 수치만 확인(원문 미검증). |
| OneTrust "Questions to Add to Existing Vendor Assessments for AI Checklist" | **미확보 — 게이트드** | 이름·이메일·회사명 등 리드젠 폼 제출 전에는 문항 비공개. |
| Georgia GS-25-002 (주정부 AI 조달 가이드라인) | **미확보 — 문항지 형식 아님** | 실물 질문 목록이 아니라 기관(agency)이 RFP를 작성할 때 참고하는 "가이드라인" 문서. 발주기관마다 문항을 직접 만들어 쓰라는 지침이지, 그 자체가 배포 가능한 질문 목록이 아님 — 장르가 다르므로 인벤토리에서 제외. |

---

## 2. 질문지별 문항 전수 표 (원문 + 한국어 + 분류)

**분류 기준**
- **(A) 설정/코드 스캔** — 배포된 설정 파일·IAM 정책·모델 라우팅 표·연결된 MCP 서버/도구 목록·감사로그 스키마·fail-open/closed 플래그처럼, 시스템을 들여다보면 값이 바로 나오는 구조화된 사실.
- **(B) 정책 문서** — 계약 조항·DPA·BAA·라이선스·보존정책·인시던트 대응계획서처럼, "문서 한 장을 꺼내 보여주면" 답이 되는 것.
- **(C) 조직 프로세스 진술** — 교육 주기·레드팀을 실제로 했는지·사고 중 실시간 공조·거버넌스 담당자 지정처럼, 스캔도 문서 한 장도 아니고 "그 활동을 실제로 수행하고 있다"는 진술/증빙이 필요한 것.

### 2-1. DeepInspect — 38 Questions (7개 카테고리)

출처: https://www.deepinspect.ai/blog/ai-vendor-security-questionnaire (2026-08-18 발행, 2026-08-21 접근, 완전 무료)

**Category 1: Model coverage and isolation (모델 커버리지·격리)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 1 | Which model providers and which specific model versions does the service call? | 서비스가 호출하는 모델 제공사와 정확한 모델 버전은? | A | 모델 라우팅 설정/환경변수에 그대로 찍혀 있는 값 |
| 2 | How does the vendor pin model versions and notify customers of model changes? | 모델 버전을 어떻게 고정하고, 변경 시 고객에게 어떻게 통지하는가? | C | "고정" 자체는 설정값이지만 실질 쟁점은 "통지 의무 이행"이라는 진행형 약속 — 스캔으로 확인 불가 |
| 3 | What contractual terms with the model provider prevent customer data from being used for model training? | 모델 제공사와의 계약 중 학습 금지 조항은? | B | 계약서 조항을 꺼내 보여줘야 함 |
| 4 | Are customer prompts and responses subject to the model provider's retention? | 프롬프트·응답이 모델 제공사 보존정책 대상인가? | B | 제공사 DPA/약관 문서 확인 필요 |
| 5 | How does the vendor isolate tenants at the model call layer? | 모델 호출 계층의 테넌트 격리 방식은? | A | 시크릿관리/IaC 설정(전용 키 vs 공유 키)로 직접 관측 가능 |
| 6 | Can the customer route AI traffic through the customer's own provider account? | 고객 자신의 제공사 계정으로 라우팅 가능한가? | A | Y/N 제품 기능 플래그 |

**Category 2: Identity and authorization (신원·인가)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 7 | How does the service receive and verify the end-user identity making a request? | 요청자 신원을 어떻게 수신·검증하는가? | A | 인증 프로토콜(OIDC/SAML/API키) 설정값 |
| 8 | What identity attributes are available for policy decisions? | 정책 판단에 쓰는 신원 속성은? | A | 클레임 스키마 — 코드/설정에서 열거 가능 |
| 9 | How does the vendor enforce least privilege at the AI request layer? | 최소권한 원칙을 어떻게 강제하는가? | A | RBAC/정책엔진 설정 |
| 10 | How does the service handle service-account and agent identities? | 서비스계정·에이전트 신원 처리 방식은? | A | 신원 모델 코드/설정에서 확인 |
| 11 | What is the authentication mechanism between the customer application and the service? | 고객앱-서비스 간 인증 방식은? | A | 프로토콜명(mTLS/OAuth2 등) — 설정값 |
| 12 | How are administrative actions on the vendor's service authenticated and audited? | 관리자 작업 인증·감사 방식은? | A | MFA 여부·감사로그 존재 여부 — 설정 확인 |

**Category 3: Per-decision audit and traceability (건별 감사·추적성)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 13 | For each AI request, what is captured in the audit record? | 요청 1건당 감사기록에 남는 항목은? | A | 로그 스키마 — 코드에서 직접 확인 |
| 14 | Are the audit records tamper-evident? | 감사기록의 위변조 탐지 가능 여부는? | A | 서명/해시체인 메커니즘 존재 여부 — 코드 확인 |
| 15 | Who has write access to the audit records? | 감사기록 쓰기 권한 보유자는? | A | IAM 정책 — 설정 확인 |
| 16 | How long are audit records retained, and who controls the retention period? | 보존기간·통제주체는? | A | 보존 설정값(일수) |
| 17 | Can the customer export the raw audit records? | 원본 감사기록 내보내기 가능한가? | A | Y/N 기능 존재 여부 |
| 18 | Does the audit record include the policy state at the moment of the decision? | 감사기록에 결정시점 정책상태 포함되는가? | A | 스키마 필드 존재 여부 |

**Category 4: Policy enforcement and prompt-injection handling (정책 집행·프롬프트 인젝션 대응)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 19 | What policy primitives does the service expose? | 제공하는 정책 구성요소는? | A | 정책엔진 API/스키마 열거 |
| 20 | How does the service handle policy ambiguity or evaluation failure? | 정책 평가 실패 시 처리방식(fail-open/closed)은? | A | 설정 플래그 — 원문 기사도 "스캔 가능 4대 증거" 중 하나로 명시 |
| 21 | How does the service detect and respond to prompt injection? | 프롬프트 인젝션 탐지·대응 방식은? | B | 탐지기 존재 자체는 코드로 보이지만 "탐지+정책+감사 3단 대응"의 충분성은 설계문서로만 확인 가능 |
| 22 | How does the service handle indirect prompt injection in retrieved content? | 검색콘텐츠 내 간접 인젝션 처리방식은? | B | 위와 동일 — 방어설계 문서 필요 |
| 23 | What is the latency overhead of the policy enforcement? | 정책집행 지연시간 오버헤드는? | C | 벤치마크를 실제로 돌려 측정·보고해야 나오는 수치 — 정적 스캔 불가 |
| 24 | Can the customer bring its own policy? | 고객 자체 정책 반입 가능한가? | A | Y/N API 기능 |

**Category 5: Data residency and processing locations (데이터 거주지)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 25 | In which geographies is the customer data processed? | 데이터 처리 지역은? | A | 인프라 배포 설정 |
| 26 | Can the customer pin processing to a specific region? | 특정 리전 고정 가능한가? | A | 리전 고정 기능 설정 |
| 27 | Does the model provider's data processing also stay in the pinned region? | 모델 제공사 처리도 고정 리전 내에 머무는가? | B | 벤더 자체 설정을 넘어 제3자(모델 제공사)의 리전 공약 문서까지 필요 |
| 28 | What is the data classification taxonomy the service applies to prompts and responses? | 적용하는 데이터 분류체계는? | A | 분류 스키마 코드에서 열거 |
| 29 | How does the service handle data subject rights under GDPR for prompts that contain personal data? | GDPR 정보주체 권리 처리방식은? | B | 정보주체 요청 처리 절차 문서 필요 |

**Category 6: Regulatory alignment (규제 정합성)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 30 | How does the service support EU AI Act Article 12 traceability? | EU AI Act 제12조 추적가능성 지원 방식은? | A | 이미 스캔된 감사/보존 설정을 그대로 재사용해 답변 가능 |
| 31 | How does the service support HIPAA audit requirements for AI-mediated decisions on PHI? | PHI 관련 HIPAA 감사요건 지원 방식은? | B | BAA 문서 필요 |
| 32 | How does the service support the NIST AI Risk Management Framework? | NIST AI RMF 지원 방식은? | B | 기능-프레임워크 매핑 문서(거버넌스 문서) 필요 |
| 33 | How does the service support Fannie Mae LL-2026-04 governance requirements for AI-supported lending decisions? | Fannie Mae LL-2026-04 거버넌스 요건 지원 방식은? | B | 거버넌스 매핑 문서 필요 |
| 34 | What is the vendor's position on state-level AI legislation (Colorado SB 189, Texas TRAIGA, California SB 942)? | 주(州) AI 입법에 대한 입장은? | C | 법적 해석·입장 표명 — 스캔·단일 문서로 안 나오는 조직 판단 |

**Category 7: Incident response (사고 대응)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 35 | What is the vendor's incident response process for an AI-layer compromise? | AI계층 침해 시 사고대응 절차는? | B | 서면 IR 계획서 제출로 답변 가능 |
| 36 | How is the customer notified of an incident affecting the customer's data or workloads? | 사고 발생 시 고객 통지 방식은? | B | 계약상 SLA 조항 |
| 37 | How does the vendor coordinate with the customer's SOC during an incident? | 사고 중 고객 SOC와의 공조 방식은? | C | 실제 사고 발생 시의 실시간 협업 행위 — 사전 문서만으로 검증 불가 |
| 38 | What is the vendor's process for post-incident review and customer post-mortem? | 사고 후 검토·포스트모템 작성 절차는? | B | 포스트모템 문서 산출물로 답변 가능 |

**소계**: A 22 · B 12 · C 4 (합 38)

### 2-2. DeepInspect — 30 Questions Your SIG and CAIQ Miss (6개 카테고리)

출처: https://www.deepinspect.ai/blog/ai-vendor-due-diligence-checklist (2026-08-18 발행, 2026-08-21 접근, 완전 무료)
※ 검색엔진 스니펫에는 구 제목 "27 Questions"로 캐시되어 있었으나, 2026-08-21 원문 재확인 결과 실제 게시본은 "30 Questions"로 갱신되어 있었다 — 2차 인용("27문항")과 실물("30문항")이 다를 수 있다는 것 자체가 이번 조사의 취지를 보여주는 사례다.

**Model provenance (모델 출처, 1-5)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 1 | Which models does the product use, and from which provider? | 사용 모델과 제공사는? | A | 모델 카탈로그 설정 |
| 2 | Where does the model run? | 모델 구동 지역은? | A | 리전 설정 |
| 3 | Does the vendor train models on customer data? | 고객 데이터로 학습시키는가? | B | 학습데이터 정책 문서(원문: "artifact is the training-data policy") |
| 4 | Does the vendor use the model provider's API in a mode that excludes customer data from training? | 학습 제외 API 모드를 쓰는가? | B | API 계약/제공사 공식 성명 필요 |
| 5 | What is the model's failover provider? | 장애조치 대체 제공사는? | A | 라우팅 설정(primary/failover) |

**Identity and access (신원·접근, 6-11)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 6 | How does the vendor identify the calling user inside each AI request? | 요청 내 호출자 식별 방식은? | A | 신원 전파 설정/코드 |
| 7 | How does the vendor identify agents distinct from users? | 사용자와 구분되는 에이전트 식별 방식은? | A | 신원 스키마 |
| 8 | Does the vendor support SSO with the customer's IdP for the AI-using surface? | AI 기능에 SSO 지원하는가? | A | Y/N 설정 |
| 9 | Does the vendor support SCIM provisioning for the AI-using roles? | SCIM 프로비저닝 지원하는가? | A | Y/N 설정 |
| 10 | How does the vendor handle service accounts and machine identities? | 서비스계정·머신 신원 처리방식은? | A | IAM 설정 |
| 11 | Does the vendor allow customer-side identity binding to AI requests? | 고객측 신원 바인딩 허용하는가? | A | 통합 기능 존재 여부 |

**Data flow and classification (데이터 흐름·분류, 12-17)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 12 | What categories of customer data does the AI capability send to the model? | 모델로 보내는 데이터 범주는? | A | 데이터흐름/DLP 분류 설정 |
| 13 | Does the vendor classify data before sending it to the model? | 전송 전 분류하는가? | A | 분류기 존재 여부 — 코드 확인 |
| 14 | Can the vendor redact sensitive fields before the model sees them? | 민감필드 마스킹 가능한가? | A | 마스킹 기능/설정 |
| 15 | Does the vendor support customer-managed redaction policies? | 고객관리형 마스킹 정책 지원하는가? | A | Y/N 기능 |
| 16 | What happens to the data inside the model provider's pipeline? | 제공사 파이프라인 내 데이터 처리는? | B | 제공사 DPA 문서 필요(원문 명시) |
| 17 | Does the vendor support data-residency constraints on the AI capability? | 데이터 거주지 제약 지원하는가? | A | 리전 고정 기능 |

**Logging and audit (로깅·감사, 18-22)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 18 | What audit fields does the vendor record per AI decision? | 결정별 기록 감사필드는? | A | 로그 스키마 |
| 19 | How long does the vendor retain the AI-decision audit? | 감사기록 보존기간은? | A | 보존 설정값 |
| 20 | Can the customer export the AI-decision audit? | 감사기록 내보내기 가능한가? | A | Y/N 기능 |
| 21 | Does the vendor sign the audit records? | 감사기록에 서명하는가? | A | 서명 메커니즘 코드 확인 |
| 22 | How does the vendor link a model output back to the inputs that produced it? | 출력→입력 역추적 방식은? | A | 트레이스ID 스키마 |

**Regulatory mapping (규제 매핑, 23-27)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 23 | Does the vendor classify any of its AI capabilities as high-risk under the EU AI Act? | EU AI Act 고위험 분류 기능이 있는가? | B | 위험분류 판정문서 |
| 24 | Has the vendor completed a fundamental rights impact assessment (FRIA) for its high-risk capabilities? | FRIA를 완료했는가? | B | FRIA 평가서(원문: "artifact is the assessment") |
| 25 | Does the vendor map its AI capabilities to NIST AI RMF functions? | NIST AI RMF에 매핑하는가? | B | 매핑 문서 |
| 26 | Does the vendor sign a BAA for AI capabilities that touch PHI? | PHI 다루는 기능에 BAA 체결하는가? | B | BAA 계약서 |
| 27 | What is the vendor's incident-disclosure posture for AI-related incidents? | AI 사고 공개 방침은? | B | 인시던트대응 정책서(원문 명시) |

**AI supply chain (AI 공급망, 28-30)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 28 | Does the vendor disclose the fourth parties behind its own AI calls? | AI 호출 뒤의 4차 공급자를 공개하는가? | A | 하위처리자 목록 — 구조화된 레지스트리(도구 레지스트리와 동일 성격) |
| 29 | If the vendor fine-tunes or self-hosts an open-weight model, what is the training-data provenance and license? | 오픈웨이트 모델 사용 시 학습데이터 출처·라이선스는? | B | 모델카드+라이선스 문서 |
| 30 | Can the vendor name every tool, plugin, or retrieval source the model is allowed to call? | 모델이 호출 가능한 모든 도구·플러그인·검색소스를 특정할 수 있는가? | A | 도구 레지스트리 — MCP 서버/도구 연결 목록과 동일한 유형(AgentTrust 스캔의 전형적 예) |

**소계**: A 21 · B 9 · C 0 (합 30)

### 2-3. Reco AI — 40 Questions to Assess Any AI Vendor (6개 도메인)

출처: https://www.reco.ai/ciso-hub/ai-vendor-security-questionnaire (2026-07-15 발행, Gal Nakash, 2026-08-21 접근, 완전 무료)

**DOMAIN 1: Data Handling and Retention (1-7)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 1 | What customer data does your product send to an LLM, and is it your model or a third party's? | LLM으로 보내는 데이터와 자체/제3자 모델 여부는? | A | 데이터흐름/모델라우팅 설정 |
| 2 | How long are prompts, outputs, and embeddings retained, and can we set retention to zero? | 보존기간과 0설정 가능 여부는? | A | 보존설정값 |
| 3 | Is our data logically or physically isolated from other tenants at the model layer? | 모델계층 테넌트 격리 여부는? | A | 인프라 설정(전용/공유) |
| 4 | Can we exclude specific data classes (PII, PHI, source code) from AI processing? | 특정 데이터 범주 제외 가능한가? | A | 필터링 설정 |
| 5 | Where is inference performed geographically, and can we pin it to a region? | 추론 지역과 리전 고정 가능 여부는? | A | 리전 설정 |
| 6 | What happens to derived artifacts (embeddings, summaries, indexes) when we terminate? | 종료 시 파생 산출물 처리는? | B | 데이터 폐기 정책 문서 |
| 7 | Do human reviewers ever see our prompts or outputs, and under what circumstances? | 사람 검토자 열람 여부·조건은? | B | 인간검토 정책 문서 |

**DOMAIN 2: Model Training and Improvement (8-12)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 8 | Is customer data used to train, fine-tune, or evaluate any model, yours or a third party's? | 학습·파인튜닝·평가에 데이터 사용하는가? | B | 학습데이터 정책 문서 |
| 9 | If training on customer data is opt-in, is the opt-in contractual or a UI toggle any admin can flip? | 옵트인이 계약 보장인가 UI 토글인가? | B | 계약보장 여부가 핵심 쟁점 — 계약서 확인 필요 |
| 10 | How do you prevent our data from appearing in another customer's outputs? | 교차테넌트 유출 방지 방식은? | C | 레드플래그가 "교차테넌트 유출 테스트 미실시"로 명시 — 테스트 수행 여부라는 활동 진술 |
| 11 | Do you use our data for "service improvement," and how is that defined? | "서비스개선" 목적 사용·정의는? | B | 용어정의 정책 문서 |
| 12 | When you upgrade or swap the underlying model, do you notify customers before or after? | 모델 교체 시 사전/사후 통지 여부는? | C | 통지 이행이라는 진행형 약속 — 스캔·문서 한 장으로 검증 불가 |

**DOMAIN 3: Access, Identity and Permissions (13-19)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 13 | What is the minimum OAuth scope set your product functions with? | 최소 OAuth 권한범위는? | A | OAuth 스코프 설정 — "에이전트 권한범위"의 전형 |
| 14 | Does the product support read-only or scoped deployment modes for evaluation? | 읽기전용·제한배포 모드 지원하는가? | A | 배포모드 설정 |
| 15 | How are non-human identities (service accounts, keys, tokens) created, rotated, and revoked? | 비인간 신원 생성·순환·폐기 방식은? | A | 시크릿관리 설정 |
| 16 | Can we restrict which users and groups can invoke AI features? | 호출 가능 사용자·그룹 제한 가능한가? | A | RBAC 설정 |
| 17 | Do AI features inherit the invoking user's permissions, or run with elevated service permissions? | 호출자 권한 상속 여부는? | A | 권한모델 코드/설정 |
| 18 | Does the product support SSO and SCIM, and are AI features covered by the same session controls? | SSO·SCIM 지원 및 세션통제 포함 여부는? | A | 설정 확인 |
| 19 | What audit events do you emit for AI actions, and can we stream them to our SIEM? | AI 동작 감사이벤트·SIEM 연동 가능 여부는? | A | 로그스키마+연동기능 |

**DOMAIN 4: Autonomy and Guardrails (20-26)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 20 | Which actions can the product take autonomously versus with human approval? | 자율수행 행동 vs 승인필요 행동 목록은? | A | 승인게이트 설정 — 행동별 자율성 플래그 열거 가능 |
| 21 | Can we require human approval per action type (sending, deleting, purchasing, code execution)? | 행동유형별 승인 요구 가능한가? | A | 승인게이트 설정 |
| 22 | How do you defend against prompt injection and instruction hijacking from untrusted content? | 프롬프트 인젝션·지시탈취 방어 방식은? | B | 방어설계 문서 필요(레드플래그가 "구체적 통제 없음"인지 판단하려면 설계문서 대조 필요) |
| 23 | Are tool calls and external actions sandboxed and rate-limited? | 도구호출·외부행동 샌드박스·속도제한 여부는? | A | 샌드박스/rate-limit 설정 |
| 24 | Can users build their own automations or agents on your product, and can we disable that? | 자체 자동화 생성·비활성화 가능한가? | A | 기능 토글 |
| 25 | Is there a kill switch to halt all autonomous activity immediately, and who can trigger it? | 킬스위치 존재·작동주체는? | A | 기능+RBAC 설정 |
| 26 | How do you log the decision process or tool sequence behind an autonomous action? | 의사결정과정·도구순서 기록 방식은? | A | 트레이스 로그 스키마 |

**DOMAIN 5: Supply Chain and Sub-processors (27-32)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 27 | List every model provider and AI sub-processor in the request path for our data. | 요청경로상 모든 모델제공사·하위처리자 나열 | A | 하위처리자 레지스트리 — 구조화된 목록 |
| 28 | What is your notification window when you add or change an AI sub-processor? | 하위처리자 추가·변경 시 사전통지 기간은? | B | 계약/정책상 통지 SLA |
| 29 | Do plugins, connectors, or marketplace extensions inherit your security guarantees? | 플러그인·확장기능도 동일 보안보증 받는가? | B | 보증범위 정책 명시 문서 |
| 30 | How do you vet third-party integrations before listing them in your ecosystem? | 제3자 통합 검증(vet) 절차는? | C | 검증 활동 자체(자가진술 vs 벤더심사)에 대한 진술 |
| 31 | Which of your certifications (SOC 2, ISO 27001, ISO 42001) cover the AI features specifically? | 보유인증 중 AI 기능 커버 범위는? | B | 인증서·범위기술서 |
| 32 | Have your AI features been independently red teamed or pen tested in the last 12 months? | 최근 12개월 내 독립 레드팀·모의침투 여부는? | C | 활동 수행 여부에 대한 진술·증빙 |

**DOMAIN 6: Incident Response and Accountability (33-40)**

| # | 원문 | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 33 | What is your notification SLA for incidents involving AI processing of our data? | 사고 발생 시 통지 SLA는? | B | 계약 SLA 조항 |
| 34 | Do you classify model-behavior incidents (output leakage, successful injection) as security incidents? | 모델행동 사고를 보안사고로 분류하는가? | B | 사고분류 정책 문서 |
| 35 | Can you reconstruct what an autonomous workflow did during a given time window? | 특정 시간대 자율워크플로우 재구성 가능한가? | A | 로그 보존/상세도 설정 — 실제 재구성 테스트로 검증 가능한 기술역량 |
| 36 | Who is liable when an autonomous action causes damage: you, the model provider, or us? | 손해 발생 시 책임 소재는? | B | 계약 책임조항 |
| 37 | Do you maintain a public trust center or changelog for AI feature changes? | 공개 트러스트센터·변경이력 운영하는가? | A | URL 존재 여부 — 외부에서 직접 관측 가능 |
| 38 | How quickly can you revoke our tenant's access tokens and connections on request? | 접근토큰 폐기 소요시간은? | A | 폐기기능+실측 가능한 기술역량 |
| 39 | Do you carry insurance that covers AI-specific failures? | AI 특유 장애 보장 보험 가입 여부는? | B | 보험증권 문서 |
| 40 | Will you contractually commit to the answers in this questionnaire? | 답변내용을 계약으로 확약할 것인가? | C | 계약체결이라는 조직의 의사결정 행위 — 스캔·기존문서로 안 나옴 |

**소계**: A 22 · B 13 · C 5 (합 40)

### 2-4. Microsoft Supplier Data Protection Requirements — Section K: AI Systems (요건 50-67, 18항목)

출처: https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY25-Microsoft-Supplier-Data-Protection-Requirements-v11_en-US.pdf (Version 11, 2025-04, 2026-08-21 접근, 완전 무료 PDF 27페이지)

> 이 문서는 "질문"이 아니라 "요건(Requirement) + 준수증빙(Evidence of Compliance)" 쌍으로 구성된다. Microsoft가 실제 공급업체에게 매년 자가진술(self-attestation)을 요구하는 현행 조달 문서라, 마케팅 블로그성 질문지 3건과는 성격이 전혀 다르다 — Section A~J(요건 1~49)는 AI와 무관한 일반 SaaS 보안요건("SOC2류 기본형")이고, **AI 특화 요건은 Section K(50~67) 18개뿐**이라 이 표는 그 18개만 다룬다.

| # | 원문(요건 요지) | 한국어 | 분류 | 근거 |
|---|---|---|---|---|
| 50 | Supplier must have applicable AI Systems contractual terms in place; changes to Intended Uses disclosed without undue delay and reviewed annually. | AI 시스템 계약조항을 갖추고 Intended Use 변경을 지체없이 공개, 연 1회 검토 | B | 계약서 자체가 증빙 |
| 51 | Assign responsibility and accountability for the AI System to a designated person or group. | AI 시스템 운영 책임을 특정 담당자/그룹에 지정 | C | 조직 내 역할 지정이라는 거버넌스 사실 — 스캔/단일문서로 검증 어려움 |
| 52 | Establish, maintain, and perform annual privacy/security training for anyone with AI System access. | AI 시스템 접근자 대상 연 1회 개인정보·보안 교육 실시 | C | 교육을 "실제로 실시했는지"에 대한 활동 진술(과제 예시 "사고대응 훈련 주기"와 동일 유형) |
| 53 | AI System incident response plan (customer notification, system rollback, feature kill switch, model update process, change notification). | AI 시스템 사고대응계획(통지·롤백·기능차단·업데이트절차 포함) | B | 서면 IR 계획서 제출로 답변 가능 |
| 54 | Supplier must have Red Teaming of AI Systems; vulnerabilities addressed prior to deployment. | AI 시스템 레드티밍 수행, 배포 전 취약점 해결 | C | 레드팀을 "실제로 했는지" — 활동 수행 여부 진술 |
| 55 | Supplier has a Responsible AI program (parent item, detailed in 56-61). | 책임있는 AI 프로그램 운영(56~61 세부항목) | C | 프로그램 존재·운영이라는 거버넌스 활동 |
| 56 | Supplier has Intended Uses Transparency disclosures. | 의도된 용도 투명성 공시 보유 | B | 공시문서 제출로 답변 가능 |
| 57 | Signed Agreement — explicit contractual terms on data handling, IP, liability, incident response, Sensitive Uses. | 데이터처리·IP·책임·사고대응·민감용도 명시 계약 체결 | B | 계약서 |
| 58 | Accountability — clear lines of accountability for AI deployment/risk management, ethical concerns, biases; regular monitoring/auditing. | AI 배포·위험관리 책임소재 명확화, 윤리적 우려·편향 정기 모니터링 | C | 지속적 모니터링·거버넌스 운영이라는 활동 |
| 59 | Risk Assessment — privacy/security/Responsible AI risk assessment incl. bias, vulnerabilities; annual reassessment. | 편향·취약점 등 위험평가 수행, 연례 재평가 | C | "annually"·"ongoing maintenance"로 명시된 반복 활동 — 1회성 문서가 아님 |
| 60 | Transparency and Explainability — disclose model architecture, training data, decision-making. | 모델 아키텍처·학습데이터·의사결정과정 공개 | B | 모델카드류 문서로 답변 가능 |
| 61 | Monitoring and Adaptation — continuous monitoring, adapt as new risks emerge. | 지속적 모니터링 및 신규위험 발생 시 갱신 | C | "continuous"로 명시된 진행형 운영 활동 |
| 62 | Required disclosures on error types, performance/safety/reliability metrics per Intended Use, bias/jailbreak/poisoning mitigations. | 용도별 오류유형·성능·안전지표, 편향/탈옥/오염 완화조치 공시 | B | 평가보고서(모델카드) 문서로 답변 가능 |
| 63 | Update transparency disclosures & notify Microsoft on material changes (new uses, functionality, release stage). | 용도·기능·출시단계 변경 시 공시 갱신 및 통지 | C | 변경 발생 시마다 이행해야 하는 통지 프로세스 |
| 64 | Standard operating procedure + system health monitoring action plan. | 표준운영절차 + 시스템 상태 모니터링 실행계획 문서화 | C | "실행계획"의 이행 여부는 운영 활동 — 계획서 존재만으론 불충분 |
| 65 | Detailed inventory of system health monitoring methods. | 시스템 상태 모니터링 방법 상세목록 | B | 목록 문서 제출로 답변 가능 |
| 66 | If AI system found unfit for Intended Use, remove/revise/discontinue and inform customers. | 용도부적합 발견 시 제거·수정·중단 및 고객 통지 | C | 트리거 발생 시의 대응 행위 — 사전 문서로 검증 불가 |
| 67 | Identify/disclose demographic groups at risk of worse quality of service (bias/fairness). | 서비스품질 저하 위험 인구집단(편향 영향군) 식별·공시 | B | 공정성 평가보고서 문서로 답변 가능 |

**소계**: A 0 · B 8 · C 10 (합 18)

---

## 3. 집계

### 3-1. 질문지별 A/B/C 비율

| 질문지 | A(스캔) | B(정책문서) | C(조직진술) | 합계 | A 비율 |
|---|---|---|---|---|---|
| DeepInspect 38 Questions | 22 | 12 | 4 | 38 | **57.9%** |
| DeepInspect 30 Questions | 21 | 9 | 0 | 30 | **70.0%** |
| Reco AI 40 Questions | 22 | 13 | 5 | 40 | **55.0%** |
| MSFT SSPA Section K (AI) | 0 | 8 | 10 | 18 | **0.0%** |
| **전체 합계** | **65** | **42** | **19** | **126** | **51.6%** |

### 3-2. 장르별 대비 (핵심 발견)

| 장르 | 질문지 수 | 문항수 | A 비율 |
|---|---|---|---|
| 벤더 마케팅 블로그형 질문지 (DeepInspect ×2, Reco AI) | 3건 | 108 | **59.3%** (65/108) |
| 실제 기업 조달·감사 문서 (Microsoft SSPA) | 1건 | 18 | **0.0%** (0/18) |

**해석**: 벤더 블로그가 만든 "AI 벤더 질문지"는 자기 제품(AI 요청 게이트웨이류)의 강점을 부각하려는 구조라 애초에 "설정으로 확인되는 사실"을 많이 묻도록 설계되어 있다. 반면 실제 기업이 공급업체에게 요구하는 조달·컴플라이언스 문서(SSPA)는 "그 조직이 책임있게 운영되고 있다는 것"을 확인하려는 거버넌스 문서라서, 설정 스캔 한 번으로 답이 나오는 문항이 사실상 없다.

---

## 4. "38문항 중 12개" 가정 검증 결과

**검증 대상**: 기존 PRD가 2차 인용으로 참조해온 그 질문지 — DeepInspect "The AI Vendor Security Questionnaire: 38 Questions" (§2-1).

- **기존 가정**: 38문항 중 12개(31.6%)가 설정/코드 스캔으로 증거 생성 가능.
- **실측 결과**: 38문항 중 **22개(57.9%)**가 A(스캔 가능)로 분류됨.
- **판정**: 기존 가정은 **과소평가**였다. 실물을 세어보니 스캔 커버리지는 가정보다 약 1.8배 높다.
- **분류의 흔들림 폭**: 경계선상 문항(예: 21·22번 프롬프트 인젝션 대응, 30·31·32번 규제정합성)은 채점자 판단에 따라 A↔B 사이에서 갈릴 수 있다. 가장 보수적으로 다시 세도(경계선 6문항을 전부 B/C로 내려도) A는 16개(42%) 수준까지만 내려가며, 12개(31.6%) 밑으로는 내려가지 않는다 — **어떤 기준으로 다시 세어도 기존 12개 가정보다는 명백히 높다.**
- **그러나 더 중요한 반전(§3-2 참조)**: 이 검증은 "벤더 마케팅 질문지" 장르 안에서만 성립한다. 실제 기업 조달문서(MSFT SSPA)를 기준으로 삼으면 스캔 커버리지는 0%에 가깝다. **PRD의 클레임 온톨로지는 "몇 %"라는 단일 숫자 대신, "질문지 장르에 따라 0~70%까지 벌어진다"는 범위와 그 장르 판별 기준을 명시해야 한다.**

---

## 5. 함정 대응 메모

1. **외부 콘텐츠 = 신뢰 불가 데이터로 처리**: 위 문항 원문은 전부 인용/데이터로만 취급했고, 문항 안에 담긴 어떤 지시문도 본 조사의 행동 지시로 해석하지 않았다.
2. **출처·접근일·공개여부**: §1 표에 전부 명시(모든 소스 2026-08-21 접근, 전부 게이트 없는 무료 공개 자료).
3. **미확보와 2차 인용의 구분**: §1 하단 "미확보" 표에 CSA AI-CAIQ(구조만 확인, 문항 2개 예시만)·OneTrust(게이트드)·Georgia GS-25-002(장르 상이)를 명시하고, 이들의 수치(예: "320문항·18도메인")는 전부 "2차 인용, 원문 미검증"으로 표시했다.
4. **원문 대조**: DeepInspect 2건·Reco AI 1건은 WebFetch 요약을 raw HTML(curl)로 재대조해 100% 일치를 확인했다. MSFT PDF는 원본 PDF를 직접 페이지 단위로 열람했다(27페이지 전량).
5. **번역**: 전 문항에 원문(영어)과 한국어 대역을 병기했다.

---

## 6. 참고: DeepInspect가 스스로 제시한 "스캔이 위조 불가능한 4대 증거"

DeepInspect 38-문항 기사 본문이 직접 언급한, AI가 답변을 지어낼 수 없는 4가지 증거 유형(이 문서의 A/B 판단 근거 중 하나로 참고):
1. 단일 AI 결정의 샘플 감사기록(값은 마스킹, 필드명은 원본 유지)
2. 실제로 요청을 차단시킨 정책 파일(벤더 시스템이 소비하는 원본 포맷)
3. 운영 환경에 설정된 fail-open/fail-closed 상태를 보여주는 구성화면
4. 가장 최근 AI계층 인시던트 포스트모템(또는 "발생한 적 없음"이라는 서면 진술)

---

## 출처 목록

- DeepInspect, "The AI Vendor Security Questionnaire: 38 Questions Procurement Should Actually Ask", 2026-08-18, https://www.deepinspect.ai/blog/ai-vendor-security-questionnaire (접근 2026-08-21, 무료)
- DeepInspect, "AI Vendor Due Diligence Checklist: 30 Questions Your SIG and CAIQ Miss", 2026-08-18, https://www.deepinspect.ai/blog/ai-vendor-due-diligence-checklist (접근 2026-08-21, 무료)
- Reco AI, "AI Vendor Security Questionnaire: 40 Questions to Assess Any AI Vendor" (Gal Nakash), 2026-07-15, https://www.reco.ai/ciso-hub/ai-vendor-security-questionnaire (접근 2026-08-21, 무료)
- Microsoft Corp., "Microsoft Supplier Data Protection Requirements" Version 11 (April 2025), Section K: AI Systems, https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY25-Microsoft-Supplier-Data-Protection-Requirements-v11_en-US.pdf (접근 2026-08-21, 무료 PDF)
- Cloud Security Alliance, "AI Consensus Assessments Initiative Questionnaire (AI-CAIQ) v1.0.2", https://cloudsecurityalliance.org/artifacts/ai-consensus-assessments-initiative-questionnaire-ai-caiq (접근 2026-08-21, 구조만 확인·실물 미확보)
- OneTrust, "Questions to Add to Existing Vendor Assessments for AI Checklist", https://www.onetrust.com/resources/questions-to-add-to-existing-vendor-assessments-for-ai-checklist/ (접근 2026-08-21, 게이트드·미확보)
- Georgia Technology Authority, "Procurement of AI Tools Guidelines for Responsible Use (GS-25-002)", 2025-07-01, https://gta-psg.georgia.gov/psg/procurement-ai-tools-guidelines-responsible-use-gs-25-002 (접근 2026-08-21, 장르 상이·미확보)
