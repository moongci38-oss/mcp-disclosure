#!/usr/bin/env bash
# 공개 표준 질문지 원문 확보 — 재현 스크립트
#
# 2026-08-23 최초 작성. 계정·결제 없이 받을 수 있는 것만 담는다.
# 산출물은 OUT_DIR 에 떨어지며 레포에는 커밋하지 않는다(아래 라이선스 주석 참조).
#
# 재현: bash docs/research/scripts/fetch-public-questionnaires.sh /tmp/q
set -euo pipefail

OUT_DIR="${1:-${TMPDIR:-/tmp}/public-questionnaires}"
mkdir -p "$OUT_DIR/vsaq" "$OUT_DIR/caiq"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

echo "==> VSAQ (Google, Apache-2.0) — 질문지 4종"
# 라이선스: Apache 2.0(재배포 가능). 그래도 이 레포에는 넣지 않는다 — 원본이 갱신되면
# 우리 사본이 조용히 낡는다. 링크가 정본이고 이 스크립트가 그 링크를 붙잡아 둔다.
for f in infrastructure physical_and_datacenter security_privacy_programs webapp; do
  curl -fsSL --max-time 60 -o "$OUT_DIR/vsaq/$f.json" \
    "https://raw.githubusercontent.com/google/vsaq/master/questionnaires/$f.json"
  echo "    $f.json"
done

echo "==> CAIQ (CSA) — 벤더 완성본 PDF 3종 (버전이 섞여 있다, 아래 주의)"
# ⚠️ CSA 공식 배포처(cloudsecurityalliance.org/artifacts/...)는 다운로드에 계정이 필요하다
#    (무료 가입이지만 폼 뒤에 있다 — 2026-08-23 확인, 정적 fetch 로는 파일 링크가 안 나온다).
#    아래는 벤더가 자사 STAR Level 1 자기평가로 공개한 "완성본"이고, 261문항 원문이 그대로 들어 있다.
#    문항 텍스트를 얻는 목적에는 충분하다. 답변란은 그 벤더의 것이므로 우리 분석에서 무시한다.
#
# ⚠️ 세 파일의 CAIQ 버전이 다르다(2026-08-23 실측 — 처음엔 같은 줄 알았다가 ID 개수가
#    엇갈려서 발견했다). 버전을 확인하지 않고 합치면 서로 다른 시험지를 한 장으로 세게 된다.
#      katalon / aws → v4.0.3 (261문항) — 두 파일의 문항 ID 집합이 완전히 동일하다
#      esri          → v4.1   (283문항, 2026-07 판) — IVS 도메인이 I&S 로 개명됐다
dl() { curl -fsSL --max-time 90 -A "$UA" -o "$OUT_DIR/caiq/$1" "$2" && echo "    $1"; }
dl katalon.pdf "https://katalon.com/hubfs/Katalon%20-%20CAIQv4.0.3_STAR-Security-Questionnaire%20(7Nov2025).pdf"
dl aws.pdf     "https://d1.awsstatic.com/whitepapers/compliance/CSA_Consensus_Assessments_Initiative_Questionnaire.pdf"
dl esri.pdf    "https://content.esri.com/resources/enterprisegis/agol_csa_caiq.pdf"

echo "==> 텍스트 추출(poppler 필요: pdftotext)"
for f in katalon aws esri; do
  pdftotext -raw "$OUT_DIR/caiq/$f.pdf" "$OUT_DIR/caiq/$f-raw.txt"
done

echo
echo "완료: $OUT_DIR"
echo
echo "교차검증 — 기대값:  katalon 261 · aws 261 · esri 277"
echo "  (esri 는 다른 버전이라 수가 다른 것이 정상이다. 앞의 둘이 서로 다르면 그때가 문제다.)"
PAT='\b(A&A|AIS|BCR|CCC|CEK|DCS|DSP|GRC|HRS|IAM|IPY|IVS|I&S|LOG|SEF|STA|TVM|UEM)-[0-9]{2}\.[0-9]+\b'
for f in katalon aws esri; do
  grep -oE "$PAT" "$OUT_DIR/caiq/$f-raw.txt" | sort -u > "$OUT_DIR/caiq/$f.ids"
  echo "  $f: $(wc -l < "$OUT_DIR/caiq/$f.ids") 문항 ID"
done
if cmp -s "$OUT_DIR/caiq/katalon.ids" "$OUT_DIR/caiq/aws.ids"; then
  echo "  ✅ katalon 과 aws 의 ID 집합이 완전히 동일 — v4.0.3 문항 추출이 신뢰 가능하다"
else
  echo "  ❌ katalon 과 aws 의 ID 집합이 다르다 — 한쪽이 발췌본이거나 파서가 깨졌다"
fi
