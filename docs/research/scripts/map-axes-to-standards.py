#!/usr/bin/env python3
"""15축 온톨로지 ↔ 공개 표준 질문지 매핑률 실측 — 재현 스크립트.

쉽게 말하면: "우리 스캔 결과로 남의 시험지 몇 문제를 풀 수 있나"를 세는 도구다.

두 단계로 나뉜다.
  1단계 (기계) — 키워드로 후보를 넓게 긁는다. 여기 안 걸리면 판정 대상이 아니다.
  2단계 (사람) — 후보를 읽고 Full/Partial/None 을 판정한다. 그 판정은 VERDICTS 에 박아 둔다.

1단계를 굳이 두는 이유: 2단계가 사람 판단이라 "안 본 문항이 있는 것 아니냐"는 반문이 나온다.
1단계 숫자가 그 반문에 대한 답이다 — 걸린 후보 전량을 봤다는 것을 보일 수 있다.

선행: bash docs/research/scripts/fetch-public-questionnaires.sh /tmp/q
재현: python3 docs/research/scripts/map-axes-to-standards.py /tmp/q
"""
import collections
import json
import re
import sys

# ---------------------------------------------------------------- 1단계 키워드
# 넓게 잡는다. 오탐은 2단계가 걷어내지만 누락은 아무도 못 잡기 때문이다.
AXIS_KW = {
    'prompt_injection_defense': r'prompt|injection|jailbreak|\bllm\b|generative|model input',
    'secret_exposure':          r'secret|credential|password|private key|api key|\btoken\b|hardcod',
    'vulnerable_deps':          r'vulnerabilit|vulnerable|third.?party librar|open.?source librar|dependenc|\bcve\b|patch|software compos',
    'malicious_pattern':        r'malicious|malware|code execution|backdoor|exfiltrat|tamper|anti.?virus',
    'operational_reliability':  r'configuration file|config file|hardening|build standard|baseline|readiness|misconfigur',
    'tool_permission':          r'least privilege|privileged|permission|authoriz|access control|separation of duties',
    'auth_oauth':               r'authenticat|oauth|multifactor|multi.?factor|\bmfa\b|single sign|\bsso\b|certificate',
    'data_flow':                r'data flow|data is processed|transmit|transfer of|where it is stored',
    'logging':                  r'\blog\b|logging|audit record|audit log|monitor',
    'sdlc':                     r'\bsdlc\b|software development|build|release|pipeline|deploy|change management|change control',
    'incident_response':        r'incident|breach|forensic',
    'data_retention':           r'retention|retain|deletion|disposal|archiv|destroy',
    'subprocessor':             r'sub.?processor|subcontractor|supply chain|third.?part(y|ies)|vendor|service provider',
    'training_data':            r'training data|model training|train(ing)? (the )?model',
    'dpa':                      r'data processing agreement|\bdpa\b|contractual|written contract|service level agreement|\bsla\b',
}

# ---------------------------------------------------------------- 2단계 판정
# 판정 규칙(이 세 줄이 아래 표의 전부다):
#   Full    = 우리 스캔 출력만으로 그 문항의 답과 근거가 나온다.
#   Partial = 우리 스캔 리포트를 그 문항 답변의 증거로 첨부하는 것이 실제로 말이 된다.
#             (답 자체는 여전히 조직이 써야 한다 — 우리는 근거 한 장을 보탤 뿐이다)
#   None    = 기여 없음. 기본값이다.
#
# 경계 판정 기준: "질문이 묻는 자산 범위 안에 MCP/AI 에이전트 설정이 들어가는가."
#   들어가면 Partial, 질문이 대상을 다른 것으로 못박으면(host-level, OS, 웹서버) None.
#
# ⚠️ 여기 없는 문항은 전부 None 이다. 아래 목록이 짧은 것은 실수가 아니라 결과다.
VERDICTS = {
    # --- CAIQ v4.0.3 (261문항 중 3건) ---
    'CEK-11.1': ('secret_exposure', 'Partial',
                 '"private key 가 고유 목적으로 관리되고 암호가 비밀로 유지되는가". '
                 '우리 스캔은 MCP 설정 파일 범위 안에서 평문 자격증명 부재를 보인다 — '
                 '질문 전체가 아니라 그 한 귀퉁이다.'),
    'TVM-05.1': ('vulnerable_deps', 'Partial',
                 '"서드파티/오픈소스 라이브러리를 쓰는 애플리케이션의 업데이트를 식별하는 '
                 '프로세스·기술적 조치". vulnerable_package 분석기가 그 기술적 조치의 하나로 열거된다.'),
    'TVM-07.1': ('vulnerable_deps', 'Partial',
                 '"조직 관리 자산에 대해 최소 월 1회 취약점 탐지". 스캔 실행 기록이 증거가 된다. '
                 '단 자산 범위가 MCP 설정으로 좁아 이 문항을 혼자 못 채운다.'),

    # --- VSAQ (242문항 중 5건) ---
    'servers_configmgmt_audit': ('operational_reliability', 'Partial',
                 '"설정 파일을 검토·감사해 보안정책에 부합하는지 확인하는가". '
                 '우리 제품이 하는 일과 가장 정확히 겹치는 단 하나의 문항이다.'),
    'infrastructure#32': ('vulnerable_deps', 'Partial',
                 '"시스템이 패치가 필요한 취약점의 영향을 받는지 어떻게 판단하나(복수 선택)". '
                 '선택지의 하나로 우리 스캔을 댈 수 있다.'),
    'infrastructure#64': ('vulnerable_deps', 'Partial',
                 '위 문항의 클라이언트 시스템 판(같은 질문, 다른 대상).'),
    'servers_patching_infosource_other_explain': ('vulnerable_deps', 'Partial',
                 '"어떤 패치가 우리 시스템에 해당되는지 알아내는 방법을 서술하라" — 자유서술이라 '
                 '우리 리포트를 근거로 문장을 쓸 수 있다.'),
    'clients_patching_infosource_other_explain': ('vulnerable_deps', 'Partial',
                 '위 문항의 클라이언트 시스템 판.'),
}

# 참고로만 세는 항목 — 축이 아니라 discover 단계의 부산물(서버·도구 목록)이 기여하는 문항.
# 15축 어디에도 이 산출물이 등재돼 있지 않다(온톨로지 갭, 본문 §5 참조).
INVENTORY_BYPRODUCT = {
    'STA-07.1': '"공급망 관계 인벤토리를 개발·유지하는가" — 우리 discover 가 MCP 서버 목록을 만든다.',
    'UEM-02.1': '"승인된 서비스·애플리케이션·소스 목록" — 실제로 설치된 목록의 실측치를 준다.',
    'DSP-05.1': '"데이터 흐름 문서화" — 어떤 서버로 무엇이 나가는지의 일부만 보인다.',
}

# ⚠️ 'I&S' 는 v4.1 에서 'IVS'(Infrastructure & Virtualization Security)가 개명된 코드다.
#    둘 다 넣어야 두 버전을 같은 파서로 읽는다 — 2026-08-23 실측(v4.1 에는 IVS 가 0건이다).
DOMAINS = r'(?:A&A|AIS|BCR|CCC|CEK|DCS|DSP|GRC|HRS|IAM|IPY|IVS|I&S|LOG|SEF|STA|TVM|UEM)'
ID_RE = re.compile(rf'^({DOMAINS}-\d{{2}}\.\d+)$')
# 벤더마다 PDF 레이아웃이 달라 ID 가 단독 줄일 때도, 질문문과 같은 줄일 때도 있다.
ID_HEAD_RE = re.compile(rf'^({DOMAINS}-\d{{2}}\.\d+)\s+(\S.*)$')


def load_caiq(path, label):
    """벤더 완성본 PDF 의 raw 텍스트에서 문항 ID + 질문문을 뽑는다.

    두 레이아웃을 모두 받는다:
      (a) ID 가 단독 줄, 다음 줄부터 질문문   — Katalon/AWS(v4.0.3)
      (b) ID 와 질문문이 같은 줄에서 시작     — Esri(v4.1)
    """
    lines = [l.rstrip() for l in open(path, encoding='utf-8', errors='replace')]
    found = {}
    i = 0
    while i < len(lines):
        s0 = lines[i].strip()
        m_solo, m_head = ID_RE.match(s0), ID_HEAD_RE.match(s0)
        if not (m_solo or m_head):
            i += 1
            continue
        if m_solo:
            qid, buf = m_solo.group(1), []
        else:
            qid, buf = m_head.group(1), [m_head.group(2)]
        j = i + 1
        while j < len(lines) and len(buf) < 12 and not (buf and buf[-1].endswith('?')):
            s = lines[j].strip()
            if ID_RE.match(s) or ID_HEAD_RE.match(s):
                break
            buf.append(s)
            j += 1
        q = re.sub(r'\s+', ' ', ' '.join(x for x in buf if x)).strip()
        if '?' in q:
            q = q[:q.index('?') + 1]
        # 같은 ID 가 여러 번 나오면 가장 긴 것을 문항문으로 본다(PDF 컬럼 파편 방지).
        if qid not in found or len(q) > len(found[qid]):
            found[qid] = q
        i = max(j, i + 1)
    return [{'src': label, 'id': k, 'text': v} for k, v in sorted(found.items())]


def load_vsaq(dirpath):
    """VSAQ 질문지 JSON 을 읽는다. 순수 JSON 이 아니라 두 군데를 손봐야 한다."""
    QTYPES = {'radiogroup', 'checkgroup', 'line', 'box'}
    rows = []
    for name in ('infrastructure', 'physical_and_datacenter',
                 'security_privacy_programs', 'webapp'):
        s = open(f'{dirpath}/{name}.json', encoding='utf-8').read()
        s = s[min(x for x in (s.find('{'), s.find('[')) if x >= 0):]  # 앞머리 라이선스 주석 제거
        s = re.sub(r'"\s*\+\s*"', '', s)                              # JS 문자열 연결 제거
        doc = json.loads(s)

        def walk(node, idx=[0]):
            if isinstance(node, dict):
                if node.get('type') in QTYPES:
                    txt = ''
                    for k in ('text', 'caption', 'name'):
                        if isinstance(node.get(k), str) and node[k].strip():
                            txt = ' '.join(node[k].split())
                            break
                    txt = re.sub(r'<[^>]+>', '', txt).strip()
                    if txt:
                        rows.append({'src': f'VSAQ/{name}',
                                     'id': node.get('id') or f'{name}#{idx[0]}',
                                     'text': txt})
                    idx[0] += 1
                for k, v in node.items():
                    if k in ('items', 'questionnaire'):
                        walk(v, idx)
            elif isinstance(node, list):
                for it in node:
                    walk(it, idx)

        walk(doc)
    return rows


# CAIQ 소스 — 벤더 완성본 PDF 별로 버전이 다르다(2026-08-23 실측).
CAIQ_SOURCES = {
    '4.0.3': ('katalon-raw.txt', 'CAIQ v4.0.3'),   # AWS(aws-raw.txt)와 ID 261개가 완전 일치
    '4.1':   ('esri-raw.txt',    'CAIQ v4.1'),     # 2026-07 판. IVS → I&S 개명
}


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else '/tmp/public-questionnaires'
    ver = sys.argv[2] if len(sys.argv) > 2 else '4.0.3'
    if ver not in CAIQ_SOURCES:
        sys.exit(f'CAIQ 버전은 {list(CAIQ_SOURCES)} 중 하나여야 한다 (받은 값: {ver})')
    fname, label = CAIQ_SOURCES[ver]

    rows = load_caiq(f'{base}/caiq/{fname}', label) + load_vsaq(f'{base}/vsaq')
    n_caiq = sum(1 for r in rows if r['src'].startswith('CAIQ'))
    n_vsaq = len(rows) - n_caiq
    print(f'CAIQ 소스: {label} ({fname})')

    hits = collections.defaultdict(list)
    for r in rows:
        low = r['text'].lower()
        for ax, kw in AXIS_KW.items():
            if re.search(kw, low):
                hits[ax].append(r)

    print(f'문항 총계: CAIQ {n_caiq} + VSAQ {n_vsaq} = {len(rows)}\n')
    print('1단계 — 키워드 후보(상한선. 실제 판정은 이보다 훨씬 적다)')
    for ax in AXIS_KW:
        verdict_n = sum(1 for v in VERDICTS.values() if v[0] == ax)
        print(f'  {ax:26s} 후보 {len(hits[ax]):3d}  →  Partial 판정 {verdict_n}')

    uniq = {r['id'] for v in hits.values() for r in v}
    print(f'\n  키워드 1개 이상 걸린 고유 문항: {len(uniq)} / {len(rows)}')

    print('\n2단계 — 최종 판정')
    ids = {r['id'] for r in rows}
    missing = [k for k in VERDICTS if k not in ids]
    if missing:
        print(f'  ⚠️ 판정표에 있으나 파싱 결과에 없는 ID: {missing}')
        print('     (질문지 원본이 갱신됐거나 파서가 깨진 것이다 — 아래 수치를 믿지 말 것)')

    full = [k for k, v in VERDICTS.items() if v[1] == 'Full']
    part = [k for k, v in VERDICTS.items() if v[1] == 'Partial']
    print(f'  Full    : {len(full):3d} / {len(rows)}  ({len(full)/len(rows)*100:.1f}%)')
    print(f'  Partial : {len(part):3d} / {len(rows)}  ({len(part)/len(rows)*100:.1f}%)')
    print(f'  None    : {len(rows)-len(full)-len(part):3d} / {len(rows)}')

    pc = sum(1 for k in VERDICTS if k.startswith(tuple(f'{d}-' for d in
             ('A&A', 'AIS', 'BCR', 'CCC', 'CEK', 'DCS', 'DSP', 'GRC', 'HRS',
              'IAM', 'IPY', 'IVS', 'I&S', 'LOG', 'SEF', 'STA', 'TVM', 'UEM'))))
    print(f'\n  질문지별 — CAIQ {pc}/{n_caiq} ({pc/n_caiq*100:.1f}%) · '
          f'VSAQ {len(VERDICTS)-pc}/{n_vsaq} ({(len(VERDICTS)-pc)/n_vsaq*100:.1f}%)')
    print(f'  (참고) 축 미등재 인벤토리 부산물이 부분 기여하는 문항: {len(INVENTORY_BYPRODUCT)}')


if __name__ == '__main__':
    main()
