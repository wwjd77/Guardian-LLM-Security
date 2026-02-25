# Guardian: Lightweight Intent Verification for Local LLM Agents 🛡️
**(로컬 LLM 에이전트를 위한 경량화된 의도 검증 보안 프레임워크)**

> **Abstract:** Guardian is a security framework designed for local LLM agents (running on edge devices like Apple M-series, consumer GPUs). It mitigates **Indirect Prompt Injection (IPI)** attacks by verifying the semantic consistency between a user's intent and the agent's tool execution using a lightweight SLM (e.g., Phi-3-mini).
>
> **요약:** Guardian은 로컬 환경(Apple M 시리즈, 개인용 GPU 등 엣지 디바이스)에서 구동되는 LLM 에이전트를 위한 보안 프레임워크입니다. 경량화된 소형 언어 모델(SLM, 예: Phi-3-mini)을 활용하여 사용자의 의도(Intent)와 에이전트의 도구 실행(Tool Execution) 간의 의미적 일치성을 검증함으로써, **간접 프롬프트 주입(IPI)** 공격을 효과적으로 방어합니다.

---

## 📂 Repository Structure (폴더 구조)

| File (파일명) | Description (설명) |
| :--- | :--- |
| `guardian_test_v3.py` | **Core Module.** Implements the intent verification logic using Ollama API.<br>핵심 모듈. Ollama API를 사용하여 의도 검증 로직을 구현했습니다. |
| `guardian_defense.py` | **AgentDojo Integration.** Adapter class to plug Guardian into the [AgentDojo](https://github.com/ethz-spylab/agentdojo) benchmark.<br>AgentDojo 벤치마크 연동을 위한 어댑터 클래스입니다. |
| `guardian_fpr_meta_test.py` | **Validation Script.** Measures False Positive Rate (FPR) on 200 benign samples and tests meta-injection attacks.<br>오탐률(FPR) 측정 및 메타 주입 공격 테스트 스크립트입니다. |
| `guardian_stress_test.py` | **Stress Test.** Tests defense against obfuscated (Base64) and social engineering attacks.<br>난독화(Base64) 및 사회공학적 공격에 대한 스트레스 테스트입니다. |
| `guardian_visualize.py` | **Visualization.** Generates ROC curves, latency distribution plots, and consistency score histograms for the thesis.<br>논문용 그래프(ROC 커브, 지연 시간 분포 등)를 생성하는 시각화 도구입니다. |
| `attack.html` | **PoC Exploit.** A sample HTML file containing hidden prompt injection payloads for testing.<br>공격 테스트를 위해 숨겨진 프롬프트가 포함된 샘플 HTML 파일입니다. |

---

## 🚀 Getting Started (시작하기)

### 1. Prerequisites (준비 사항)

- **Python 3.10+**
- **Ollama** (로컬 SLM 구동용 / for running the local SLM)
- **Node.js** (n8n 파이프라인 사용 시에만 필요 / Optional)

### 2. Environment Setup (환경 설정)

1.  **Install Python Dependencies (라이브러리 설치):**
    ```bash
    pip install -r requirements.txt
    ```
    *(If `requirements.txt` is missing, install manually / 파일이 없다면 수동 설치: `pip install requests matplotlib seaborn scikit-learn`)*

2.  **Setup Ollama & Model (Ollama 및 모델 설정):**
    Guardian uses **Microsoft Phi-3-mini** by default. (기본적으로 Phi-3-mini를 사용합니다.)
    ```bash
    # Install Ollama from https://ollama.com/
    # Pull the model (모델 다운로드)
    ollama pull phi3:mini
    
    # Start the server (서버 실행)
    ollama serve
    ```

---

## 🧪 How to Run Experiments (실험 실행 방법)

### 1. Basic Defense Test (기본 방어 테스트)
Test if Guardian correctly blocks a simple attack. (간단한 공격을 막는지 확인합니다.)
```bash
python guardian_test_v3.py
```
> **Expected Output (예상 결과):**
> - Intent: "Summarize news" / Action: "email.send(/etc/passwd)" -> **[DENY]** ⛔
> - Intent: "Check weather" / Action: "weather.get()" -> **[ALLOW]** ✅

### 2. False Positive & Meta-Attack Analysis (오탐률 및 메타 공격 분석)
Measure FPR and check resilience against "Ignore previous instructions" attacks.
```bash
python guardian_fpr_meta_test.py
```

### 3. Stress Testing (스트레스 테스트)
Test against Base64 encoded payloads and social engineering tricks. (난독화 및 사회공학 공격 테스트)
```bash
python guardian_stress_test.py
```

### 4. AgentDojo Benchmark Integration (벤치마크 연동)
To run the full benchmark using Guardian as a defense:
1.  Clone the [AgentDojo repository](https://github.com/ethz-spylab/agentdojo).
2.  Copy `guardian_defense.py` into `agentdojo/src/agentdojo/agent_pipeline/`.
3.  Register `guardian` in `agent_pipeline.py` (refer to thesis details).
4.  Run the benchmark:
    ```bash
    python -m agentdojo.scripts.benchmark --model LOCAL --model-id phi3:mini --defense guardian --suite workspace --attack tool_knowledge
    ```

### 5. Generate Thesis Figures (논문용 그래프 생성) 📊
Create academic-quality plots (ROC Curve, Latency, Score Distribution).
```bash
python guardian_visualize.py
```
*Output images (`figure_*.png`) will be saved in the current directory.*

---

## 🧩 System Architecture (시스템 아키텍처)

```mermaid
graph TD
    User([User Prompt / 사용자 명령]) --> Agent[Local LLM Agent]
    Agent -->|Tool Call / 도구 호출| Guardian{Guardian (Phi-3)}
    Guardian -->|Verify Intent / 의도 검증| SLM[SLM Inference]
    SLM -->|Consistency Score / 정합성 점수| Decision
    
    Decision -- "Score < Threshold" --> Block[🚫 DENY / 차단]
    Decision -- "Score >= Threshold" --> Allow[✅ ALLOW / 허용]
```

## 📜 Citation (인용)

If you use this code for your research, please cite:
(이 코드를 연구에 활용하신다면 아래와 같이 인용해 주세요.)

```bibtex
@mastersthesis{Guardian2026,
  author = {Soon Gil Kwon},
  title = {Guardian: SLM-based Intent Verification for Local LLM Agent Security},
  school = {Your University Name},
  year = {2026}
}
```

---

**License:** MIT License
