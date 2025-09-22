# POLAR: Automating Cyber Threat Prioritization Through LLM-Powered Assessment


## Overview

POLAR is an LLM-based framework that automates end-to-end cyber threat prioritization, addressing the critical challenge of managing new vulnerabilities reported annually. The framework operates through four sequential stages:

1. **CTI Triage** - Categorizes threat indicators and enriches contexts with vulnerability metadata
2. **Static Analysis** - Maps threats to CVSS metrics for standardized severity assessment  
3. **Exploitation Analysis** - Forecasts near-term exploitation likelihood using temporal evidence
4. **Mitigation Recommendation** - Generates prioritized remediation strategies

## Key Results

- **71.9%** improvement in CTI extraction F1 score
- **43.5%** increase in CVSS accuracy
- **22.4%** reduction in EPSS RMSE
- **50.8%** improvement in mitigation NDCG@5

## Repository Structure

```
├── RQ2_Experiments/          # CVSS prediction experiments
│   └── cvss_prediction/
│       ├── metrics_prediction.py        # Multi-model CVSS metrics predictor
│       ├── multi_model_cvss_predictor.py # Fixed version for 2024 directory
│       ├── score_prediction1.py         # Direct score prediction
│       ├── score_prediction2.py         # Metrics-based prediction
│       └── two_stage_prediction.py      # Two-stage prediction approach
│
├── RQ3_Experiments/          # EPSS exploitation prediction
│   └── epss_prediction/
│       ├── RQ3_Experiment_1.py  # Trend-based prediction evaluation
│       └── RQ3_Experiment_2.py  # Window size analysis
│
├── enhanced_threat_reports/  # [Data directory - not included]
└── GT_Data/                  # [Ground truth data - not included]
```

## Requirements

```python
python >= 3.8
numpy >= 1.20.0
pandas >= 1.3.0
scikit-learn >= 0.24.0
matplotlib >= 3.3.0
tqdm >= 4.60.0
g4f  # For LLM model access
```

## Experiments

### RQ2: Static Analysis (CVSS Prediction)

Evaluates POLAR's ability to predict CVSS metrics and scores from threat reports.

```bash
# Run multi-model CVSS metrics prediction
python RQ2_Experiments/cvss_prediction/multi_model_cvss_predictor.py

# Run two-stage prediction (metrics classification + score prediction)
python RQ2_Experiments/cvss_prediction/two_stage_prediction.py
```

**Key Configuration Parameters:**
- `TEST_LIMIT`: Number of CVEs to test (set to `None` for full dataset)
- `MODELS_TO_TEST`: LLM models to evaluate
- `MAX_RETRIES`: Number of retry attempts for LLM calls

### RQ3: Exploitation Analysis (EPSS Prediction)

#### Experiment 1: Trend-based Prediction
Evaluates prediction accuracy across different exploitation patterns (monotonic, stable, sudden changes).

```bash
python RQ3_Experiments/epss_prediction/RQ3_Experiment_1.py
```

**Configuration:**
- `WINDOW_DAYS = 180`: Historical window for predictions (6 months)
- `SAMPLE_PER_TREND`: Number of samples per trend type (None for all)

#### Experiment 2: Window Size Analysis
Analyzes the impact of historical context length on prediction accuracy.

```bash
python RQ3_Experiments/epss_prediction/RQ3_Experiment_2.py
```

**Configuration:**
- `WINDOW_YEARS = [0.5, 1.0, 2.0]`: Different historical windows to test

## Data Format

### CVSS Ground Truth Format
```json
{
  "CVE-2024-9xxx": [
    {
      "base_score": 7.5,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      "score_source": "NIST"
    }
  ]
}
```

### EPSS History Format
```json
{
  "CVE-2024-xxxx": [
    {
      "date": "2024-01-15",
      "score": 0.00145,
      "delta": 0.00012
    }
  ]
}
```

## Model Configuration

The experiments support multiple LLM models through the g4f library:

```python
MODELS = {
    "gpt-4o": g4f.models.gpt_4o,
    "gpt-4": g4f.models.gpt_4,
    "gpt-4o-mini": g4f.models.gpt_4o_mini,
    "gemini-1.5-pro": g4f.models.gemini_1_5_pro,
    "llama-3.1-70b": g4f.models.llama_3_1_70b
}
```

## Output Files

### CVSS Experiments Output
- `multi_model_results.csv`: Accuracy metrics for each model
- `multi_model_comparison.png`: Visualization of model performance
- `{model}_results.json`: Detailed predictions for each model

### EPSS Experiments Output
- `rq3_exp1_detail_{timestamp}.csv`: Per-sample predictions
- `rq3_exp1_summary_{timestamp}.csv`: Aggregated metrics by trend and model
- `exp2_{trend}_{metric}.png`: Performance curves for different window sizes

## Evaluation Metrics

### CVSS Metrics
- **Accuracy**: Per-metric classification accuracy
- **RMSE/MAE**: Score prediction error
- **Correlation**: Prediction vs ground truth correlation

### EPSS Metrics  
- **RMSE/MAE**: Exploitation probability prediction error
- **Direction Accuracy**: Correct prediction of increase/decrease
- **MAPE**: Mean absolute percentage error
- **R²**: Coefficient of determination

## Notes

- The experiments use caching to avoid redundant LLM calls
- Results are saved incrementally to prevent data loss
- Random delays are added between API calls to avoid rate limiting
- Invalid predictions automatically fall back to baseline methods

## Citation

If you use this code in your research, please cite:

```bibtex
@inproceedings{polar2026,
  title={POLAR: Automating Cyber Threat Prioritization Through LLM-Powered Assessment},
  author={Anonymous Authors},
  booktitle={International Conference on Learning Representations (ICLR)},
  year={2026}
}
```

## License

This code is provided for research purposes. See LICENSE file for details.