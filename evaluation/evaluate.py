import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score

# Load evaluation dataset
df = pd.read_csv("evaluation/test_dataset.csv")

# Convert actual labels to binary
label_map = {
    "SAFE": 0,
    "THREAT": 1
}

df["expected"] = df["expected_label"].map(label_map)

# Methods to compare
methods = {
    "Rule-Based": "rule_prediction",
    "AI-Only": "ai_prediction",
    "Full CloudSentinel": "full_prediction"
}

print("\nCloudSentinel Evaluation Results")
print("=" * 45)

for method, column in methods.items():

    predictions = df[column].map(label_map)

    precision = precision_score(
        df["expected"],
        predictions,
        zero_division=0
    )

    recall = recall_score(
        df["expected"],
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        df["expected"],
        predictions,
        zero_division=0
    )

    print(f"\n{method}")
    print(f"Precision: {precision:.2f}")
    print(f"Recall:    {recall:.2f}")
    print(f"F1 Score:  {f1:.2f}")