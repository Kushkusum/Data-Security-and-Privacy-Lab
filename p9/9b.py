import streamlit as st
import pandas as pd
import numpy as np
import io

# ------------------------------
# Utility Functions
# ------------------------------

def generalize_zip(zipcode, level):
    if pd.isna(zipcode): return zipcode
    s = str(zipcode)
    if level <= 0: return s
    if level >= len(s): return "*" * len(s)
    return s[:len(s) - level] + "*" * level

def generalize_age(age, bin_size):
    if pd.isna(age): return age
    # Ensure age is treated as a number for binning
    try:
        age = int(age)
    except ValueError:
        return age # Return as-is if conversion fails
        
    start = (age // bin_size) * bin_size
    return f"{start}-{start+bin_size-1}"

def equivalence_classes(df, quasi_identifiers):
    """
    Return merged dataframe and grouped summary (counts per equivalence class).
    """
    if not quasi_identifiers:
        # Return empty grouped DataFrame with expected structure
        grouped = pd.DataFrame(columns=quasi_identifiers + ["count"])
        merged = df.copy()
        merged["count"] = len(df)
        return merged, grouped
    grouped = df.groupby(quasi_identifiers).size().reset_index(name="count")
    merged = df.merge(grouped, on=quasi_identifiers, how="left")
    return merged, grouped

def reidentification_risk(df, quasi_identifiers):
    """
    Computes re-identification risk metrics based on equivalence class sizes.
    """
    if not quasi_identifiers:
        n = len(df)
        if n == 0:
            return {"min_eq_size": 0, "avg_eq_size": 0, "naive_min_risk": 1.0, "unique_fraction": 0.0}
        # If no QIs, the whole dataset is treated as one class
        return {"min_eq_size": n, "avg_eq_size": float(n), "naive_min_risk": 1.0 / n, "unique_fraction": 0.0}

    _, grouped = equivalence_classes(df, quasi_identifiers)
    
    if grouped.empty and len(df) > 0:
        # Defensive fallback if grouping produced nothing but data exists (e.g., all NaN QIs)
        n = len(df)
        return {"min_eq_size": n, "avg_eq_size": float(n), "naive_min_risk": 1.0 / n, "unique_fraction": 0.0}
    elif grouped.empty and len(df) == 0:
        return {"min_eq_size": 0, "avg_eq_size": 0, "naive_min_risk": 1.0, "unique_fraction": 0.0}
        
    min_size = int(grouped["count"].min())
    avg_size = float(grouped["count"].mean())
    naive_min_risk = 1.0 / min_size if min_size > 0 else 1.0
    unique_frac = (grouped["count"] == 1).sum() / len(df)
    
    return {
        "min_eq_size": min_size,
        "avg_eq_size": avg_size,
        "naive_min_risk": naive_min_risk,
        "unique_fraction": unique_frac
    }

def apply_k_anonymity(df, quasi_identifiers, k):
    """
    Applies generalization to Age/Zip QIs until k-anonymity is met or limits are reached.
    Returns the generalized DataFrame, the final risk stats, and the list of QI columns used for the check.
    """
    df_work = df.copy()
    
    def make_qis(d, zip_level, age_bin):
        """Helper to create generalized columns based on current levels."""
        d = d.copy()
        qi_cols_used = []
        
        if "Zip" in quasi_identifiers and "Zip" in d.columns:
            d["Zip_g"] = d["Zip"].apply(lambda z: generalize_zip(z, zip_level))
            qi_cols_used.append("Zip_g")
        elif "Zip" in quasi_identifiers and "Zip" not in d.columns:
             # QI selected but not in data, ignore
             pass
        elif "Zip" in d.columns:
             # Column in data but not QI, keep as-is
             qi_cols_used.append("Zip")
        
        if "Age" in quasi_identifiers and "Age" in d.columns:
            # Handle potential non-numeric Age values by coercing
            d["Age_g"] = d["Age"].apply(lambda a: generalize_age(a, age_bin))
            qi_cols_used.append("Age_g")
        elif "Age" in quasi_identifiers and "Age" not in d.columns:
             pass
        elif "Age" in d.columns:
             qi_cols_used.append("Age")

        # For other QIs, use the original column name if present
        for q in quasi_identifiers:
            if q not in ["Zip", "Age"] and q in d.columns:
                qi_cols_used.append(q)

        # Filter to unique columns for the check
        return d, list(set(qi_cols_used))

    # Initial generalization levels
    zip_level = 0
    age_bin = 5

    # ---------------------------------------------
    # Initial Check (level 0 generalization)
    # ---------------------------------------------
    zipped, risk_qis = make_qis(df_work, zip_level, age_bin)
    
    # If no QIs were selected or found, return original data and single class stats
    if not risk_qis:
        stats = reidentification_risk(df_work, []) # Single equivalence class
        return df_work, stats, []

    stats = reidentification_risk(zipped, risk_qis)

    # ---------------------------------------------
    # Iterate generalization until k satisfied
    # ---------------------------------------------
    max_zip_level = 5 # 56001 -> 5600* -> 560** -> 56*** -> 5**** -> *****
    max_age_bin = 80
    
    while stats["min_eq_size"] < k:
        
        # Determine the next step: generalize Zip first, then widen Age bins
        if "Zip" in quasi_identifiers and zip_level < max_zip_level:
            zip_level += 1
        elif "Age" in quasi_identifiers and age_bin < max_age_bin:
            # Double the bin size until max_age_bin
            age_bin = min(age_bin * 2, max_age_bin)
        else:
            # no generalizable QIs left or limits reached -> break
            break
        
        # Apply new generalization levels and re-evaluate
        zipped, risk_qis = make_qis(df_work, zip_level, age_bin)
        stats = reidentification_risk(zipped, risk_qis)

    # Final result: only include original columns plus the generalized ones (if created)
    return zipped, stats, risk_qis


def l_diversity_check(df, quasi_identifiers, sensitive_attr, l):
    if sensitive_attr not in df.columns:
        return {"total_classes": 0, "failing_classes": 0, "failing_fraction": 0.0, "error": f"Sensitive attribute '{sensitive_attr}' not found."}
        
    if not quasi_identifiers:
        distinct_sens = df[sensitive_attr].nunique()
        failing = 1 if distinct_sens < l else 0
        return {"total_classes": 1, "failing_classes": failing, "failing_fraction": float(failing)}
        
    merged = df.groupby(quasi_identifiers)[sensitive_attr].nunique().reset_index(name="distinct_sens")
    failing = merged[merged["distinct_sens"] < l]
    
    return {
        "total_classes": len(merged),
        "failing_classes": len(failing),
        "failing_fraction": (len(failing) / len(merged)) if len(merged) > 0 else 0
    }

def t_closeness_check(df, quasi_identifiers, sensitive_attr, t):
    if sensitive_attr not in df.columns:
        return {"num_classes": 0, "failing_classes": 0, "failing_fraction": 0.0, "error": f"Sensitive attribute '{sensitive_attr}' not found."}
        
    if not quasi_identifiers:
        # single class; TVD is 0
        return {"num_classes": 1, "failing_classes": 0, "failing_fraction": 0.0}
        
    # Global distribution of the sensitive attribute
    global_dist = df[sensitive_attr].value_counts(normalize=True)
    grouped = df.groupby(quasi_identifiers)
    
    failing = 0
    num_classes = 0
    
    for _, group in grouped:
        num_classes += 1
        class_dist = group[sensitive_attr].value_counts(normalize=True)
        
        # Union of indices to cover all possible values in the TVD calculation
        all_idx = global_dist.index.union(class_dist.index)
        gd = global_dist.reindex(all_idx, fill_value=0)
        cd = class_dist.reindex(all_idx, fill_value=0)
        
        # Total Variation Distance (TVD)
        tvd = 0.5 * (gd - cd).abs().sum()
        
        if tvd > t:
            failing += 1
            
    return {
        "num_classes": num_classes,
        "failing_classes": failing,
        "failing_fraction": failing / num_classes if num_classes > 0 else 0
    }

def apply_differential_privacy(df, numeric_cols, epsilon):
    df2 = df.copy()
    scale = 1.0 / epsilon # Laplace mechanism scale (sensitivity/epsilon, sensitivity assumed 1 for counts/sums)
    
    for col in numeric_cols:
        if col in df2.columns:
            noise = np.random.laplace(0, scale, size=len(df2))
            
            # Check if the column is primarily integer-based to round the noisy result
            is_int = pd.api.types.is_integer_dtype(df2[col]) or all(float(x).is_integer() for x in df2[col].dropna())
            
            if is_int:
                # Add noise, round, and ensure result is within reasonable bounds (e.g., non-negative for age/counts)
                df2[col + "_dp"] = (df2[col] + noise).round().clip(lower=0).astype(int)
            else:
                df2[col + "_dp"] = df2[col] + noise
                
    return df2

# ------------------------------
# Streamlit UI
# ------------------------------

st.set_page_config(page_title="PII Anonymizer Advanced", layout="wide")
st.title("🔐 PII Anonymizer — Advanced Streamlit Demo")

st.write("Upload a CSV file containing PII-like data and apply privacy-preserving techniques.")

uploaded_file = st.file_uploader("Upload CSV dataset", type=["csv"])

if uploaded_file:
    df_raw = pd.read_csv(uploaded_file)
    st.subheader("📄 Original Dataset Preview")
    st.dataframe(df_raw.head(10))
else:
    st.info("Upload a CSV to begin, or use the sample dataset below.")
    np.random.seed(42)
    names = [f"Person_{i+1}" for i in range(20)]
    # Create sample data
    df_raw = pd.DataFrame({
        "Name": names,
        "Age": np.random.randint(20, 80, 20),
        "Gender": np.random.choice(["M", "F"], 20),
        "Zip": np.random.choice([56001, 56002, 56003, 56004, 56005], 20),
        "Diagnosis": np.random.choice(["Flu", "Diabetes", "COVID", "Healthy"], 20)
    })
    st.dataframe(df_raw.head(10))

# ------------------------------
# Sidebar settings
# ------------------------------
st.sidebar.header("⚙️ Settings")

available_cols = df_raw.columns.tolist()

# Drop Direct PII (Name) if it exists in the raw data
df_anon = df_raw.copy()
if 'Name' in available_cols:
    df_anon = df_anon.drop(columns=['Name'])
    available_cols.remove('Name')
    st.sidebar.caption("✅ 'Name' column (Direct PII) has been dropped for anonymization.")

# Update available columns after dropping 'Name'
current_cols = df_anon.columns.tolist()

# Safe defaults for QIs
default_qi = [c for c in ["Age", "Gender", "Zip"] if c in current_cols]
quasi_identifiers = st.sidebar.multiselect(
    "Select Quasi-Identifiers (QI)",
    current_cols,
    default=default_qi
)

# Safe default for sensitive attribute
if "Diagnosis" in current_cols:
    default_sensitive = "Diagnosis"
elif len(current_cols) > 0:
    default_sensitive = current_cols[-1]
else:
    default_sensitive = None

sensitive_attr = st.sidebar.selectbox(
    "Select Sensitive Attribute",
    current_cols,
    index=current_cols.index(default_sensitive) if default_sensitive in current_cols else 0
)

# Safe numeric column detection
numeric_cols_all = [c for c in current_cols if pd.api.types.is_numeric_dtype(df_anon[c])]
default_numeric = [c for c in ["Age"] if c in numeric_cols_all]

numeric_cols = st.sidebar.multiselect(
    "Numeric Columns for Differential Privacy",
    numeric_cols_all,
    default=default_numeric
)

# Privacy parameters
k = st.sidebar.slider("k (k-anonymity)", 2, 10, 3)
l = st.sidebar.slider("l (l-diversity)", 1, 5, 2)
t = st.sidebar.slider("t (t-closeness)", 0.0, 1.0, 0.25, step=0.05)
epsilon = st.sidebar.slider("ε (Differential Privacy)", 0.1, 5.0, 1.0, step=0.1)

# ------------------------------
# Apply button
# ------------------------------
if st.button("🔒 Apply Anonymization & Evaluate Risk", key="apply_btn_main"):
    with st.spinner("Applying privacy techniques..."):
        
        # 1. Evaluate risk before (using df_anon which has PII removed)
        if not quasi_identifiers:
             st.error("⚠️ Please select at least one quasi-identifier (QI) before applying anonymization.")
             st.stop()
             
        risk_before = reidentification_risk(df_anon, quasi_identifiers)

        # 2. Apply k-anonymity (an_k contains generalized columns like Age_g, Zip_g)
        #    qi_cols_anonymized contains the generalized column names (e.g., 'Age_g', 'Zip_g', 'Gender')
        an_k, stats_k, qi_cols_anonymized = apply_k_anonymity(df_anon, quasi_identifiers, k)

        # 3. Evaluate l-diversity and t-closeness (on the k-anonymized data)
        l_stats = l_diversity_check(an_k, qi_cols_anonymized, sensitive_attr, l)
        t_stats = t_closeness_check(an_k, qi_cols_anonymized, sensitive_attr, t)
        
        # 4. Apply differential privacy
        an_dp = apply_differential_privacy(an_k, numeric_cols, epsilon)

        # 5. Risk after (using the combined an_dp dataset and the generalized QI columns)
        risk_after = reidentification_risk(an_dp, qi_cols_anonymized)

    st.success("Anonymization Completed ✅")

    st.subheader("📊 Risk Evaluation Comparison")
    col1, col2 = st.columns(2)
    with col1:
        st.write("**Before Anonymization** (Risk based on original QIs)")
        st.json(risk_before)
    with col2:
        st.write("**After Anonymization** (Risk based on generalized QIs: **{}**)".format(", ".join(qi_cols_anonymized)))
        st.json(risk_after)

    st.subheader("k-Anonymity & Diversity Metrics")
    st.write(f"**Target k-Anonymity:** k={k} (Achieved minimum equivalence class size: **{stats_k['min_eq_size']}**)")
    st.write("**k-Anonymity Stats (based on generalized data):**", stats_k)
    st.write("**l-Diversity Stats (based on generalized data):**", l_stats)
    st.write("**t-Closeness Stats (based on generalized data):**", t_stats)

    st.subheader("🔍 Anonymized Dataset (Top 10 Rows)")
    st.write("Contains original columns, generalized QI columns (e.g., `Age_g`, `Zip_g`), and differentially private columns (e.g., `Age_dp`).")
    st.dataframe(an_dp.head(10))

    # Download anonymized CSV
    csv = an_dp.to_csv(index=False).encode('utf-8')
    st.download_button("📥 Download Anonymized CSV", csv, "anonymized_dataset.csv", "text/csv")

st.markdown("---")
st.caption("Educational demo — for learning only. Use professional anonymization libraries for production.")

