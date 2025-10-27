from src.parse_nvd import parse_nvd_feed
from src.normalize_deps import load_dependencies
from src.analyzer import analyze_dependencies

if __name__ == "__main__":


    # Step 2: Parse feed into structured CSV
    # df_nvd = parse_nvd_feed("data/nvd/nvdcve-2.0-2025.json")

    # Step 3: Load dependencies
    deps = load_dependencies("data/dependencies/requirements.txt")

    # # Step 4: Run analyzer
    results = analyze_dependencies(deps)

    print("\n🔎 Vulnerability Report:")
    print(results)

    results.to_csv("data/processed/dependency_analysis.csv", index=False)
    print("\nReport saved to data/processed/dependency_analysis.csv")
