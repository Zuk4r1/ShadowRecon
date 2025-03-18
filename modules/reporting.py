import json

def generate_report(results):
    print("[+] Generando reporte de hallazgos...")

    with open("report.json", "w") as f:
        json.dump(results, f, indent=4)

    with open("report.md", "w") as f:
        f.write("# ShadowRecon Report\n\n")
        for section, data in results.items():
            f.write(f"## {section.capitalize()}\n")
            if data:
                for item in data:
                    f.write(f"- {item}\n")
            else:
                f.write("No se encontraron resultados.\n")
            f.write("\n")

    print("[+] Reporte generado en 'report.json' y 'report.md'.")
