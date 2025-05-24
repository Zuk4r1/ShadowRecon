import json
import csv

def generate_report(results):
    print("[+] Generando reporte de hallazgos...")

    # Guardar JSON
    with open("report.json", "w") as f:
        json.dump(results, f, indent=4)

    # Generar Markdown avanzado
    with open("report.md", "w") as f:
        f.write("# ShadowRecon Report\n\n")
        # Resumen general
        total_items = sum(len(data) for data in results.values() if isinstance(data, list))
        f.write(f"**Resumen:** Se encontraron {total_items} hallazgos en {len(results)} categorías.\n\n")
        # Sección crítica si existe
        if "críticos" in results and results["críticos"]:
            f.write("## 🚨 Hallazgos Críticos\n")
            for item in results["críticos"]:
                f.write(f"- **{item}**\n")
            f.write("\n")
        # Secciones por categoría
        for section, data in results.items():
            if section == "críticos":
                continue
            f.write(f"## {section.capitalize()}\n")
            if data:
                for item in data:
                    if "vulnerabilidad" in str(item).lower() or "expuesto" in str(item).lower():
                        f.write(f"- **{item}**\n")
                    else:
                        f.write(f"- {item}\n")
            else:
                f.write("No se encontraron resultados.\n")
            f.write("\n")
        # Estadísticas
        f.write("## Estadísticas\n")
        for section, data in results.items():
            if isinstance(data, list):
                f.write(f"- {section.capitalize()}: {len(data)} hallazgos\n")
        f.write("\n")

    # Guardar CSV para análisis avanzado
    with open("report.csv", "w", newline='', encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Sección", "Hallazgo"])
        for section, data in results.items():
            if isinstance(data, list):
                for item in data:
                    writer.writerow([section, item])

    print("[+] Reporte generado en 'report.json', 'report.md' y 'report.csv'.")
