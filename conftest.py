# Este código deve estar no arquivo conftest.py

import pytest

# Lista para armazenar os resultados de cada teste
test_results = []

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """
    Hook para capturar o resultado de cada teste executado.
    """
    outcome = yield
    report = outcome.get_result()

    if report.when == "call":
        level = item.callspec.params.get("level", "N/A") if hasattr(item, "callspec") else "N/A"
        

        vulnerabilidade_esperada = level in ["low", "medium"]
        
        if "piggybacked" in item.name or "error_based" in item.name:
            vulnerabilidade_esperada = level in ["low"]
            
        # Define a mensagem de resultado obtido com base no status do teste E na expectativa
        if report.passed:
            if vulnerabilidade_esperada:
                obtido = "✅ Vulnerabilidade detectada (Esperado)"
            else:
                obtido = "✅ Nenhuma vulnerabilidade (Esperado)"
        elif report.failed:
            if vulnerabilidade_esperada:
                obtido = "❌ ERRO: Vulnerabilidade NÃO detectada"
            else:
                obtido = "❌ ERRO: Falso positivo detectado"
        else: # report.skipped
            obtido = "⚠️ Teste pulado (skipped)"

        test_results.append({
            "teste": report.nodeid.split("::")[-1],
            "level": level,
            "passou": report.passed,
            "tempo": report.duration,
            "obtido": obtido
        })

def pytest_sessionfinish(session, exitstatus):
    """
    Hook executado no final de toda a sessão de testes para imprimir o relatório.
    """
    print("\n\n===== RELATÓRIO FINAL DE TESTES SQL INJECTION =====")
    if not test_results:
        print("Nenhum resultado de teste foi coletado.")
        return

    # Cabeçalho da tabela 
    header = f"{'Teste':<50} | {'Nível':<12} | {'Status':<8} | {'Resultado Obtido':<40} | {'Tempo (s)':<10}"
    separator = "-" * len(header)
    print(header)
    print(separator)

    # Imprime cada linha do resultado
    for r in test_results:
        status = "Passou" if r["passou"] else "Falhou"
        tempo_formatado = f"{r['tempo']:.2f}"
        print(f"{r['teste']:<50} | {r['level']:<12} | {status:<8} | {r['obtido']:<40} | {tempo_formatado:<10}")

    # Rodapé com o resumo
    total_passou = sum(1 for t in test_results if t["passou"])
    total_falhou = len(test_results) - total_passou
    print(separator)
    print(f"Total de testes:
     {len(test_results)} | ✅ Passaram: {total_passou} | ❌ Falharam: {total_falhou}")
    print("=" * len(header))