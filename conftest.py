import time
import pytest

test_results = []

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_call(item):
    start_time = time.time()
    outcome = yield
    duration = time.time() - start_time

    result = outcome.get_result()
    if result is None:  # Ignora quando não há resultado (ex: teardown)
        return

    test_id = item.name
    level = item.callspec.params.get("level", "N/A") if hasattr(item, "callspec") else "N/A"

    test_results.append({
        "teste": test_id,
        "level": level,
        "passou": result.passed,
        "tempo": round(duration, 2),
        "esperado": "Detectar vulnerabilidade",
        "obtido": "Detectado" if result.passed else "Não detectado"
    })

def pytest_sessionfinish(session, exitstatus):
    print("\n===== RELATÓRIO FINAL DE TESTES SQL INJECTION =====")
    if not test_results:
        print("Nenhum teste foi executado.")
        return

    header = f"{'Teste':<30} | {'Level':<10} | {'Status':<8} | {'Esperado':<25} | {'Obtido':<25} | {'Tempo (s)':<10}"
    separator = "-" * len(header)

    print(header)
    print(separator)

    for r in test_results:
        status = "Passou" if r["passou"] else "Falhou"
        print(f"{r['teste']:<30} | {r['level']:<10} | {status:<8} | {r['esperado']:<25} | {r['obtido']:<25} | {r['tempo']:<10}")

    print(separator)
    print(f"Total de testes: {len(test_results)} | Passaram: {sum(t['passou'] for t in test_results)} | Falharam: {sum(not t['passou'] for t in test_results)}")
