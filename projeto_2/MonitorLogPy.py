import random
import datetime

def menu():
    nome_arq = 'log.txt'
    while True:
        print('MENU\n')
        print('1 - Gerar logs')
        print('2 - Analisar logs')
        print('3 - Gerar e Analisar logs')
        print('4 - SAIR')
        opc = int(input('Escolha uma opção: '))
        if opc == 1:
            try:
                qtd = int(input('Quantidade de logs(registros): '))
                gerarArquivo(nome_arq, qtd)
            except:
                print('Entrada inválida.')
        elif opc == 2:
            analisarLogs(nome_arq)
        elif opc == 3:
            try:
                qtd = int(input('Quantidade de logs(registros): '))
                gerarArquivo(nome_arq, qtd)
                analisarLogs(nome_arq)
            except:
                print('Entrada Invalida')
        elif opc == 4:
            print('Até Mais')
            break
        else:
            print('Opção Invalida')
            
def gerarArquivo(nome_arq, qtd):
    with open(nome_arq, 'w', encoding='UTF-8') as arq:
        for i in range(qtd):
            arq.write(montarLog(i) + '\n')
    print('Log gerado')
    
def montarLog(i):
    data        = gerarData(i)
    ip          = gerarIp(i)
    recurso     = gerarRecurso(i)
    metodo      = gerarMetodo(i)
    status      = gerarStatus(i, recurso)
    tempo       = gerarTempo(i, status)
    agente      = gerarAgente(i)
    protocolo   = gerarProtocolo(i)
    tamanho     = gerarTamanho(i)
    return f'[{data}] {ip} - {metodo} - {status} - {recurso} - {tempo}ms - {tamanho}B - {protocolo} - {agente} - /home'
    
def gerarData(i):
    base = datetime.datetime.now()
    delta = datetime.timedelta(seconds= i * random.randint(5,20))
    return (base + delta).strftime('%d/%m/%Y %H:%M:%S')

def gerarIp(i):
    r = random.randint(1,6)
    if i >= 20 and i <= 25:
        return '203.120.45.7'
    if r == 1:
        return '192.168.12.1'
    elif r == 2:
        return '192.168.12.3'
    elif r == 3:
        return '192.100.12.3'
    elif r == 4:
        return '192.168.162.3'
    elif r == 5:
        return '192.168.23.3'
    else:
        return '192.168.0.3'

def gerarRecurso(i):
    r = random.randint(1, 5)
    if r == 1: return '/home'
    elif r == 2: return '/login'
    elif r == 3: return '/admin'
    elif r == 4: return '/produtos'
    else: return '/contato'

def gerarMetodo(i):
    if i % 3 == 0: return 'POST'
    return 'GET'

def gerarStatus(i, recurso):
    r = random.randint(1, 10)
    if recurso == '/admin' and r > 7: return 403
    if i > 50 and i < 54: return 500
    if r == 9: return 404
    if r == 10: return 500
    return 200

def gerarTempo(i, status):
    if i > 40 and i < 45: return 800 + (i * 10)
    if status == 500: return 2000
    return random.randint(50, 900)

def gerarAgente(i):
    r = random.randint(1, 3)
    if i % 15 == 0: return 'GoogleBot'
    if r == 1: return 'Chrome'
    elif r == 2: return 'Firefox'
    else: return 'Safari'

def gerarProtocolo(i):
    if i % 2 == 0: return 'HTTP/1.1'
    return 'HTTP/2'

def gerarTamanho(i):
    return random.randint(100, 5000)

def analisarLogs(nome_arquivo):
    total_acessos = 0
    total_sucesso = 0
    total_erro = 0
    total_critico = 0
    soma_tempo = 0
    maior_tempo = 0
    menor_tempo = 99999
    rapidos = 0
    normais = 0
    lentos = 0
    s200 = 0
    s403 = 0
    s404 = 0
    s500 = 0
    
    indevidos_admin = 0
    sensiveis_total = 0
    sensiveis_falhas = 0
    
    ultimo_ip = ""
    ip_mais_ativo = ""
    max_acessos_ip = 0
    ip_mais_erros = ""
    max_erros_ip = 0
    
    forca_bruta_eventos = 0
    ultimo_ip_fb = ""
    seq_fb = 0
    
    degradacao_eventos = 0
    seq_degradacao = 0
    ultimo_tempo = 0
    
    falha_critica_eventos = 0
    seq_500 = 0
    
    bot_eventos = 0
    ultimo_ip_bot = ""
    seq_ip_bot = 0
    ultimo_ip_processado = ""
    
    with open(nome_arquivo, 'r', encoding='UTF-8') as arq:
        for linha in arq:
            if linha.strip() == "": continue
            
            total_acessos += 1
            
            p1 = 0
            while linha[p1] != ']': p1 += 1
            data_hora = linha[1:p1]
            
            p2 = p1 + 2
            p3 = p2
            while linha[p3] != ' ': p3 += 1
            ip = linha[p2:p3]
            
            p4 = p3 + 3
            p5 = p4
            while linha[p5] != ' ': p5 += 1
            metodo = linha[p4:p5]
            
            p6 = p5 + 3
            p7 = p6
            while linha[p7] != ' ': p7 += 1
            status = int(linha[p6:p7])
            
            p8 = p7 + 3
            p9 = p8
            while linha[p9] != ' ': p9 += 1
            recurso = linha[p8:p9]
            
            p10 = p9 + 3
            p11 = p10
            while linha[p11] != 'm': p11 += 1
            tempo = int(linha[p10:p11])
            
            p12 = p11 + 5
            p13 = p12
            while linha[p13] != 'B': p13 += 1
            tamanho = linha[p12:p13]
            
            p14 = p13 + 4
            p15 = p14
            while linha[p15] != ' ': p15 += 1
            protocolo = linha[p14:p15]
            
            p16 = p15 + 3
            p17 = p16
            while linha[p17] != ' ': p17 += 1
            agente = linha[p16:p17]
            
            if status == 200:
                total_sucesso += 1
                s200 += 1
            else:
                total_erro += 1
                if status == 403: s403 += 1
                elif status == 404: s404 += 1
                elif status == 500: 
                    s500 += 1
                    total_critico += 1

            soma_tempo += tempo
            if tempo > maior_tempo: maior_tempo = tempo
            if tempo < menor_tempo: menor_tempo = tempo
            
            if tempo < 200: rapidos += 1
            elif tempo < 800: normais += 1
            else: lentos += 1
            
            if recurso == '/admin' and status != 200:
                indevidos_admin += 1
                
            if recurso == '/admin' or recurso == '/backup' or recurso == '/config' or recurso == '/private':
                sensiveis_total += 1
                if status != 200: sensiveis_falhas += 1
            
            if ip == ultimo_ip_processado and recurso == '/login' and status == 403:
                seq_fb += 1
                if seq_fb == 3:
                    forca_bruta_eventos += 1
                    ultimo_ip_fb = ip
            else:
                seq_fb = 0
                
            if tempo > ultimo_tempo:
                seq_degradacao += 1
                if seq_degradacao == 3:
                    degradacao_eventos += 1
            else:
                seq_degradacao = 0
            ultimo_tempo = tempo
            
            if status == 500:
                seq_500 += 1
                if seq_500 == 3:
                    falha_critica_eventos += 1
            else:
                seq_500 = 0
                
            is_bot_agent = False
            if 'Bot' in agente or 'Crawler' in agente or 'Spider' in agente:
                is_bot_agent = True
                
            if ip == ultimo_ip_processado:
                seq_ip_bot += 1
                if seq_ip_bot == 5 or is_bot_agent:
                    bot_eventos += 1
                    ultimo_ip_bot = ip
            else:
                seq_ip_bot = 1
                if is_bot_agent:
                    bot_eventos += 1
                    ultimo_ip_bot = ip
            
            ultimo_ip_processado = ip

    media_tempo = soma_tempo / total_acessos if total_acessos > 0 else 0
    disponibilidade = (total_sucesso / total_acessos) * 100 if total_acessos > 0 else 0
    taxa_erro = (total_erro / total_acessos) * 100 if total_acessos > 0 else 0
    
    estado = "SAUDÁVEL"
    if falha_critica_eventos >= 1 or disponibilidade < 70:
        estado = "CRÍTICO"
    elif disponibilidade < 85 or lentos > (total_acessos * 0.3):
        estado = "INSTÁVEL"
    elif disponibilidade < 95 or bot_eventos > 0 or forca_bruta_eventos > 0:
        estado = "ATENÇÃO"

    print("-" * 30)
    print("RELATÓRIO TÉCNICO - MONITOR LOGPY")
    print("-" * 30)
    print(f"Total de acessos: {total_acessos}")
    print(f"Total de sucessos: {total_sucesso}")
    print(f"Total de erros: {total_erro}")
    print(f"Total de erros críticos: {total_critico}")
    print(f"Disponibilidade: {disponibilidade:.2f}%")
    print(f"Taxa de erro: {taxa_erro:.2f}%")
    print(f"Tempo médio: {media_tempo:.2f}ms")
    print(f"Maior tempo: {maior_tempo}ms")
    print(f"Menor tempo: {menor_tempo}ms")
    print(f"Acessos rápidos: {rapidos}")
    print(f"Acessos normais: {normais}")
    print(f"Acessos lentos: {lentos}")
    print(f"Status 200: {s200}")
    print(f"Status 403: {s403}")
    print(f"Status 404: {s404}")
    print(f"Status 500: {s500}")
    print(f"Acessos indevidos /admin: {indevidos_admin}")
    print(f"Eventos de força bruta: {forca_bruta_eventos}")
    print(f"Último IP força bruta: {ultimo_ip_fb}")
    print(f"Eventos de degradação: {degradacao_eventos}")
    print(f"Eventos de falha crítica: {falha_critica_eventos}")
    print(f"Suspeitas de bot: {bot_eventos}")
    print(f"Último IP bot: {ultimo_ip_bot}")
    print(f"Acessos rotas sensíveis: {sensiveis_total}")
    print(f"Falhas rotas sensíveis: {sensiveis_falhas}")
    print(f"ESTADO FINAL: {estado}")
    print("-" * 30)

menu()
