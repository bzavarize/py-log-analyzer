import pandas as pd
import os


def analyze_logs(file_path):
    """
    Função para analisar logs de segurança em busca de padrões de Brute Force.
    """
    # 1. Verificação de existência do arquivo
    if not os.path.exists(file_path):
        print(f"❌ Erro: O arquivo '{file_path}' não foi encontrado no diretorio.")
        return

    try:
        # 2. Leitura robusta do arquivo CSV
        # sep=None + engine='python' detecta automaticamente se o separador é vírgula ou ponto-e-vírgula
        df = pd.read_csv(file_path, sep=None, engine='python', skip_blank_lines=True)

        # 3. Limpeza de dados (Data Cleaning)
        # Remove espaços em branco acidentais nas colunas de texto
        df = df.apply(lambda x: x.str.strip() if x.dtype == "object" else x)

        print(f"\n--- 🛡️  Iniciando Análise de Segurança: {file_path} ---")

        # 4. Lógica de Detecção de Brute Force
        # Filtramos apenas as entradas onde o status é 'fail'
        failures = df[df['status'].str.lower() == 'fail']

        # Contamos quantas vezes cada IP aparece nas falhas
        brute_force_check = failures['ip'].value_counts()

        # Definimos o limite de tentativas para gerar alerta
        threshold = 3
        alerts = brute_force_check[brute_force_check >= threshold]

        # 5. Apresentação dos Resultados
        if not alerts.empty:
            print(f"\n[⚠️  ALERTA] Possivel ataque de Brute Force detectado!")
            print("-" * 50)
            for ip, count in alerts.items():
                print(f"📍 IP Suspeito: {ip} | ❌ Tentativas Falhas: {count}")
            print("-" * 50)

            # BÔNUS: Salvando a evidência em um arquivo de log de incidentes
            with open("../incidentes_detectados.txt", "w") as f:
                f.write(f"Relatorio de Incidentes - Brute Force\n")
                f.write(f"Arquivo analisado: {file_path}\n")
                for ip, count in alerts.items():
                    f.write(f"IP: {ip} - Tentativas: {count}\n")
            print("\n[💾] Relatorio de evidencias salvo em 'incidentes_detectados.txt'")

        else:
            print("\n[✅] Nenhum padrao de ataque detectado. Ambiente integro.")

    except Exception as e:
        print(f"❌ Ocorreu um erro inesperado durante a analise: {e}")


# Ponto de entrada do script
if __name__ == "__main__":
    # Certifique-se de que o arquivo 'meus_logs.csv' esteja na mesma pasta
    analyze_logs('../data/meus_logs.csv')