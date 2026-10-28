# -*- coding: utf-8 -*-
"""
release_alert.py
Monitora divulgacoes de resultados (earnings / releases) e envia e-mail
quando um novo documento e publicado.

Fontes (tempo (quase) real, gratuitas e oficiais):
  * SEC EDGAR  -> empresas de tecnologia dos EUA (8-K item 2.02) + TSM/ASML (6-K)
  * CVM / RAD  -> empresas listadas na B3 (categoria "Dados Economico-Financeiros")

Nao envia nada quando nao ha documento novo desde a ultima execucao.
Roda de forma independente do app do Claude (agendado pelo Windows).
"""

import json
import os
import re
import sys
import time
import unicodedata
import smtplib
import logging
import datetime as dt
import urllib.request
import http.cookiejar
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

# ---------------------------------------------------------------------------
# Caminhos
# ---------------------------------------------------------------------------
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
CONFIG     = os.path.join(BASE_DIR, "config.json")
STATE      = os.path.join(BASE_DIR, "state.json")
HEARTBEAT  = os.path.join(BASE_DIR, "heartbeat.json")
LOG_FILE   = os.path.join(BASE_DIR, "release_alert.log")

# ---------------------------------------------------------------------------
# Watchlists
# ---------------------------------------------------------------------------
# EDGAR: ticker -> CIK. 8-K (item 2.02 = resultados) para empresas dos EUA.
# EDGAR: emissoras DOMESTICAS que divulgam resultado via 8-K item 2.02.
# Cobertura: Nasdaq-100 tech + setor de TI do S&P 500 + principais SaaS/cloud/
# fintech-tech + os bancos/financas globais. (ticker -> CIK da SEC)
EDGAR_8K = {
    "AAPL": 320193, "MSFT": 789019, "NVDA": 1045810, "GOOGL": 1652044,
    "AMZN": 1018724, "META": 1326801, "TSLA": 1318605, "AVGO": 1730168,
    "AMD": 2488, "NFLX": 1065280, "CRM": 1108524, "ORCL": 1341439,
    "ADBE": 796343, "BKNG": 1075531, "MELI": 1099590, "INTC": 50863,
    "QCOM": 804328, "PLTR": 1321655, "UBER": 1543151, "IBM": 51143,
    "CSCO": 858877, "NOW": 1373715,
    # Financas globais (todos divulgam resultado via 8-K item 2.02)
    "JPM": 19617, "BAC": 70858, "C": 831001, "WFC": 72971,
    "GS": 886982, "MS": 895421, "BLK": 2012383, "AXP": 4962,
    "V": 1403161, "MA": 1141391, "SCHW": 316709,
    # Semicondutores + hardware
    "INTU": 896878, "TXN": 97476, "AMAT": 6951, "ADP": 8670,
    "MU": 723125, "LRCX": 707549, "KLAC": 319201, "ADI": 6281,
    "MRVL": 1835632, "MCHP": 827054, "NXPI": 1413447, "ON": 1097864,
    "SWKS": 4127, "QRVO": 1604778, "MPWR": 1280452, "TER": 97210,
    "ENPH": 1463101, "FSLR": 1274494, "SMCI": 1375365, "GFS": 1709048,
    "MSI": 68505, "ANET": 1596532, "APH": 820313, "GLW": 24741,
    "KEYS": 1601046, "DELL": 1571996, "HPQ": 47217, "HPE": 1645590,
    "STX": 1137789, "WDC": 106040, "NTAP": 1002047, "ZBRA": 877212,
    "TRMB": 864749, "GRMN": 1121788, "FFIV": 1048695,
    # Software / SaaS / cloud
    "PANW": 1327567, "SNPS": 883241, "CDNS": 813672, "CRWD": 1535527,
    "FTNT": 1262039, "ROP": 882835, "WDAY": 1327811, "TEAM": 1650372,
    "ADSK": 769397, "FICO": 814547, "IT": 749251, "HUBS": 1404655,
    "DDOG": 1561550, "SNOW": 1640147, "ZS": 1713683, "NET": 1477333,
    "TTD": 1671933, "MDB": 1441816, "OKTA": 1660134, "TWLO": 1447669,
    "ZM": 1585521, "DOCU": 1261333, "TYL": 860731, "PTC": 857005,
    "AKAM": 1086222, "EPAM": 1352010, "JKHY": 779152, "VRSN": 1014473,
    "ESTC": 1707753, "S": 1583708, "BILL": 1786352, "ASAN": 1477720,
    "PATH": 1734722, "GTLB": 1653482, "BOX": 1372612, "DBX": 1467623,
    "APPF": 1433195, "BRZE": 1676238, "PD": 1568100, "FSLY": 1517413,
    "AI": 1577526, "CFLT": 1699838, "CTSH": 1058290, "ACN": 1467373,
    "CDW": 1402057, "GEN": 849399,
    # Internet / plataformas / fintech-tech
    "DASH": 1792789, "ABNB": 1559720, "HOOD": 1783879, "COIN": 1679788,
    "PYPL": 1633917, "FIS": 1136893, "GPN": 1123360, "PAYX": 723531,
    "PCTY": 1591698, "PAYC": 1590955, "FI": 798354, "XYZ": 1512673,
    "RDDT": 1713445, "PINS": 1506293, "SNAP": 1564408, "ROKU": 1428439,
    "LYFT": 1759509, "ETSY": 1370637, "EBAY": 1065088, "Z": 1617640,
    "GTM": 1794515,
}
# EDGAR: emissores estrangeiros que reportam via 6-K.
# 6-K e usado para MUITA coisa (troca de diretor, AGM, dividendo...) e os nomes
# de arquivo sao opacos, entao verificamos o CONTEUDO do documento (ver
# verify_earnings_6k) e so alertamos quando parece um relatorio de resultados.
EDGAR_6K = {
    "TSM": 1046179, "ASML": 937966, "SHOP": 1594805, "SAP": 1000184,
    "SPOT": 1639920, "SE": 1703399, "GRAB": 1855612, "GLOB": 1557860,
    "NICE": 1003935, "WIX": 1576789, "MNDY": 1845338, "STNE": 1745431,
    "PAGS": 1712807, "NU": 1691493, "ARM": 1973239, "CYBR": 1598110,
}
# EDGAR: empresas cujo resultado sai no relatorio periodico (10-Q/10-K) e NAO
# num 8-K item 2.02. Ex.: Berkshire Hathaway divulga junto com o 10-Q/10-K.
EDGAR_10KQ = {"BRK": 1067983}
# Sinais textuais de "relatorio de resultados" (exige >= 3 distintos no documento)
EARNINGS_TEXT_SIGNALS = (
    "net income", "earnings per share", "results of operations", "gross margin",
    "operating income", "diluted", "quarter ended", "months ended",
    "cash flow", "net sales", "total revenue", "operating profit",
)

# CVM / B3: Codigo_CVM (numerico) -> nome curto/ticker.
CVM_WATCH = {
    94: "PANATLANTICA",
    701: "BIOMA EDUCAÇÃO S.A",
    906: "Bradesco (BBDC4)",
    922: "BANCO DA AMAZONIA S.A",
    1023: "Banco do Brasil (BBAS3)",
    1120: "BANESE",
    1155: "BANESTES S/A",
    1171: "BANPARÁ S.A",
    1210: "BANRISUL S/A",
    1228: "BANCO DO NORDESTE",
    1309: "BANCO MERCANTIL DE INVESTIMENTOS SA",
    1325: "BANCO MERCANTIL DO BRASIL S/A",
    1520: "BARDELLA",
    1562: "BAUMER",
    1570: "EXCELSIOR",
    1694: "MONARK",
    2100: "PENALTY",
    2429: "IRANI PAPEL E EMBALAGEM S.A",
    2437: "Axia Energia / Eletrobras (ELET3)",
    2453: "Cemig (CMIG4)",
    2461: "CELESC",
    3050: "AMPLA",
    3069: "FERBASA",
    3077: "CIA. DE FIAÇÃO E TECIDOS CEDRO CACHOEIRA",
    3190: "REDE ENERGIA PARTICIPAÇÕES S.A",
    3298: "CIA HABITASUL DE PARTICIPAÇÕES",
    3328: "CHESF",
    3395: "COMPANHIA INDUSTRIAL CATAGUASES",
    3450: "INDL ITAUNENSE",
    3654: "MELHORAMENTOS",
    3980: "Gerdau (GGBR4)",
    4030: "CSN (CSNA3)",
    4146: "KARSTEN",
    4170: "Vale (VALE3)",
    4448: "COBRASMA S/A",
    4537: "GRAZZIOTIN",
    4669: "GUARARAPES CONFECÇÕES",
    4693: "CONSERVAS ODERICH SA",
    4723: "CAL S/A",
    4782: "MENDES JUNIOR ENGENHARIA S/A",
    4820: "Braskem (BRKM5)",
    5207: "DOHLER",
    5258: "Raia Drogasil (RADL3)",
    5312: "MUNDIAL",
    5380: "ELECTRO AÇO ALTONA S/A",
    5410: "WEG (WEGE3)",
    5762: "ETERNIT",
    5770: "EUCATEX",
    5983: "SÃO JOSÉ",
    6041: "INVESTIMENTOS BEMGE",
    6173: "TAURUS ARMAS S.A",
    6211: "FRASLE MOBILITY S.A",
    6343: "TUPY",
    6505: "PONTO FRIO",
    6629: "HERCULES S/A",
    6700: "HOTEIS OTHON S.A",
    7510: "ROMI S.A",
    7544: "RENAUXVIEW",
    7595: "INEPAR S/A",
    7617: "Itausa (ITSA4)",
    7811: "JOÃO FORTES ENGENHARIA S.A",
    7870: "KEPLER WEBER SA",
    8133: "Lojas Renner (LREN3)",
    8192: "TREVISA INVESTIMENTOS SA",
    8397: "MANGELS",
    8427: "ESTRELA",
    8451: "Marcopolo (POMO4)",
    8575: "MAHLE METAL LEVE",
    8656: "Metalurgica Gerdau (GOAU4)",
    8672: "Iguatemi (IGTI11)",
    8745: "METANOR S.A METANOL DO NORDESTE",
    8753: "METISA",
    8818: "MINASMÁQUINAS S/A",
    9067: "SUZANO HOLDING S.A",
    9083: "NORDON INDS METALURGICAS SA",
    9342: "PANVEL FARMÁCIAS",
    9393: "PARANAPANEMA S.A",
    9415: "SÃO PAULO TURISMO S. A",
    9512: "Petrobras (PETR)",
    9520: "PETROLUSA",
    9717: "PORTUENSE",
    9954: "ALFA HOLDINGS",
    9989: "REFINARIA DE PETRÓLEOS DE MANGUINHOS S.A",
    10243: "CHAPECO",
    10456: "ALPARGATAS",
    10561: "SEIVA S.A. - FLORESTAS E INDÚSTRIAS",
    10880: "SONDOTECNICA S/A",
    11070: "WLM",
    11215: "TECBLU",
    11258: "TELEBRAS",
    11312: "BRASIL TELECOM S.A",
    11398: "MILLENNIUM INORGANIC CHEMICALS DO BRASIL",
    11592: "UNIPAR CARBOCLORO S.A",
    11762: "VULCABRAS S/A",
    11932: "IOCHPE-MAXION",
    11975: "AZEVEDO & TRAVASSOS",
    11991: "WETZEL S.A",
    12190: "BOMBRIL S.A. - EM RECUPERAÇÃO JUDICIAL",
    12572: "RECRUSUL",
    12653: "Klabin (KLBN11)",
    12696: "SANSUY S.A. INDÚSTRIA DE PLÁSTICOS",
    12823: "ALIPERTI S.A",
    13030: "CONSTRUTORA SULTEPA S/A",
    13285: "JOSAPAR S/A",
    13366: "HAGA",
    13439: "METALURGICA RIOSULENSE S/A",
    13447: "POLPAR S.A",
    13471: "PLASCAR PARTICIPAÇÕES INDUSTRIAIS S.A",
    13765: "MINUPAR",
    13773: "PORTOBELLO S/A",
    13781: "SÃO CARLOS EMPREEND.E PARTICIPAÇÕES S.A",
    13854: "CIA MARCOPOLO",
    13986: "Suzano (SUZB3)",
    14109: "RANDON S.A. IMPLEMENTOS E PARTICIPAÇÕES",
    14206: "BRB",
    14311: "Copel (CPLE6)",
    14320: "Usiminas (USIM5)",
    14346: "WHIRLPOOL S.A",
    14443: "Sabesp (SBSP3)",
    14451: "CEB - COMPANHIA ENERGÉTICA DE BRASÍLIA",
    14460: "Cyrela (CYRE3)",
    14524: "Coelba (CEEB3)",
    14605: "ENERGISA MATO GROSSO - DISTRIBUIDORA DE ENERGIA S.A",
    14664: "SCHULZ",
    14680: "PARCOM PARTICIPACOES SA EM LIQUIDACAO",
    14796: "FORPART SA",
    14826: "PÃO DE AÇÚCAR",
    14869: "CIA ENERG CEARA - COELCE",
    15091: "LITEL PARTICIPACOES",
    15253: "Energisa (ENGI11)",
    15369: "FERROVIA CENTRO-ATLÂNTICA S.A",
    15407: "PORTO PONTA DO FELIX S",
    15423: "FICTOR ALIMENTOS S.A",
    15458: "EMBPAR PARTICIPAÇÕES S/A",
    15636: "Comgas (CGAS3/CGAS5)",
    16101: "GAFISA",
    16241: "SANASA-CAMPINAS",
    16268: "MARINA PARK",
    16284: "524 PARTICIPACOES SA",
    16292: "BRF (BRFS3)",
    16373: "CEDAE",
    16438: "OPPORTUNITY SUL S.A",
    16560: "BONAIRE",
    16586: "SUDESTE S.A",
    16608: "EQUATORIAL MARANHÃO DISTRIBUIDORA DE ENERGIA S.A",
    16616: "CEG",
    16632: "DEXXOS PARTICPAÇÕES S.A",
    16659: "Porto Seguro (PSSA3)",
    16705: "ALEF S/A",
    16861: "CASAN",
    16993: "EMAE",
    17329: "Engie Brasil (EGIE3)",
    17434: "LONGDIS SA",
    17450: "Rumo (RAIL3)",
    17485: "ELEKTRO REDES S.A",
    17493: "CAPITALPART PARTICIPAÇÕES S.A",
    17540: "NEWTEL PARTICIPAÇÕES S.A. - EM LIQUIDAÇÃO",
    17671: "Telefonica/Vivo (VIVT3)",
    17868: "INEPAR",
    17884: "BETAPART PARTICIPAÇÕES SA",
    17949: "MRS LOGÍSTICA S/A",
    17965: "GAMA PARTICIPAÇÕES SA",
    17973: "Cogna (COGN3)",
    18309: "EQUATORIAL PARÁ DISTRIBUIDORA DE ENERGIA S.A",
    18333: "PROMPT PARTICIPAÇÕES S/A",
    18368: "DUKE ENERGY INT,GERAÇÃO PARANAPANEMA SA",
    18376: "ISA Energia (ISAE4)",
    18414: "PADTEC HOLDING S.A.",
    18465: "Ultrapar (UGPA3)",
    18546: "CAGECE",
    18589: "INVESTCO S.A",
    18597: "DTCOM",
    18627: "SANEPAR",
    18660: "CPFL Energia (CPFE3)",
    18708: "CIA. DE PARTICIPAÇÕES ALIANÇA DA BAHIA",
    18724: "Bradespar (BRAP4)",
    18775: "INVEPAR",
    18821: "Motiva (MOTV3)",
    19097: "CAIANDA PARTICIPAÇÕES S.A",
    19100: "CONTAX PARTICIPAÇÕES S.A. - EM RECUPERAÇÃO JUDICIAL",
    19119: "CABINDA PARTICIPAÇÕES S.A",
    19135: "CACONDE PARTICIPAÇÕES S.A",
    19208: "CRT SA",
    19232: "PROMAN",
    19305: "BIOMM SA",
    19330: "TPI",
    19348: "Itau Unibanco (ITUB4)",
    19445: "Copasa (CSMG3)",
    19453: "ECORODOVIAS INFRAESTRUTURA E LOGÍSTICA S.A",
    19550: "Natura (NTCO3)",
    19569: "Gol (GOLL4)",
    19615: "GRENDENE SA",
    19623: "DIAGNOSTICOS DA AMERICA SA",
    19739: "Localiza (RENT3)",
    19836: "Cosan (CSAN3)",
    19879: "LIGHT S.A. - EM RECUPERAÇÃO JUDICIAL",
    19992: "Totvs (TOTS3)",
    20010: "Equatorial (EQTL3)",
    20028: "AMERICAN BANKNOTE COMPANY",
    20036: "BRASILAGRO CIA BRAS DE PROP AGRICOLAS",
    20044: "CSU DIGITAL S.A",
    20060: "LUPATECH",
    20087: "Embraer (EMBR3)",
    20125: "BRADSAÚDE S.A",
    20257: "Taesa (TAEE11)",
    20338: "M DIAS BRANCO SA IND E COM DE ALIMENTOS",
    20346: "PROFARMA",
    20362: "POSITIVO INFORMATICA SA",
    20370: "LOPES",
    20435: "TECNISA S/A",
    20478: "PDG REALTY SA EMPREENDIMENTOS E PARTS",
    20516: "SÃO MARTINHO SA",
    20524: "EVEN",
    20532: "Santander BR (SANB11)",
    20567: "BANCO PINE S/A",
    20575: "JBS (JBSS3)",
    20605: "JHSF",
    20613: "METALFRIO SOLUTIONS S/A",
    20621: "FERTILIZANTES HERINGER SA",
    20630: "CR2 EMPREENDIMENTOS IMOBILIÁRIOS S/A",
    20648: "CEEE-D",
    20702: "VIVER",
    20710: "LOG-IN LOGISTICA INTERMODAL SA",
    20729: "PARANA",
    20745: "SLC Agricola (SLCE3)",
    20770: "EZ TEC EMPREEND. E PARTICIPAÇÕES S/A",
    20788: "Marfrig (MRFG3)",
    20800: "TEGMA GESTÃO LOGÍSTICA SA",
    20877: "HELBOR",
    20915: "MRV (MRVE3)",
    20931: "Minerva (BEEF3)",
    20958: "BANCO ABC BRASIL S/A",
    20982: "Multiplan (MULT3)",
    20990: "AMERICANAS S.A. - EM RECUPERAÇÃO JUDICIAL",
    21008: "GENERAL SHOPPING BRASIL SA",
    21016: "Yduqs (YDUQ3)",
    21040: "SYN PROP & TECH S.A",
    21067: "MOURA DUBEUX",
    21091: "DEXCO S.A",
    21130: "TRISUL",
    21148: "CONSTRUTORA TENDA S/A",
    21180: "NEXPE PARTICIPAÃiES S.A",
    21202: "VIX LOGÍSTICA S/A",
    21237: "Eneva (ENEV3)",
    21334: "NUTRIPLANT",
    21342: "OSX BRASIL S.A. - EM RECUPERAÇÃO JUDICIAL",
    21350: "Direcional (DIRR3)",
    21393: "CELGPAR",
    21431: "Hypera (HYPE3)",
    21440: "LE LIS BLANC DEUX",
    21490: "ALUPAR INVESTIMENTO S/A",
    21610: "B3 (B3SA3)",
    21636: "RENOVA ENERGIA S/A",
    21733: "Cielo (CIEL3)",
    21881: "Fleury (FLRY3)",
    22012: "MILLS ESTRUTURAS E SERVIÇOS DE ENGENHARIA S/A",
    22020: "JSL S.A",
    22055: "MARISA LOJAS SA",
    22179: "AFLUENTE TRANSMISSÃO DE ENERGIA ELETRICA S/A",
    22187: "PRIO (PRIO3)",
    22349: "Azzas 2154 (AZZA3)",
    22357: "Allos (ALOS3)",
    22454: "T4F ENTRETENIMENTO SA",
    22470: "Magazine Luiza (MGLU3)",
    22497: "QUALICORP CONSULTORIA E CORRETORA DE SEGUROS S.A",
    22500: "BRASIL PHARMA SA - EM RECUPERAÇÃO JUDICIAL",
    22519: "TECHNOS SA",
    22560: "INBRANDS SA",
    22586: "MLOG S.A",
    22608: "EMPREENDIMENTOS PAGUE MENOS SA",
    22616: "BTG Pactual (BPAC11)",
    22675: "HIDROVIAS DO BRASIL S.A",
    22780: "UNICASA INDÚSTRIA DE MÓVEIS S.A",
    23159: "BB Seguridade (BBSE3)",
    23175: "COMPANHIA DE AGUAS DO BRASIL - CAB AMBIENTAL",
    23221: "SER EDUCACIONAL S.A",
    23248: "ANIMA HOLDING S/A",
    23264: "Ambev (ABEV3)",
    23272: "LOG COMMERCIAL PROPERTIES E PARTICIPAÇÕES S.A",
    23280: "UNIDAS LOCAÇÕES E SERVIÇOS S.A",
    23302: "QUALITY SOFWARE S.A",
    23310: "CVC (CVCB3)",
    23396: "AEGEA SANEAMENTO E PARTICIPAÇÕES S.A",
    23507: "OUROFINO S.A",
    23531: "CLARO TELECOM PARTICIPAÇÕES S.A",
    23574: "INTERNATIONAL MEAL COMAPANY ALIMENTAÇÃO S.A",
    23590: "WIZ CO PARTICIPAÇÕES E CORRETAGEM DE SEGUROS S.A",
    23604: "YOU INC INCORPORADORA E PARTICIPAÇÕES S.A",
    23612: "MAESTRO LOCADORA DE VEÍCULOS S.A",
    23620: "OCEANA OFFSHORE S.A",
    23795: "Caixa Seguridade (CXSE3)",
    23817: "BRQ SOLUÇÕES EM INFORMÁTICA S.A",
    23825: "MOVIDA PARTICIPAÇÕES S.A",
    23981: "CTC - CENTRO DE TECNOLOGIA CANAVIEIRA S.A",
    24058: "ALLIANÇA SAÚDE E PARTICIPAÇÕES S.A",
    24112: "Azul (AZUL4)",
    24180: "IRB - BRASIL RESSEGUROS S.A",
    24228: "CAMIL ALIMENTOS S/A",
    24236: "PRINER SERVIÇOS INDUSTRIAIS S.A",
    24260: "Smart Fit (SMFT3)",
    24279: "INC EMPREENDIMENTOS IMOBILIÁRIOS S.A",
    24295: "Vibra (VBBR3)",
    24392: "Hapvida (HAPV3)",
    24546: "PRÁTICA KLIMAQUIP INDÚSTRIA E COMÉRCIO S.A",
    24600: "BANCO BMG S/A",
    24627: "BLAU FARMACÊUTICA S.A",
    24660: "BBM LOGÍSTICA S.A",
    24694: "GRUPO SBF S.A",
    24716: "Vamos (VAMO3)",
    24759: "LITELA PARTICIPAÇÕES S.A",
    24805: "Vivara (VIVA3)",
    24821: "Rede D'Or (RDOR3)",
    24830: "BRK AMBIENTAL PARTICIPAÇÕES S.A",
    24848: "C&A Modas (CEAB3)",
    24872: "LIFEMED INDUSTRIAL DE EQUIP. E ART. MEDICOS E HOSP. S.A",
    24902: "MITRE REALTY EMPREENDIMENTOS E PARTICIPAÇÕES S.A",
    24910: "LWSA S/A",
    24929: "TIM (TIMS3)",
    24953: "ALLPARK EMPREENDIMENTOS, PARTICIPAÇÕES E SERVIÇOS S.A",
    24961: "AMBIPAR PARTICIPAÇÕES E EMPREENDIMENTOS S.A",
    25003: "SIMPAR S.A",
    25038: "LOJAS QUERO-QUERO S.A",
    25046: "D1000 VAREJO FARMA PARTICIPAÇÕES S.A",
    25062: "LAVVI EMPREENDIMENTOS IMOBILIÁRIOS S.A",
    25070: "PLANO & PLANO DESENVOLVIMENTO IMOBILIÁRIO S.A",
    25097: "NORTE ENERGIA S.A",
    25100: "Cury (CURY3)",
    25119: "MELNICK EVEN DESENVOLVIMENTO IMOBILIÁRIO S.A",
    25127: "Compass Gas e Energia (Cosan)",
    25143: "PACAEMBU CONSTRUTORA S.A",
    25160: "SEQUOIA LOGÍSTICA E TRANSPORTES S.A",
    25186: "GRUPO MATEUS S.A",
    25194: "ALARES INTERNET PARTICIPAÇÕES S/A",
    25208: "TRACK & FIELD CO S.A",
    25232: "MELIUZ S.A",
    25259: "ENJOEI S.A",
    25275: "ALPHAVILLE S.A",
    25283: "AERIS IND. E COM. DE EQUIP. PARA GER. DE ENG. S.A",
    25291: "Brava (BRAV3)",
    25305: "PATRIMAR ENGENHARIA S.A",
    25330: "ALLIED TECNOLOGIA S.A",
    25348: "ELFA MEDICAMENTOS S.A",
    25372: "Assai/Sendas (ASAI3)",
    25380: "EZ INC INCORPORAÇÕES S.A",
    25399: "NEOGRID PARTICIPAÇÕES S.A",
    25402: "HBR REALTY EMPREENDIMENTOS IMOBILIÁRIOS S.A",
    25429: "FARMÁCIA E DROGARIA NISSEI S.A",
    25437: "URBA DESENVOLVIMENTO URBANO S.A",
    25445: "MPM CORPÓREOS S.A",
    25453: "INTELBRAS S.A",
    25461: "GRUPO TOKY S.A. - EM RECUPERAÇÃO JUDICIAL",
    25496: "JALLES MACHADO S.A",
    25500: "BEMOBI MOBILE TECH S.A",
    25518: "WESTWING COMÉRCIO VAREJISTA S.A",
    25526: "CRUZEIRO DO SUL EDUCACIONAL S.A",
    25534: "OCEANPACT SERVIÇOS MARÍTIMOS S.A",
    25542: "CVLB BRASIL S.A",
    25550: "ORIZON VALORIZAÇÃO DE RESÍDUOS S.A",
    25585: "CSN Mineracao (CMIN3)",
    25631: "KALUNGA S.A",
    25658: "AGROGALAXY PARTICIPAÇÕES S.A. - EM RECUPERAÇÃO JUDICIAL",
    25674: "HMOBI PARTICIPAÇÕES S.A",
    25682: "CM HOSPITALAR S.A",
    25690: "HOSPITAL MATER DEI S.A",
    25704: "BOA SAFRA SEMENTES S.A",
    25712: "GPS PARTICIPAÇÕES E EMPREENDIMENTOS S/A",
    25720: "RIO ALTO ENERGIAS RENOVÁVEIS S.A",
    25747: "INFRACOMMERCE CXAAS S.A",
    25763: "VITTIA S.A",
    25771: "CALEDÔNIA SAÚDE S.A",
    25780: "PetroReconcavo (RECV3)",
    25798: "KALLAS INCORPORAÇÕES E CONSTRUÇÕES S.A",
    25801: "RODOBENS S.A",
    25836: "DOTZ S.A",
    25844: "TEGRA INCORPORADORA S.A",
    25852: "W2W E-COMMERCE DE VINHOS S.A",
    25860: "BRBI BR PARTNERS S.A",
    25887: "GETNINJAS S.A",
    25895: "LIVETECH DA BAHIA INDÚSTRIA E COMÉRCIO S.A",
    25909: "EMCCAMP RESIDENCIAL S.A",
    25917: "RAÍZEN S.A",
    25925: "BIONEXO S.A",
    25950: "TRÊS TENTOS AGROINDUSTRIAL S.A",
    25984: "COMPANHIA BRASILEIRA DE ALUMINIO",
    26000: "TS AGRO S.A",
    26026: "DESKTOP S.A",
    26034: "GRUPO MULTILASER S.A",
    26050: "UNIFIQUE TELECOMUNICAÇÕES S.A",
    26069: "ARMAC LOCAÇÃO, LOGÍSTICA E SERVIÇOS S.A",
    26077: "TC S.A",
    26123: "ONCOCLÍNICAS DO BRASIL SERVIÇOS MÉDICOS S.A",
    26166: "GRUPO FARTURA DE HORTIFRUT S.A",
    26174: "AUREN OPERAÇÕES S.A",
    26182: "LABORATÓRIO TEUTO BRASILEIRO S.A",
    26190: "CARAMURU ALIMENTOS S.A",
    26204: "BLUEFIT ACADEMIAS DE GINÁSTICA E PARTICIPAÇÕES S.A",
    26271: "ENVIRONMENTAL ESG PARTICIPAÇÕES S.A",
    26280: "COMERC ENERGIA S.A",
    26379: "MADERO INDÚSTRIA E COMÉRCIO S.A",
    26395: "ALMEIDA JUNIOR SHOPPING CENTERS S.A",
    26409: "VERO S.A",
    26433: "ALVAREZ & MARSAL INVESTIMENTOS I S.A",
    26506: "LUPO S.A",
    26522: "CERRADINHO BIOENERGIA S.A",
    26603: "GSH CORP PARTICIPAÇÕES S.A",
    26620: "Auren (AURE3)",
    26646: "CANTU STORE S.A",
    26700: "EUROFARMA LABORATËRIOS S.A",
    26760: "TECIDOS E ARMARINHOS MIGUEL BARTOLOMEU S.A",
    26786: "SENIOR SISTEMAS S.A",
    26905: "IFIN PARTICIPAÇÕES S.A",
    26956: "OCEÂNICA ENGENHARIA E CONSULTORIA S.A",
    26980: "BORRACHAS VIPAL S.A",
    27014: "SOLAR BEBIDAS S.A",
    27057: "VITRU EDUCAÇÃO S.A",
    27103: "CHINA THREE GORGES BRASIL ENERGIA S.A",
    27189: "VOTORANTIM CIMENTOS S.A",
    27219: "GRANJA FARIA S.A",
    27227: "ORIGEM ENERGIA S.A",
    27324: "VOKE S.A",
    27340: "CONSTRUTORA METROCASA S.A",
    27391: "BRZ EMPREENDIMENTOS E CONSTRUÇÕES S.A",
    27502: "GIGA MAIS FIBRA TELECOMUNICAÇÕES S.A",
    27510: "VITAL ENGENHARIA AMBIENTAL S.A",
    27561: "REVEE MCO S.A",
    27570: "BELORA RDVC CITY DESENVOLVIMENTO IMOBILIÁRIO S.A",
    27600: "PORTO SERVIÇO S.A",
    27618: "PORTO SAÚDE PARTICIPAÇÕES S.A",
    27626: "AZEVEDO & TRAVASSOS ENERGIA S.A",
    27634: "CIABRASF - CIA. BRASILEIRA DE SERVIÇOS FINANCEIROS S.A",
    27650: "REVEE S.A",
    27677: "ATOM EDUCAÇÃO E EDITORA S.A",
    27685: "R/HOLDINGS S.A",
    27693: "BRISANET SERVIÇOS DE TELECOMUNICAÇÕES S.A",
    27707: "VAMOS COMÉRCIO DE MÁQUINAS LINHA AMARELA S.A",
    27766: "UNIÃO PET PARTICIPAÇÕES S.A",
    27820: "GRUPO SALTA EDUCAÇÃO S.A",
    27910: "ORANJEBTC S.A. - EDUCAÇÃO E INVESTIMENTO",
    28010: "FGR INCORPORAÇÕES S.A",
    28029: "PLAMEV ADMINISTRADORA DE BENEFÍCIOS DE ATENÇÃO À SAÚDE DE ANIMAIS DOMÉSTICOS S.A",
    28037: "MAIS MU COMÉRCIO DE ALIMENTOS E BEBIDAS S/A",
}

# Documentos da CVM que geram alerta. A pedido da Brenda (14/08/2026), SO estes
# quatro: Fato Relevante, Apresentacoes a Investidores, Press Release e DFs/ITRs.
# Precisa olhar CATEGORIA **e** TIPO, porque "Apresentacoes" e "DFs/ITRs" sao
# TIPOS dentro de categorias, nao categorias soltas:
#   Fato Relevante          -> categoria "Fato Relevante"
#   Press Release           -> "Dados Economico-Financeiros" / tipo "Press-release"
#   DFs/ITRs                -> "Dados Economico-Financeiros" / tipo "Demonstracoes
#                              Financeiras ..."  (ou categorias formais ITR/DFP)
#   Apresentacoes Investidor -> "Comunicado ao Mercado" / tipo "Apresentacoes a
#                              analistas/agentes do mercado"
# (Comparacao SEM acento e minuscula via _norm.) De "Comunicado ao Mercado" entram
# APENAS os materiais (01/10/2026): Aquisicao/Alienacao de Participacao Relevante e
# Esclarecimentos a CVM/B3 (+ Apresentacoes). Fora: "Outros Comunicados", "Mudanca
# de Auditor" e Calendario de Eventos - reativar aqui se quiser.
def _cvm_wanted(categoria, tipo):
    c = _norm(categoria)
    t = _norm(tipo)
    if c.startswith("fato relevante"):                # Fato Relevante
        return True
    if t.startswith("apresenta"):                     # Apresentacoes a investidores
        return True
    if c.startswith(("itr", "dfp")):                  # DF trimestral/anual formais
        return True
    if c.startswith("dados econ"):                    # Press Release + DFs/ITRs
        return "press" in t or t.startswith("demonstracoes financeiras")
    if c.startswith("comunicado ao mercado"):         # so os comunicados MATERIAIS
        # Aquisicao/Alienacao de Participacao Relevante + Esclarecimentos a CVM/B3.
        # Ficam de fora "Outros Comunicados" e "Mudanca de Auditor" (ruido).
        return "aquisic" in t or "alienac" in t or "esclarecimento" in t
    if c.startswith("aviso aos debenturistas"):       # aviso aos debenturistas (a pedido)
        return True
    return False


def _norm(s):
    """Minusculas e sem acentos, para casar categorias com seguranca."""
    s = unicodedata.normalize("NFKD", s or "")
    return "".join(c for c in s if not unicodedata.combining(c)).lower().strip()

RAD_BASE = "https://www.rad.cvm.gov.br/ENET/frmConsultaExternaCVM.aspx"
RAD_URL  = RAD_BASE + "/ListarDocumentos"

# ---------------------------------------------------------------------------
# Infra
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"),
              logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("release-alert")


def load_config():
    with open(CONFIG, encoding="utf-8") as fh:
        return json.load(fh)


def load_state():
    if not os.path.exists(STATE):
        return None                      # None => primeira execucao (baseline)
    try:
        with open(STATE, encoding="utf-8") as fh:
            return set(json.load(fh).get("seen", []))
    except Exception:
        return set()


def save_state(seen):
    seen = list(seen)[-8000:]            # limita o tamanho do historico
    with open(STATE, "w", encoding="utf-8") as fh:
        json.dump({"seen": seen}, fh)


def http_get_json(url, ua, timeout=40):
    req = urllib.request.Request(url, headers={"User-Agent": ua,
                                               "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


# ---------------------------------------------------------------------------
# Fonte 1: SEC EDGAR
# ---------------------------------------------------------------------------
def fetch_edgar(cfg):
    ua = cfg["edgar_user_agent"]
    cutoff = dt.date.today() - dt.timedelta(days=int(cfg.get("edgar_lookback_days", 5)))
    # Consultas em PARALELO (antes eram ~150 em fila, ~70s por rodada). A SEC
    # permite ate 10 req/s por usuario; _ritmo() segura em ~8/s com folga.
    # Mantem a consulta empresa por empresa (cobertura total): o feed de
    # "ultimos filings" da SEC so traz os ~100 mais recentes e perderia
    # documentos quando o GitHub fica horas sem rodar.
    import threading
    from concurrent.futures import ThreadPoolExecutor
    trava = threading.Lock()
    ultimo = [0.0]

    def _ritmo():
        with trava:
            espera = ultimo[0] + 0.125 - time.monotonic()
            if espera > 0:
                time.sleep(espera)
            ultimo[0] = time.monotonic()

    def scan(ticker, cik, want_forms, require_item_202, verify=False, label=None):
        out = []
        url = f"https://data.sec.gov/submissions/CIK{cik:010d}.json"
        _ritmo()
        try:
            data = http_get_json(url, ua)
        except Exception as exc:
            log.warning("EDGAR falhou para %s (CIK %s): %s", ticker, cik, exc)
            return out
        rec = data.get("filings", {}).get("recent", {})
        forms = rec.get("form", [])
        for i, form in enumerate(forms):
            if form not in want_forms:
                continue
            fdate = rec["filingDate"][i]
            try:
                if dt.date.fromisoformat(fdate) < cutoff:
                    continue
            except Exception:
                continue
            if require_item_202 and "2.02" not in (rec.get("items", [""])[i] or ""):
                continue
            primary = rec.get("primaryDocument", [""])[i]
            acc = rec["accessionNumber"][i]
            acc_nodash = acc.replace("-", "")
            when = rec.get("acceptanceDateTime", [fdate])[i]
            url_doc = (f"https://www.sec.gov/Archives/edgar/data/{cik}/"
                       f"{acc_nodash}/{primary}") if primary else                       (f"https://www.sec.gov/Archives/edgar/data/{cik}/{acc_nodash}/")
            # 8-K item 2.02 ja e resultado; 6-K precisa checar o CONTEUDO
            # (nomes de arquivo dos estrangeiros sao opacos - ex.: tm2613731d1_6k.htm)
            out.append({
                "id": f"edgar:{acc}",
                "source": "EDGAR",
                "company": ticker,
                "kind": label or (f"{form}" + (" (item 2.02 - Resultados)" if require_item_202 else " (6-K financeiro)")),
                "when": when,
                "url": url_doc,
                "verify": verify,
            })
        return out

    tarefas = [(tk, cik, ("8-K",), True) for tk, cik in EDGAR_8K.items()]
    tarefas += [(tk, cik, ("6-K",), False, True) for tk, cik in EDGAR_6K.items()]
    tarefas += [(tk, cik, ("10-Q", "10-K"), False, False, "10-Q/10-K (Resultados)")
                for tk, cik in EDGAR_10KQ.items()]
    t0 = time.monotonic()
    items = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for res in ex.map(lambda t: scan(*t), tarefas):
            items.extend(res)
    log.info("EDGAR: %d consultas em %.1fs.", len(tarefas), time.monotonic() - t0)
    return items


def verify_earnings_6k(url, ua):
    """Le o filing 6-K INTEIRO (documento principal + anexos/exhibits, pois os
    numeros costumam vir num exhibit separado) e decide se e resultado.
    Retorna True (e resultado), False (nao e) ou None (falha ao verificar)."""
    try:
        base = url.rsplit("/", 1)[0] + "/"
        idx = http_get_json(base + "index.json", ua)
        files = [f for f in idx.get("directory", {}).get("item", [])
                 if f.get("name", "").lower().endswith((".htm", ".html", ".txt"))]
        files.sort(key=lambda f: int(f.get("size", 0) or 0), reverse=True)
        text = ""
        for f in files[:4]:                      # os maiores docs do filing
            try:
                req = urllib.request.Request(base + f["name"], headers={"User-Agent": ua})
                with urllib.request.urlopen(req, timeout=40) as r:
                    text += r.read(300_000).decode("utf-8", "ignore").lower()
            except Exception:
                continue
            if len(text) > 800_000:
                break
        if not text:
            return None
        hits = sum(1 for s in EARNINGS_TEXT_SIGNALS if s in text)
        return hits >= 3
    except Exception as exc:
        log.warning("Falha ao verificar 6-K (%s): %s", url, exc)
        return None


# Ordem de preferencia do exhibit que contem o press release de resultados.
# EX-99.1 e a convencao; os demais sao rede de seguranca.
EDGAR_PR_PREF = ("EX-99.1", "EX-99", "EX-99.01", "EX-99.2", "EX-99.02", "EX-99.3")


def find_edgar_press_release(item, ua):
    """Descobre o Exhibit com o PRESS RELEASE de resultados do filing.

    O documento principal do 8-K (ex.: gs-20260714.htm) e so a CAPA: nao tem os
    numeros, so aponta para o exhibit. Os numeros estao no EX-99.1.
    O nome do arquivo NAO e confiavel (no 8-K do GS, 'a2q26gsearningsresultspr.htm'
    - com "pr" no nome! - e o EX-99.2/apresentacao, enquanto o EX-99.1 de verdade
    e 'a2q26gsearningsresults.htm'). Por isso lemos a coluna 'Type' da tabela
    oficial do {accession}-index.html.

    Retorna (url, tipo) ou (None, None).
    """
    try:
        acc = item["id"].split(":", 1)[1]                 # 0000886982-26-000294
        base = item["url"].rsplit("/", 1)[0] + "/"
        req = urllib.request.Request(base + f"{acc}-index.html",
                                     headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=40) as r:
            raw = r.read().decode("utf-8", "ignore")
        import html as _html
        docs = {}                                          # TIPO -> arquivo
        for row in re.findall(r"(?is)<tr[^>]*>(.*?)</tr>", raw):
            cells = [_html.unescape(re.sub(r"(?s)<[^>]+>", " ", c)).strip()
                     for c in re.findall(r"(?is)<t[dh][^>]*>(.*?)</t[dh]>", row)]
            # colunas: Seq | Description | Document | Type | Size
            if len(cells) >= 4 and cells[2] and cells[3]:
                nome = cells[2].split()[0]                 # tira sufixo " iXBRL"
                docs.setdefault(cells[3].strip().upper(), nome)
        for want in EDGAR_PR_PREF:
            f = docs.get(want, "")
            if f.lower().endswith((".htm", ".html", ".txt")):
                return base + f, want
    except Exception as exc:
        log.warning("Nao consegui achar o press release de %s: %s",
                    item.get("company"), exc)
    return None, None


# ---------------------------------------------------------------------------
# Fonte 2: CVM / RAD  (tempo real, sem captcha para consulta por data)
# ---------------------------------------------------------------------------
def fetch_cvm(cfg):
    window = int(cfg.get("rad_window_days", 2))
    hoje = dt.date.today()
    de = (hoje - dt.timedelta(days=window - 1)).strftime("%d/%m/%Y")
    ate = hoje.strftime("%d/%m/%Y")

    payload = {
        "dataDe": de, "dataAte": ate, "empresa": "",
        "setorAtividade": "-1", "categoriaEmissor": "-1", "situacaoEmissor": "-1",
        "tipoParticipante": "-1", "dataReferencia": "", "categoria": "-1",
        "periodo": "2", "horaIni": "", "horaFim": "", "palavraChave": "",
        "ultimaDtRef": "false", "tipoEmpresa": "1", "token": "", "versaoCaptcha": "",
    }
    # A conexao com o RAD as vezes cai (timeout / reset). Tenta algumas vezes
    # antes de desistir; se desistir, a proxima execucao re-varre a janela.
    tentativas = int(cfg.get("rad_retries", 3))
    d = None
    for n in range(1, tentativas + 1):
        try:
            cj = http.cookiejar.CookieJar()
            op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
            op.addheaders = [("User-Agent", "Mozilla/5.0")]
            op.open(RAD_BASE, timeout=40).read()          # estabelece sessao ASP.NET
            req = urllib.request.Request(
                RAD_URL, data=json.dumps(payload).encode("utf-8"), method="POST",
                headers={"Content-Type": "application/json; charset=UTF-8",
                         "User-Agent": "Mozilla/5.0", "Referer": RAD_BASE,
                         "X-Requested-With": "XMLHttpRequest"})
            d = json.load(op.open(req, timeout=60))["d"]
            break
        except Exception as exc:
            log.warning("CVM/RAD: tentativa %d/%d falhou: %s", n, tentativas, exc)
            if n < tentativas:
                time.sleep(4)
    if d is None:
        log.warning("CVM/RAD: sem resposta apos %d tentativas; pulando B3 nesta "
                    "execucao (a proxima re-varre a janela).", tentativas)
        return []

    if d.get("SolicitarCaptcha") == "S":
        log.warning("CVM/RAD: captcha exigido nesta execucao; pulando B3 (EDGAR segue).")
        return []
    if d.get("temErro"):
        log.warning("CVM/RAD: erro retornado: %s", d.get("msgErro"))
        return []

    items = []
    for rec in d.get("dados", "").split("*"):
        f = rec.split("$&")
        if len(f) < 11:
            continue
        # f[0] e o codigo CVM formatado "NNNNN-D" (6 digitos, hifen antes do
        # ultimo). O codigo REAL e o numero inteiro sem o hifen:
        #   Raia "00525-8" -> 005258 -> 5258 ; Unilever "05258-2" -> 52582.
        # (usar split("-")[0] PAREIA A EMPRESA ERRADA - bug corrigido 06/07/2026)
        cod_raw = f[0].strip()
        try:
            code = int(cod_raw.replace("-", ""))
        except ValueError:
            continue
        if code not in CVM_WATCH:
            continue
        categoria = f[2].strip()
        tipo = re.sub(r"<[^>]+>", "", f[3]).strip()
        if tipo in ("-", "--", ""):          # tipo vazio (ex.: Fato Relevante) -> sem sufixo
            tipo = ""
        if not _cvm_wanted(categoria, tipo):
            continue
        mw = re.search(r"\d{2}/\d{2}/\d{4}(?:\s+\d{2}:\d{2})?", f[6])  # limpa spanOrder
        when = mw.group(0) if mw else re.sub(r"<[^>]+>", "", f[6]).strip()
        # O HTML com os links fica num campo interno (nao no ultimo) -> busca no
        # registro inteiro. protocolo = visualizar; (seq,ver) = download do arquivo.
        m = re.search(r"NumeroProtocoloEntrega=(\d+)", rec)
        protocolo = m.group(1) if m else None
        if not protocolo:
            continue
        dl = re.search(r"OpenDownloadDocumentos\('(\d+)','(\d+)','(\d+)','(\w+)'\)", rec)
        seq, ver, _, dtipo = dl.groups() if dl else (None, None, None, "IPE")
        # LINK do e-mail = VISUALIZADOR em /ENETWeb/. A versao /ENET/ deste
        # visualizador dava "Nao foi possivel carregar o arquivo" (reCAPTCHA v3
        # nao passava no clique frio); a versao NOVA /ENETWeb/ ABRE o PDF direto
        # no navegador (o reCAPTCHA v3 invisivel passa sozinho) - testado 14/08.
        # O download p/ ANEXO usa item['dl'] (frmDownloadDocumento), separado.
        url_doc = (f"https://www.rad.cvm.gov.br/ENETWeb/"
                   f"frmExibirArquivoIPEExterno.aspx?NumeroProtocoloEntrega={protocolo}")
        items.append({
            "id": f"cvm:{protocolo}",
            "source": "B3/CVM",
            "company": CVM_WATCH[code],
            "kind": f"{categoria} - {tipo}" if tipo else categoria,
            "when": when,
            "url": url_doc,
            "categoria": categoria,               # p/ decidir se resume
            "cod_cvm": code,                       # p/ o link de busca na CVM
            "dl": {"seq": seq, "ver": ver, "prot": protocolo, "tipo": dtipo},
        })
    return items


# Pagina de BUSCA da CVM (funciona no navegador: o captcha do doc passa dentro
# da sessao de consulta). Nao aceita parametro de URL p/ pre-preencher (o campo
# empresa e autocomplete via JS), entao mostramos o Codigo CVM p/ digitar+Enter.
# A CVM descontinuou a consulta em /ENET/ (mostra "pagina descontinuada" e
# redireciona) -> usar /ENETWeb/ (14/08/2026). Os endpoints de DOWNLOAD e de
# LISTAGEM em /ENET/ ainda funcionam (testado), entao so a consulta mudou aqui.
CVM_CONSULTA_URL = "https://www.rad.cvm.gov.br/ENETWeb/frmConsultaExternaCVM.aspx"


# ---------------------------------------------------------------------------
# Resumo com IA (Google Gemini) + PDF
# ---------------------------------------------------------------------------
def _strip_html(raw):
    import html as _html
    txt = re.sub(r"(?is)<(script|style).*?</\1>", " ", raw)
    txt = re.sub(r"(?s)<[^>]+>", " ", txt)
    return re.sub(r"\s+", " ", _html.unescape(txt)).strip()


def extract_document_text(item, cfg, max_chars=12000):
    """Baixa o documento do release e devolve o texto (para resumir)."""
    try:
        if item["source"] == "B3/CVM":
            dl = item.get("dl") or {}
            if not dl.get("seq"):
                return ""
            cj = http.cookiejar.CookieJar()
            op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
            op.addheaders = [("User-Agent", "Mozilla/5.0")]
            op.open(RAD_BASE, timeout=40).read()          # sessao para o download
            url = (f"https://www.rad.cvm.gov.br/ENET/frmDownloadDocumento.aspx?"
                   f"Tela=ext&descTipo={dl['tipo']}&CodigoInstituicao=1"
                   f"&numProtocolo={dl['prot']}&numSequencia={dl['seq']}"
                   f"&numVersao={dl['ver']}")
            raw = op.open(urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0", "Referer": RAD_BASE}),
                timeout=60).read()
        else:                                             # EDGAR
            ua = cfg.get("edgar_user_agent", "release-alert")
            # O doc principal do 8-K e so a capa. Busca o EX-99.1 (press release),
            # que e onde estao os numeros. 10-Q/10-K nao tem PR: usa o proprio doc.
            if "10-Q" not in item.get("kind", "") and not item.get("pr_url"):
                pr, tipo = find_edgar_press_release(item, ua)
                if pr:
                    item["pr_url"], item["pr_tipo"] = pr, tipo
            alvo = item.get("pr_url") or item["url"]
            # Os numeros-chave ficam no inicio do PR (quadro-resumo). Como o resumo
            # agora e curto, basta o comeco -> menos tokens.
            max_chars = 14000
            req = urllib.request.Request(alvo, headers={"User-Agent": ua})
            raw = urllib.request.urlopen(req, timeout=60).read()
        if raw[:4] == b"%PDF":                            # detecta PDF por magic bytes
            import io
            from pypdf import PdfReader
            txt = "".join((p.extract_text() or "") + "\n"
                          for p in PdfReader(io.BytesIO(raw)).pages[:8])
            return txt[:max_chars]
        text = _strip_html(raw.decode("utf-8", "ignore"))
        # pagina intermediaria/erro (sem o conteudo real) -> nao resume, so link
        if len(text) < 400 or "download de documento" in text.lower():
            return ""
        return text[:max_chars]
    except Exception as exc:
        log.warning("Falha ao extrair texto de %s: %s", item.get("company"), exc)
        return ""


def should_summarize(item):
    """So resume resultados e fatos relevantes (nao comunicados/proventos/etc.)."""
    if item["source"] != "B3/CVM":
        return True                                       # EDGAR = sempre resultado
    return _norm(item.get("categoria", "")).startswith(("dados econ", "fato relevante"))


def is_resultado(item):
    """True quando o documento e um RELEASE DE RESULTADOS (tem numeros de
    trimestre) - e nao um fato relevante/evento. Define o formato do resumo:
    resultado -> BLURB + NUMEROS com QoQ/YoY; o resto -> topicos livres."""
    if item["source"] == "EDGAR":
        return True                                       # 8-K 2.02 / 6-K / 10-Q
    return _norm(item.get("categoria", "")).startswith("dados econ")


def _clean_md(s):
    """Remove formatacao markdown (**, ##, *, `) que polui o texto."""
    if not s:
        return s
    s = re.sub(r"\*\*(.+?)\*\*", r"\1", s)                # **negrito** -> negrito
    s = re.sub(r"__(.+?)__", r"\1", s)
    s = re.sub(r"(?m)^\s{0,3}#{1,6}\s*", "", s)           # ## titulo -> titulo
    s = re.sub(r"(?m)^\s*[\*•]\s+", "- ", s)         # bullets -> "- "
    s = s.replace("**", "").replace("`", "").replace("__", "")
    return re.sub(r"\n{3,}", "\n\n", s).strip()


# Reserva do resumo: se o Gemini falhar numa rodada, o resto da rodada vai
# direto p/ o Groq (sem esperar timeout de novo a cada item).
_GEMINI_FORA = False
GROQ_MODELOS = ("openai/gpt-oss-120b", "openai/gpt-oss-20b")
_UA_NAVEGADOR = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                 "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


def _groq_summarize(prompt, item, cfg):
    """Resumo pelo Groq (modelos abertos gpt-oss). gpt-oss e modelo de raciocinio:
    reasoning_effort=low + max_tokens folgado, senao a resposta sai vazia.
    Em 429 (limite) espera o retry-after uma vez; depois tenta o modelo menor."""
    import urllib.error
    gq = cfg.get("groq", {})
    if not gq.get("enabled") or not gq.get("api_key"):
        return None
    for modelo in GROQ_MODELOS:
        texto = prompt
        for tent in range(3):
            # max_tokens conta no limite de tokens/min do Groq gratis: 2048 sobra
            # p/ um resumo de 5-10 topicos e deixa espaco p/ documentos grandes.
            body = {"model": modelo, "messages": [{"role": "user", "content": texto}],
                    "temperature": 0.2, "max_tokens": 2048, "reasoning_effort": "low"}
            req = urllib.request.Request(
                "https://api.groq.com/openai/v1/chat/completions",
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json",
                         "Authorization": f"Bearer {gq['api_key']}",
                         "User-Agent": _UA_NAVEGADOR})   # Cloudflare barra o UA do Python
            try:
                d = json.load(urllib.request.urlopen(req, timeout=60))
                txt = (d["choices"][0]["message"].get("content") or "").strip()
                if txt:
                    return _clean_md(txt)
                break                                     # vazio -> proximo modelo
            except urllib.error.HTTPError as exc:
                if exc.code == 413 and len(texto) > 4000:
                    # documento grande (tabelas gastam muitos tokens): manda so o
                    # comeco - instrucoes vem antes e os numeros-chave ficam no inicio
                    texto = texto[:int(len(texto) * 0.6)]
                    continue
                if exc.code == 429 and tent < 2:
                    time.sleep(min(float(exc.headers.get("retry-after") or 10), 30))
                    continue
                log.warning("Groq %s falhou p/ %s: HTTP %s", modelo,
                            item.get("company"), exc.code)
                break
            except Exception as exc:
                log.warning("Groq %s falhou p/ %s: %s", modelo, item.get("company"), exc)
                break
    return None


def gemini_summarize(text, item, cfg):
    global _GEMINI_FORA
    g = cfg.get("gemini", {})
    if not text.strip():
        return None
    model = g.get("model", "gemini-2.5-flash")
    sem_md = ("NAO use formatacao markdown (nada de **, ##, *). Escreva texto "
              "simples; para topicos use um hifen '-' no inicio da linha.")
    if is_resultado(item):
        # RESULTADOS: resumo CURTO, so os principais pontos (menos tokens).
        if item["source"] == "EDGAR":
            contexto = (f"A empresa e {item['company']} (EUA). O texto abaixo e o "
                        f"PRESS RELEASE de resultados (em ingles).")
            nota = ("Traduza os nomes das metricas para portugues, mantendo os "
                    "valores exatos.")
            fonte = "PRESS RELEASE"
        else:
            contexto = (f"A empresa e {item['company']} (B3). O texto abaixo e o "
                        f"release de resultados na CVM ({item['kind']}).")
            nota = "'A/A' significa vs. mesmo trimestre do ano anterior (YoY)."
            fonte = "RELEASE DE RESULTADOS"
        prompt = (
            f"Voce e um analista de acoes. {contexto}\n\n"
            f"Resuma em portugues do Brasil APENAS os principais pontos, de forma "
            f"BREVE - no maximo 5 topicos curtos:\n"
            f"- 1 topico de destaque: o resultado veio forte ou fraco e o que puxou.\n"
            f"- Receita e lucro liquido, com a variacao ANUAL (YoY) quando o texto "
            f"trouxer.\n"
            f"- 1 ou 2 metricas mais relevantes ao setor (ex.: margem/EBITDA; ROE p/ "
            f"banco; guidance/receita de cloud p/ tech), so se estiverem em destaque.\n"
            f"- Se houver guidance/projecao, 1 linha.\n"
            f"NAO liste todas as metricas nem detalhe cada variacao - so o essencial. "
            f"Comece direto pelos topicos, SEM frase de introducao. {nota}\n"
            f"Use SOMENTE numeros que estao no texto; nunca invente. {sem_md}\n\n"
            f"=== {fonte} ===\n{text}"
        )
    else:
        # Fato relevante e afins: nao e resultado, entao formato livre em topicos.
        prompt = (
            f"Voce e um analista de acoes. Resuma em portugues do Brasil, de forma "
            f"objetiva e em topicos curtos, o documento a seguir da empresa "
            f"{item['company']} ({item['kind']}).\n"
            f"Diga o essencial do evento (M&A, guidance, mudanca de controle, "
            f"dividendos, etc.) e extraia TODOS os numeros presentes (valores, "
            f"prazos, percentuais, impacto financeiro). Explique em 1 linha por que "
            f"isso importa para o acionista.\n"
            f"Maximo 10 topicos. Nao invente numeros que nao estao no texto. "
            f"Responda 'Sem dados financeiros no documento.' apenas se realmente "
            f"nao houver nenhum numero.\n"
            f"{sem_md}\n\n"
            f"=== DOCUMENTO ===\n{text}"
        )
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model}:generateContent?key={g['api_key']}")
    body = {"contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1024,
                                 # gemini-2.5-flash "pensa" e consome o orcamento
                                 # de saida; desligar deixa tudo para a resposta.
                                 "thinkingConfig": {"thinkingBudget": 0}}}
    if g.get("enabled") and g.get("api_key") and not _GEMINI_FORA:
        for attempt in range(2):
            try:
                req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                             headers={"Content-Type": "application/json"})
                d = json.load(urllib.request.urlopen(req, timeout=45))
                return _clean_md(d["candidates"][0]["content"]["parts"][0]["text"])
            except Exception as exc:
                if attempt == 0:                          # 1 retry (ex.: limite/min)
                    time.sleep(6)
                    continue
                log.warning("Gemini falhou para %s: %s -> usando Groq no resto da "
                            "rodada", item.get("company"), exc)
                _GEMINI_FORA = True
    resumo = _groq_summarize(prompt, item, cfg)
    if resumo:
        return (resumo + "\n(Resumo feito pelo modelo reserva via Groq, porque o "
                "Gemini estava indisponivel. Pode ser menos preciso.)")
    return None


def _lat1(s):
    return (s or "").encode("latin-1", "replace").decode("latin-1")


def build_summary_pdf(items, path):
    """Gera um PDF com os resumos disponiveis. Retorna path ou None."""
    com = [i for i in items if i.get("summary")]
    if not com:
        return None
    try:
        from fpdf import FPDF
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        W = pdf.epw                                       # largura util da pagina

        def cell(h, s):
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(W, h, _lat1(s), new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "B", 16); cell(9, "Resumo de Releases")
        pdf.set_font("Helvetica", "", 9); pdf.set_text_color(120, 120, 120)
        cell(5, "release-alert - resumos gerados por IA (Google Gemini). "
                "Confira sempre o documento oficial.")
        pdf.set_text_color(0, 0, 0); pdf.ln(2)
        for i in com:
            pdf.set_font("Helvetica", "B", 12); cell(6, i["company"])
            pdf.set_font("Helvetica", "I", 9); pdf.set_text_color(90, 90, 90)
            cell(5, f"{i['kind']}  -  {i['when']}")
            pdf.set_text_color(0, 0, 0); pdf.set_font("Helvetica", "", 10)
            cell(5, i["summary"])
            # link principal: o press release quando existir; senao o documento
            pdf.set_font("Helvetica", "U", 9); pdf.set_text_color(12, 119, 102)
            if i.get("pr_url"):
                pdf.set_x(pdf.l_margin)
                pdf.cell(0, 5, _lat1(f"Abrir press release ({i.get('pr_tipo','EX-99.1')})"),
                         link=i["pr_url"], new_x="LMARGIN", new_y="NEXT")
            if i.get("url"):
                pdf.set_x(pdf.l_margin)
                pdf.cell(0, 5, _lat1("Abrir documento oficial"), link=i["url"],
                         new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            pdf.ln(4)
        pdf.output(path)
        return path
    except Exception as exc:
        log.warning("Falha ao gerar PDF de resumo: %s", exc)
        return None


# ---------------------------------------------------------------------------
# E-mail
# ---------------------------------------------------------------------------
def build_email_bodies(items):
    br = [i for i in items if i["source"] == "B3/CVM"]
    us = [i for i in items if i["source"] == "EDGAR"]

    def line_txt(i):
        s = f"  - {i['company']}  [{i['kind']}]  {i['when']}"
        s += f"\n    abrir documento: {i['url']}"
        if i.get("pr_url"):
            s += f"\n    press release ({i.get('pr_tipo','EX-99.1')}): {i['pr_url']}"
        return s

    txt = ["Novos documentos detectados:\n"]
    if br:
        txt.append("=== B3 / Brasil (CVM) ===")
        txt += [line_txt(i) for i in br]
        txt.append("")
    if us:
        txt.append("=== Tech Global (SEC EDGAR) ===")
        txt += [line_txt(i) for i in us]
        txt.append("")
    resumidos = [i for i in items if i.get("summary")]
    if resumidos:
        txt.append("=== RESUMOS (IA) ===")
        for i in resumidos:
            txt.append(f"\n> {i['company']}  [{i['kind']}]")
            txt.append(i["summary"])
            # o PR vai no FIM do blurb
            if i.get("pr_url"):
                txt.append(f"  Press release ({i.get('pr_tipo','EX-99.1')}): {i['pr_url']}")
            elif i["source"] == "B3/CVM":
                txt.append(f"  Abrir documento: {i['url']}")
            elif i.get("url"):
                txt.append(f"  Documento: {i['url']}")
        txt.append("")
    txt.append("--\nrelease-alert (fontes: SEC EDGAR e CVM/RAD). "
               "Resumos por IA - confira sempre o documento oficial.")
    text_body = "\n".join(txt)

    def rows(lst):
        out = ""
        for i in lst:
            links = f"<a href='{i['url']}'>abrir documento</a>"
            if i["source"] == "B3/CVM":                    # CVM: visualizador ENETWeb
                links = f"<a href='{i['url']}'>&#128196; abrir documento</a>"
            elif i.get("pr_url"):                          # press release em destaque
                links = (f"<a href='{i['pr_url']}'><b>press release</b></a>"
                         f" &middot; <span style='font-size:12px'>"
                         f"<a href='{i['url']}'>8-K</a></span>")
            out += (f"<tr><td style='padding:4px 10px'><b>{i['company']}</b></td>"
                    f"<td style='padding:4px 10px'>{i['kind']}</td>"
                    f"<td style='padding:4px 10px;white-space:nowrap'>{i['when']}</td>"
                    f"<td style='padding:4px 10px'>{links}</td></tr>")
        return out

    html = "<h2>Novos documentos</h2>"
    if br:
        html += ("<h3>&#127463;&#127479; B3 / Brasil (CVM)</h3>"
                 "<table style='border-collapse:collapse'>" + rows(br) + "</table>")
    if us:
        html += ("<h3>&#127760; Tech Global (SEC EDGAR)</h3>"
                 "<table style='border-collapse:collapse'>" + rows(us) + "</table>")
    if resumidos:
        html += "<h3>&#129504; Resumos (IA)</h3>"
        for i in resumidos:
            body = (i["summary"].replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;").replace("\n", "<br>"))
            pr = ""
            if i.get("pr_url"):                            # PR no FIM do blurb
                pr = (f"<br><a href='{i['pr_url']}' style='font-size:13px'>"
                      f"&#128196; Press release completo ({i.get('pr_tipo','EX-99.1')})</a>")
            elif i["source"] == "B3/CVM":
                pr = (f"<br><span style='font-size:13px'>"
                      f"<a href='{i['url']}'>&#128196; abrir documento</a></span>")
            elif i.get("url"):
                pr = (f"<br><a href='{i['url']}' style='font-size:13px'>"
                      f"&#128196; Documento oficial</a>")
            html += (f"<div style='margin:8px 0;padding:8px 12px;border-left:3px solid #0C7766'>"
                     f"<b>{i['company']}</b> <span style='color:#888'>&middot; {i['kind']}</span>"
                     f"<br><span style='font-size:13px'>{body}</span>{pr}</div>")
    html += ("<p style='color:#888;font-size:12px'>release-alert &middot; SEC EDGAR + CVM/RAD "
             "&middot; resumos por IA (Gemini) - confira o documento oficial</p>")
    return text_body, html


def _smtp_send(cfg, subject, text_body, html_body=None, attachment=None,
               to_addr=None, bcc=None, attachments=None):
    """Envia um e-mail (opcionalmente com anexos). True se enviou.

    to_addr:     sobrescreve o destinatario visivel (cabecalho To). Se nao dado,
                 usa cfg.email.to_addr.
    bcc:         lista de enderecos em CopiaOculta. Quando fornecida, a ENTREGA
                 vai so para os enderecos de bcc (eles nao aparecem no cabecalho);
                 o To visivel fica so cosmetico (ex.: a propria conta de envio).
    attachment:  caminho de UM arquivo PDF (compat. retro).
    attachments: lista de (filename, bytes) p/ anexar varios PDFs em memoria."""
    ec = cfg["email"]
    if not ec.get("enabled") or not ec.get("app_password"):
        log.info("E-mail DESATIVADO (sem credenciais). Conteudo que SERIA enviado:\n%s",
                 text_body)
        return False
    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(text_body, "plain", "utf-8"))
    if html_body:
        alt.attach(MIMEText(html_body, "html", "utf-8"))
    files = []                                        # [(filename, bytes)]
    if attachment and os.path.exists(attachment):
        try:
            with open(attachment, "rb") as fh:
                files.append((os.path.basename(attachment), fh.read()))
        except Exception as exc:
            log.warning("Falha ao ler anexo %s: %s", attachment, exc)
    if attachments:
        files.extend(attachments)
    if files:
        from email.mime.application import MIMEApplication
        msg = MIMEMultipart("mixed")
        msg.attach(alt)
        for fname, data in files:
            try:
                part = MIMEApplication(data, _subtype="pdf")
                part.add_header("Content-Disposition", "attachment", filename=fname)
                msg.attach(part)
            except Exception as exc:
                log.warning("Falha ao anexar %s: %s", fname, exc)
    else:
        msg = alt
    msg["Subject"] = subject
    # Nome de exibicao (ex.: "Alerta de Releases <auto...@gmail.com>")
    msg["From"] = formataddr((ec.get("from_name") or None, ec["from_addr"]))
    if to_addr:
        to_hdr = to_addr
    elif bcc:
        to_hdr = "undisclosed-recipients:;"     # BCC-only: nao expoe endereco
    else:
        to_hdr = ec["to_addr"]
    msg["To"] = to_hdr
    # Entrega: se ha bcc, so os enderecos ocultos recebem (nao entram no
    # cabecalho); senao, o destinatario visivel.
    envelope = list(bcc) if bcc else [to_hdr]
    # anexos pesados demoram no upload -> timeout maior quando ha arquivo.
    tmo = 240 if files else 45
    with smtplib.SMTP(ec["smtp_host"], int(ec["smtp_port"]), timeout=tmo) as s:
        s.starttls()
        s.login(ec["username"], ec["app_password"])
        s.sendmail(ec["from_addr"], envelope, msg.as_string())
    return True


def _pdf_filename(item):
    """Nome amigavel (ASCII, seguro) p/ o anexo: TICKER_Categoria_protocolo.pdf."""
    import unicodedata
    comp = item.get("company", "documento")
    m = re.search(r"\(([A-Z0-9]{4,6})\)", comp)      # usa o ticker se houver
    base = m.group(1) if m else comp.split(" (")[0]
    kind = (item.get("kind", "") or "").split(" - ")[0]
    prot = (item.get("dl") or {}).get("prot", "")
    raw = f"{base}_{kind}_{prot}"
    ascii_ = unicodedata.normalize("NFKD", raw).encode("ascii", "ignore").decode()
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", ascii_).strip("_")
    return (safe[:80] or "documento") + ".pdf"


def _download_cvm_pdf(item, max_bytes=15 * 1024 * 1024):
    """Baixa o PDF OFICIAL do documento CVM p/ anexar no e-mail.

    Usa o endpoint frmDownloadDocumento, que (ao contrario do VISUALIZADOR
    frmExibirArquivoIPEExterno) NAO exige reCAPTCHA e entrega o arquivo direto.
    Assim a Brenda abre o documento pelo anexo, sem depender do site da CVM
    (que passou a barrar o clique direto - "Nao foi possivel carregar o arquivo").

    Devolve (filename, bytes) ou None. So p/ B3/CVM com dados de download."""
    dl = item.get("dl") or {}
    if item.get("source") != "B3/CVM" or not dl.get("seq"):
        return None
    url = (f"https://www.rad.cvm.gov.br/ENET/frmDownloadDocumento.aspx?"
           f"Tela=ext&descTipo={dl['tipo']}&CodigoInstituicao=1"
           f"&numProtocolo={dl['prot']}&numSequencia={dl['seq']}"
           f"&numVersao={dl['ver']}")
    # As vezes a 1a requisicao (sessao recem-aberta) volta o formulario ASP.NET
    # em vez do %PDF - o mesmo "branco" do navegador. Tenta ate 3x c/ sessao nova.
    for tent in range(1, 4):
        try:
            cj = http.cookiejar.CookieJar()
            op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
            op.addheaders = [("User-Agent", "Mozilla/5.0")]
            op.open(RAD_BASE, timeout=40).read()      # abre sessao p/ o download
            raw = op.open(urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0", "Referer": RAD_BASE}),
                timeout=90).read()
            if raw[:4] == b"%PDF":
                if len(raw) > max_bytes:              # muito grande -> so o link
                    log.info("Doc CVM prot %s tem %.1f MB (> limite); anexo pulado.",
                             dl.get("prot"), len(raw) / 1e6)
                    return None
                return (_pdf_filename(item), raw)
            log.info("Doc CVM prot %s: tentativa %d nao veio PDF; repetindo.",
                     dl.get("prot"), tent)
            time.sleep(2)
        except Exception as exc:
            log.warning("Erro baixando PDF CVM (prot %s, tent %d): %s",
                        dl.get("prot"), tent, exc)
            time.sleep(2)
    log.warning("Doc CVM prot %s nao veio como PDF apos 3 tentativas; so o link.",
                dl.get("prot"))
    return None


def send_email(cfg, items):
    # Resumo com IA nos releases (resultados + fatos relevantes); os demais
    # (comunicados/proventos/valores) vao so com o link, sem resumo.
    for i in items:
        if should_summarize(i) and not i.get("summary"):
            i["summary"] = gemini_summarize(extract_document_text(i, cfg), i, cfg)
    # SEM anexo (a pedido 14/08/2026): o visualizador /ENETWeb/ abre o PDF direto
    # no navegador, entao o e-mail leva so o link "abrir documento" (mais leve).
    # (A maquinaria de anexo - _download_cvm_pdf + attachments no _smtp_send -
    #  continua existindo caso queira reativar.)
    companies = ", ".join(sorted({i["company"].split(" (")[0] for i in items}))
    subject = f"[Releases] {len(items)} novo(s): {companies}"[:180]
    text_body, html = build_email_bodies(items)
    if _smtp_send(cfg, subject, text_body, html):
        log.info("E-mail enviado para %s (%d itens).",
                 cfg["email"]["to_addr"], len(items))


# ---------------------------------------------------------------------------
# Batimento diario ("heartbeat"): 1 e-mail/dia confirmando que esta vivo.
# ---------------------------------------------------------------------------
def _load_hb():
    try:
        with open(HEARTBEAT, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {"date": "", "alerts": 0, "sent": ""}


def _save_hb(hb):
    with open(HEARTBEAT, "w", encoding="utf-8") as fh:
        json.dump(hb, fh)


def maybe_heartbeat(cfg, alertas_desta_exec):
    """Acumula o total de alertas do dia e, a partir da hora configurada,
    envia UM e-mail de confirmacao por dia."""
    if not cfg.get("heartbeat_enabled", True):
        return
    hoje = dt.date.today().isoformat()
    hb = _load_hb()
    if hb.get("date") != hoje:                    # virou o dia -> zera contador
        hb = {"date": hoje, "alerts": 0, "sent": hb.get("sent", "")}
    hb["alerts"] = int(hb.get("alerts", 0)) + int(alertas_desta_exec)

    if (dt.datetime.now().hour >= int(cfg.get("heartbeat_hour", 20))
            and hb.get("sent") != hoje):
        n_b3 = len(CVM_WATCH)
        n_us = len(EDGAR_8K) + len(EDGAR_6K) + len(EDGAR_10KQ)
        agora = dt.datetime.now().strftime("%d/%m/%Y %H:%M")
        txt = (
            "release-alert esta funcionando normalmente.\n\n"
            f"Resumo de hoje ({dt.date.today().strftime('%d/%m/%Y')}): "
            f"{hb['alerts']} alerta(s) de release enviado(s).\n"
            f"Empresas monitoradas: B3 = {n_b3}, global/EDGAR = {n_us}.\n"
            f"Ultima verificacao: {agora}.\n\n"
            "(Este e o aviso diario de funcionamento. Alertas de release, quando "
            "ha, chegam em e-mails separados.)")
        if _smtp_send(cfg, f"[release-alert] Tudo funcionando - {hb['alerts']} "
                           f"release(s) hoje", txt):
            log.info("Heartbeat diario enviado (%d alertas hoje).", hb["alerts"])
        hb["sent"] = hoje
    _save_hb(hb)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    cfg = load_config()
    seen = load_state()

    items = fetch_edgar(cfg) + fetch_cvm(cfg)
    # remove duplicados por id dentro da mesma execucao
    uniq = {i["id"]: i for i in items}
    items = list(uniq.values())
    log.info("Coletados %d documentos no total.", len(items))

    alertas = 0
    if seen is None:
        # Primeira execucao: cria baseline e NAO envia e-mail (evita enxurrada).
        save_state({i["id"] for i in items})
        log.info("Baseline criado com %d itens. Nenhum e-mail nesta primeira execucao.",
                 len(items))
    else:
        novos = [i for i in items if i["id"] not in seen]
        if not novos:
            log.info("Nada novo. Nenhum e-mail enviado.")
        else:
            # 8-K item 2.02 e docs da CVM ja sao release; 6-K precisa checar conteudo.
            ua = cfg["edgar_user_agent"]
            to_email = []
            for i in novos:
                if not i.get("verify"):
                    to_email.append(i)
                    continue
                veredito = verify_earnings_6k(i["url"], ua)
                if veredito is True:
                    to_email.append(i)
                elif veredito is None:        # nao deu para checar -> avisa marcado
                    i["kind"] += " [nao verificado]"
                    to_email.append(i)
                else:
                    log.info("  - 6-K ignorado (nao e resultado): %s | %s",
                             i["company"], i["url"])
            # marca TODOS os novos como vistos (inclusive 6-K descartados)
            seen |= {i["id"] for i in novos}
            if to_email:
                log.info("%d documento(s) NOVO(S):", len(to_email))
                for i in to_email:
                    log.info("  + %s | %s | %s | %s", i["source"], i["company"],
                             i["kind"], i["url"])
                send_email(cfg, to_email)
                alertas = len(to_email)
            else:
                log.info("%d novo(s), mas nenhum passou na verificacao. Sem e-mail.",
                         len(novos))
            save_state(seen)

    try:
        maybe_heartbeat(cfg, alertas)
    except Exception as exc:
        log.warning("Falha no heartbeat: %s", exc)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        log.exception("Erro fatal na execucao")
        sys.exit(1)
