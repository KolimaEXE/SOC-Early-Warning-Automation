import requests
import datetime
import calendar
from dateutil.relativedelta import relativedelta
import pyecharts.options as opts
from pyecharts.charts import Radar, Gauge
from pyecharts.render import make_snapshot
from snapshot_selenium import snapshot
import pandas as pd
import pdfkit
import os


# Date & Time
date = datetime.date.today()
past_date = date #- relativedelta(months=1)
year = past_date.year
month = past_date.month
month = calendar.month_name[month]
date = date.strftime("%d/%m/%Y")
cisa_date = past_date.strftime("%m/%Y")

# PDFKit Configuration
wkhtmltopdf_path = r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"
config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path)
options = {
    'page-size':'A4',
    'margin-top':'0mm',
    'margin-right':'0mm',
    'margin-bottom':'0mm',
    'margin-left':'0mm',
    'enable-local-file-access':'',
    'encoding':'utf-8',
    'disable-smart-shrinking':'',
    'dpi': 200
}

# HTML Import
html_template = open("./html_ew.html", encoding="utf-8").read()


# KEV Data
url = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
kev_data = url.json()

kev_references = kev_data["title"]
kev_version = kev_data["catalogVersion"]

df_kev = pd.DataFrame.from_dict(kev_data)
df_kev["vulnerabilities"].apply(pd.Series)
df_kev = pd.concat([df_kev, df_kev["vulnerabilities"].apply(pd.Series)], axis=1)
df_kev.drop(columns="vulnerabilities")
df_kev = df_kev.loc[:, ['cveID','vendorProject','product','vulnerabilityName','dateAdded']]
df_kev["dateAdded"] = pd.to_datetime(df_kev["dateAdded"]).dt.strftime('%d/%m/%Y') # Formattazione data
df_kev = df_kev.drop(df_kev[(df_kev["dateAdded"].str.contains(f"{cisa_date}") == False)].index) # Rimozione dati non necessari
df_kev.sort_values(by='dateAdded', ascending=False, inplace=True)
df_kev.rename(columns={'cveID': 'CVE', 'vendorProject': 'VENDOR', 'product': 'PRODUCT', 'vulnerabilityName': 'NAME', 'dateAdded': 'ADDED'}, inplace=True)

cve_list = df_kev['CVE'].to_list()

kev_table = df_kev.to_html(index=False)
html_kev_table = kev_table.replace('<table border="1" class="dataframe">', '<table class="cve-table">').replace('\n', '').replace('<tr style="text-align: right;">', '<tr>')

# CVE NIST Data

page_counter = 3
global_html_cve = ""

# CVE Data
for cve_selected in cve_list:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_selected}"
    response = requests.get(url)
    cve_data = response.json()
    try:
        cve = cve_data["vulnerabilities"][0]
        cve_details = cve["cve"]
        print(cve_details)
        cve_id = cve_details["id"]
        cve_identifier = cve_details["sourceIdentifier"]
        cve_published = cve_details["published"]
        cve_lastmodified = cve_details["lastModified"]
        cve_vulnstatus = cve_details["vulnStatus"]
        if cve_details.get('cisaExploitAdd') is not None:
            cve_cisa_cisaExploitAdd = cve_details["cisaExploitAdd"]
            cve_cisa_cisaExploitAdd = datetime.datetime.strptime(cve_cisa_cisaExploitAdd, "%Y-%m-%d").strftime("%d/%m/%Y")
            cve_cisa_cisaRequiredAction = cve_details["cisaRequiredAction"]
            cve_cisa_cisaVulnerabilityName = cve_details["cisaVulnerabilityName"]
            cve_name = f"{cve_id} - {cve_cisa_cisaVulnerabilityName}"
        else:
            cve_cisa_cisaExploitAdd = "N/A"
            cve_cisa_cisaRequiredAction = "Not Available"
            cve_name = f"{cve_id}"

        cve_description = cve_details["descriptions"]
        for description in cve_description:
            if description["lang"] == "en":
                cve_description = description["value"]
                continue

        cve_published = datetime.datetime.fromisoformat(cve_published).strftime("%d/%m/%Y %H:%M:%S")
        cve_lastmodified = datetime.datetime.fromisoformat(cve_lastmodified).strftime("%d/%m/%Y %H:%M:%S")

        # CVE Details
        def map_cvss_values(cvss_data, version):
            global html_cvss_table, cve_cvss_baseScore
            if version == "v2":
                access_vector_mapping = {"NETWORK": 5, "ADJACENT NETWORK": 3.33, "LOCAL": 1.66}
                access_complexity_mapping = {"LOW": 5, "MEDIUM": 3.33, "HIGH": 1.66}
                authentication_mapping = {"NONE": 5, "SINGLE": 3.33, "MULTIPLE": 1.66}
                confidentiality_impact_mapping = {"COMPLETE": 5, "PARTIAL": 2.5, "NONE": 0}
                integrity_impact_mapping = {"COMPLETE": 5, "PARTIAL": 2.5, "NONE": 0}
                availability_impact_mapping = {"COMPLETE": 5, "PARTIAL": 2.5, "NONE": 0}

                access_vector_value = access_vector_mapping.get(cvss_data.get("accessVector"), 0)
                access_complexity_value = access_complexity_mapping.get(cvss_data.get("accessComplexity"), 0)
                authentication_value = authentication_mapping.get(cvss_data.get("authentication"), 0)
                confidentiality_impact_value = confidentiality_impact_mapping.get(cvss_data.get("confidentialityImpact"), 0)
                integrity_impact_value = integrity_impact_mapping.get(cvss_data.get("integrityImpact"), 0)
                availability_impact_value = availability_impact_mapping.get(cvss_data.get("availabilityImpact"), 0)
                
                cve_cvss_baseSeverity = cvss_data.get("baseSeverity")
                if cve_cvss_baseSeverity == "CRITICAL":
                    baseSeverity = "#FF2B2B"
                    baseScore = "#FF2B2B"
                elif cve_cvss_baseSeverity == "HIGH":
                    baseSeverity = "#FF9900"
                    baseScore = "#FF9900"
                elif cve_cvss_baseSeverity == "MEDIUM":
                    baseSeverity = "#FFC000"
                    baseScore = "#FFC000"
                elif cve_cvss_baseSeverity == "LOW":
                    baseSeverity = "#33FF00"
                    baseScore = "#33FF00"
                else:
                    baseSeverity = "#000000"
                    baseScore = "#000000"
                cve_score_impactScore = cvss_data.get("impactScore")
                cve_score_exploitabilityScore = cvss_data.get("exploitabilityScore")
                cve_cvss_baseScore = cvss_data.get("baseScore")
                cve_cvss_accessVector = cvss_data.get("accessVector")
                cve_cvss_accessComplexity = cvss_data.get("accessComplexity")
                cve_cvss_Authenticationd = cvss_data.get("authentication")
                cve_cvss_confidentialityImpact = cvss_data.get("confidentialityImpact")
                cve_cvss_integrityImpact = cvss_data.get("integrityImpact")
                cve_cvss_availabilityImpact = cvss_data.get("availabilityImpact")
                
                html_cvss_table = f"""
                                <table class="cvss-table">
                            <tr>
                                <td>Severity:</td>
                                <td style="color: {baseSeverity}">{cve_cvss_baseSeverity}</td>
                            </tr>
                            <tr>
                                <td>Score</td>
                                <td style="color: {baseScore}">{cve_cvss_baseScore}</td>
                            </tr>
                            <tr>
                                <td>Impact Score</td>
                                <td>{cve_score_impactScore}</td>
                            </tr>
                            <tr>
                                <td>Exploitablity Score</td>
                                <td>{cve_score_exploitabilityScore}</td>
                            </tr>
                            <tr>
                                <td>Access Vector</td>
                                <td>{cve_cvss_accessVector}</td>
                            </tr>
                            <tr>
                                <td>Access Complexity</td>
                                <td>{cve_cvss_accessComplexity}</td>
                            </tr>
                            <tr>
                                <td>Authentication</td>
                                <td>{cve_cvss_Authenticationd}</td>
                            </tr>
                            <tr>
                                <td>Confidentiality Impact</td>
                                <td>{cve_cvss_confidentialityImpact}</td>
                            </tr>
                            <tr>
                                <td>Integrity Impact</td>
                                <td>{cve_cvss_integrityImpact}</td>
                            </tr>
                            <tr>
                                <td>Availability Impact</td>
                                <td>{cve_cvss_availabilityImpact}</td>
                            </tr>
                        </table>
                """

                return [access_vector_value, access_complexity_value, authentication_value, confidentiality_impact_value, integrity_impact_value, availability_impact_value, html_cvss_table]

            attack_vector_mapping = {"NETWORK": 5, "ADJACENT": 3.75, "LOCAL": 2.5, "PHYSICAL": 1.25}
            attack_complexity_mapping = {"LOW": 5, "HIGH": 2.5}
            privileges_required_mapping = {"NONE": 5, "LOW": 3.33, "HIGH": 1.66}
            user_interaction_mapping = {"NONE": 5, "REQUIRED": 2.5}
            impact_mapping = {"HIGH": 5, "LOW": 2.5, "NONE": 0}

            attack_vector_value = attack_vector_mapping.get(cvss_data.get("attackVector"), 0)
            attack_complexity_value = attack_complexity_mapping.get(cvss_data.get("attackComplexity"), 0)
            privileges_required_value = privileges_required_mapping.get(cvss_data.get("privilegesRequired"), 0)
            user_interaction_value = user_interaction_mapping.get(cvss_data.get("userInteraction"), 0)
            confidentiality_impact_value = impact_mapping.get(cvss_data.get("confidentialityImpact"), 0)
            integrity_impact_value = impact_mapping.get(cvss_data.get("integrityImpact"), 0)
            availability_impact_value = impact_mapping.get(cvss_data.get("availabilityImpact"), 0)
            
            cve_cvss_baseSeverity = cvss_data.get("baseSeverity")
            if cve_cvss_baseSeverity == "CRITICAL":
                baseSeverity = "#FF2B2B"
                baseScore = "#FF2B2B"
            elif cve_cvss_baseSeverity == "HIGH":
                baseSeverity = "#FF9900"
                baseScore = "#FF9900"
            elif cve_cvss_baseSeverity == "MEDIUM":
                baseSeverity = "#FFC000"
                baseScore = "#FFC000"
            elif cve_cvss_baseSeverity == "LOW":
                baseSeverity = "#33FF00"
                baseScore = "#33FF00"
            else:
                baseSeverity = "#FFFFFF"
                baseScore = "#FFFFFF"
            cve_score_impactScore = cvss_data.get("impactScore")
            cve_score_exploitabilityScore = cvss_data.get("exploitabilityScore")
            cve_cvss_baseScore = cvss_data.get("baseScore")
            cve_cvss_attackVector = cvss_data.get("attackVector")
            cve_cvss_attackComplexity = cvss_data.get("attackComplexity")
            cve_cvss_privilegesRequired = cvss_data.get("privilegesRequired")
            cve_cvss_userInteraction = cvss_data.get("userInteraction")
            cve_cvss_scope = cvss_data.get("scope")
            cve_cvss_confidentialityImpact = cvss_data.get("confidentialityImpact")
            cve_cvss_integrityImpact = cvss_data.get("integrityImpact")
            cve_cvss_availabilityImpact = cvss_data.get("availabilityImpact")
            
            html_cvss_table = f"""
                            <table class="cvss-table">
                        <tr>
                            <td>Severity:</td>
                            <td style="color: {baseSeverity}">{cve_cvss_baseSeverity}</td>
                        </tr>
                        <tr>
                            <td>Score</td>
                            <td style="color: {baseScore}">{cve_cvss_baseScore}</td>
                        </tr>
                        <tr>
                            <td>Impact Score</td>
                            <td>{cve_score_impactScore}</td>
                        </tr>
                        <tr>
                            <td>Exploitablity Score</td>
                            <td>{cve_score_exploitabilityScore}</td>
                        </tr>
                        <tr>
                            <td>Attack Vector</td>
                            <td>{cve_cvss_attackVector}</td>
                        </tr>
                        <tr>
                            <td>Attack Complexity</td>
                            <td>{cve_cvss_attackComplexity}</td>
                        </tr>
                        <tr>
                            <td>Privileges Required</td>
                            <td>{cve_cvss_privilegesRequired}</td>
                        </tr>
                        <tr>
                            <td>User Interaction</td>
                            <td>{cve_cvss_userInteraction}</td>
                        </tr>
                        <tr>
                            <td>Scope</td>
                            <td>{cve_cvss_scope}</td>
                        </tr>
                        <tr>
                            <td>Confidentiality Impact</td>
                            <td>{cve_cvss_confidentialityImpact}</td>
                        </tr>
                        <tr>
                            <td>Integrity Impact</td>
                            <td>{cve_cvss_integrityImpact}</td>
                        </tr>
                        <tr>
                            <td>Availability Impact</td>
                            <td>{cve_cvss_availabilityImpact}</td>
                        </tr>
                    </table>
            """

            return [attack_vector_value, attack_complexity_value, privileges_required_value, user_interaction_value, confidentiality_impact_value, integrity_impact_value, availability_impact_value, html_cvss_table]

        if "cvssMetricV31" in cve_details["metrics"]:
            cvss_version = "v3.1"
            cvss_data = cve_details["metrics"]["cvssMetricV31"][0]["cvssData"]
        elif "cvssMetricV30" in cve_details["metrics"]:
            cvss_version = "v3.0"
            cvss_data = cve_details["metrics"]["cvssMetricV30"][0]["cvssData"]
        elif "cvssMetricV2" in cve_details["metrics"]:
            cvss_version = "v2"
            cvss_data = cve_details["metrics"]["cvssMetricV2"][0]["cvssData"]
        else:
            continue

        if cvss_version == "v2": 
            cvss_metrics = [
                    "ACCESS VECTOR",
                    "ACCESS COMPLEXITY",
                    "AUTHENTICATION",
                    "CONFIDENTIALITY",
                    "INTEGRITY",
                    "AVAILABILITY"
                ]       
        elif cvss_version == "v3.1" or cvss_version == "v3.0":
            cvss_metrics = [
                    "ATTACK VECTOR",
                    "ATTACK COMPLEXITY",
                    "PRIVILEGES REQUIRED",
                    "USER INTERACTION",
                    "CONFIDENTIALITY",
                    "INTEGRITY",
                    "AVAILABILITY"
                ]

        cvss_metrics_values = map_cvss_values(cvss_data, cvss_version)

        # CVE Severity Chart
        cvss_radar = (
            Radar()
            .add_schema(
                schema=[
                    opts.RadarIndicatorItem(name=tactic, max_=5.2, color="#FFFFFF") for tactic in cvss_metrics
                    
                ],
                
                shape = "polygon",
                splitarea_opt=opts.SplitAreaOpts(is_show=True, areastyle_opts=opts.AreaStyleOpts(opacity=1)),
            )
            .add(
                series_name="MITRE ATT&CK",
                data=[cvss_metrics_values],
                symbol="none",
                linestyle_opts=opts.LineStyleOpts(color="#522988", width=1.5),
                areastyle_opts=opts.AreaStyleOpts(color="#6A359D", opacity=0.3),
            )
            .set_series_opts(label_opts=opts.LabelOpts(is_show=False, color="#000"))
            .set_global_opts(
                legend_opts=opts.LegendOpts(is_show=False),
            )
        )
        make_snapshot(snapshot, cvss_radar.render(), f"cvss_{cve_id}.png")

        #CVSS HTML Title
        html_cvss_title = f"Common Vulnerability Scoring System {cvss_version} (CVSS{cvss_version})"

        #CVSS Score Chart
        score_gauge = (
            Gauge()
                .add("",
                    [("Score", cve_cvss_baseScore)],
                    detail_label_opts=opts.LabelOpts(
                        formatter="{value}",color="#FFFFFF"),
                    max_=10,
                    title_label_opts=opts.GaugeTitleOpts(
                        color="#FFFFFF"),
                    axislabel_opts=opts.LabelOpts(color="#FFFFFF")
                    )
                .set_global_opts(
                    legend_opts=opts.LegendOpts(is_show=False),
                )
                .set_series_opts(
                    axisline_opts=opts.AxisLineOpts(
                    linestyle_opts=opts.LineStyleOpts(
                    color=[[0.005,"#FFFFFF"],[0.25,"#34EB46"],[0.5,"#EBD334"],[0.75,"#EB9334"],[1,"#EB3434"]], width=10)),
                )
            )
        make_snapshot(snapshot, score_gauge.render(), f"score_{cve_id}.png")
        
        # CVE HTML Page
        html_cve = f"""
            <!-- CVE PAGE  -->
        
            <div class="page-container">
                <div class="page-inner">
                    <header>
                        <div class="top-section">
                            <p>EARLY WARNING - <span>{cve_id}</span></p>
                            <p>Page {page_counter}</p>
                        </div>
                        <hr>
                    </header>

                    <h2>{cve_id}</h2>

                    <table class="cve-table">
                        <tr>
                            <th>PUBLISHING DATE</th>
                            <th>LAST MODIFICATION DATE</th>
                            <th>EXPLOIT DATE</th>
                        </tr>
                        <tr>
                            <td>{cve_published}</td>
                            <td>{cve_lastmodified}</td>
                            <td>{cve_cisa_cisaExploitAdd}</td>
                        </tr>
                    </table>

                    <h4 style="margin-top: 8px;">Description</h4>
                    <p class="cve">{cve_description}</p>

                    <h4 class="cve-title">Required Action</h4>
                    <p class="cve">{cve_cisa_cisaRequiredAction}</p>
                    
                    <h3 class="cve-title">{html_cvss_title}</h3>
                    {html_cvss_table}
        
                    <img src="./score_{cve_id}.png" class="score-img">
                    <img src="./cvss_{cve_id}.png" class="cvss-img">

                    <footer>
                        <hr>
                        <div class="bottom-section">
                            <p>RISERVATO - <span style="color: #FFC000;">TLP:AMBER</span></p>
                            <img src="./img/logo.png" class="footer-logo">
                        </div>
                    </footer>
                </div>
            </div>
        """
        global_html_cve += html_cve
        page_counter += 1
    except IndexError:
        html_cve = f"""
            <div class="page-container">
                <div class="page-inner">
                    <header>
                        <div class="top-section">
                            <p>EARLY WARNING - <span>{cve_id}</span></p>
                            <p>Page {page_counter}</p>
                        </div>
                        <hr>
                    </header>

                    <h2>{cve_id}</h2>
                    <p style="margin-top: 20px;">CVE data not found or not available.</p>
                    <img src="./img/404.png" class="error-img">

                    <footer>
                        <hr>
                        <div class="bottom-section">
                            <p>RISERVATO - <span style="color: #FFC000;">TLP:AMBER</span></p>
                            <img src="./img/logo.png" class="footer-logo">
                        </div>
                    </footer>
                </div>
            </div>
            """
        global_html_cve += html_cve
        page_counter += 1
    
global_html_cve.replace('\n','')

# Variables for HTML and formatting
html_vars = {
             "month": month,
             "year": year,
             "kev_references": kev_references,
             "kev_version": kev_version,
             "html_kev_table": html_kev_table,
             "global_html_cve": global_html_cve
             }
html = html_template.format(**html_vars)

# HTML Report Writing
file = open(f"./Early Warning - {month} {year}.html", "w", encoding="utf-8")
file.write(html)
file.close()

# PDF Conversion
html_path = f"./Early Warning - {month} {year}.html"
pdfkit.from_file(html_path, output_path=f"./Early Warning - {month} {year}.pdf", configuration=config, options=options)

# Deleting useless files after report generation
os.remove(html_path)
os.remove('render.html')
for cve_del in cve_list:
    try:
        os.remove(f"score_{cve_del}.png")
        os.remove(f"cvss_{cve_del}.png")
    except FileNotFoundError:
        continue