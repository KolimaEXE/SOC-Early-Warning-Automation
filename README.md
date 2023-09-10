![report automation]([./demo/Report%20Automation.jpg](https://github.com/KolimaH4x/Early-Warning-Automation/blob/main/demo/Report%20Automation.jpg))

# Automated Early Warning Reports in Python :bar_chart:	
Automate your Early Warning reports with Python :snake:. \
This script automatically generates an Early Warning PDF report, is designed for companies offering SOC services and can be customized with your company logo. \
Data on the most exploited CVEs are taken from the CISA KEV (Known Exploited Vulnerabilities) catalog. The script uses HTTP requests to access NIST APIs to obtain detailed information about each CVE, such as description, severity, and so on. \
The script uses the Python Pyecharts library to create information graphics representing CVEs based on various criteria. After collecting all the data it uses the wkhtmltopdf conversion tool and the Python PDFKit library to generate a high-quality PDF report. \
It is designed to run monthly and retrieves all CVEs released in the KEV catalog in the previous month.

## Links :globe_with_meridians:
* `wkhtmltopdf` Website https://wkhtmltopdf.org/
* `pyecharts` Website https://pyecharts.org/#/

## Report Demo :card_index_dividers:
### Convert Report to PDF
![demo](https://github.com/KolimaH4x/Early-Warning-Automation/blob/main/demo/Demo.gif)
