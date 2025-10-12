from flask import Flask, render_template, request, flash, redirect, url_for
import requests
import xml.etree.ElementTree as ET
import os
import time
from dotenv import load_dotenv
load_dotenv() 

app = Flask(__name__)
app.secret_key = 'supersecretkey'

API_KEY = os.environ.get('API_KEY')
if not API_KEY:
    print("Warning: API_KEY environment variable not set. VirusTotal requests will fail until you set it.")
VIRUSTOTAL_URL_FILE = 'https://www.virustotal.com/vtapi/v2/file/report'
VIRUSTOTAL_URL_SCAN = 'https://www.virustotal.com/vtapi/v2/file/scan'
VIRUSTOTAL_URL_URL = 'https://www.virustotal.com/vtapi/v2/url/report'

UPLOAD_FOLDER = '/tmp'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

recent_results = []

@app.route('/')
def index():
    return render_template('index.html', recent_results=recent_results)

@app.route('/analyze', methods=['POST'])
def analyze():
    file_hash = request.form.get('file_hash')
    xml_data = request.form.get('xml_data')
    file = request.files.get('file')
    url = request.form.get('url')

    if not file and not url and not file_hash and not xml_data:
        flash('Please input File, URL or Hash', 'error')
        return redirect(url_for('index'))

    if xml_data:
        try:
            root = ET.fromstring(xml_data)
            file_hash = root.findtext('hash')
        except ET.ParseError:
            flash('Invalid XML data.', 'error')
            return redirect(url_for('index'))

    result = {}

    if file:
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        try:
            file.save(file_path)
            with open(file_path, 'rb') as f:
                if not API_KEY:
                    flash('API key not set. Please set the API_KEY environment variable.', 'error')
                    return redirect(url_for('index'))

                files = {'file': (file.filename, f)}
                try:
                    response = requests.post(VIRUSTOTAL_URL_SCAN, files=files, params={'apikey': API_KEY}, timeout=30)
                except requests.RequestException as e:
                    flash(f'Network error when contacting VirusTotal: {e}', 'error')
                    return redirect(url_for('index'))

                try:
                    result = response.json()
                except Exception:
                    txt = (response.text[:500] + '...') if response.text else '<empty response>'
                    flash(f'Unexpected response from VirusTotal (status {response.status_code}): {txt}', 'error')
                    return redirect(url_for('index'))

                # Check if the scan was successful
                if result.get('response_code') == 1:
                    resource_id = result.get('resource') or result.get('scan_id')
                    time.sleep(15)  # Wait to give VirusTotal time to generate the report
                    params = {'apikey': API_KEY, 'resource': resource_id}
                    try:
                        report_response = requests.get(VIRUSTOTAL_URL_FILE, params=params, timeout=30)
                        result = report_response.json()
                    except requests.RequestException as e:
                        flash(f'Network error when fetching report: {e}', 'error')
                        return redirect(url_for('index'))
                    except Exception:
                        txt = (report_response.text[:500] + '...') if report_response and getattr(report_response, 'text', None) else '<empty response>'
                        flash(f'Unexpected report response from VirusTotal: {txt}', 'error')
                        return redirect(url_for('index'))
                else:
                    flash('Error scanning file: {}'.format(result.get('verbose_msg', 'Unknown error')), 'error')
                    return redirect(url_for('index'))
        finally:
            try:
                os.remove(file_path)
            except Exception:
                pass

    elif url:
        if not API_KEY:
            flash('API key not set. Please set the API_KEY environment variable.', 'error')
            return redirect(url_for('index'))
        params = {'apikey': API_KEY, 'resource': url}
        try:
            response = requests.get(VIRUSTOTAL_URL_URL, params=params, timeout=30)
            result = response.json()
        except requests.RequestException as e:
            flash(f'Network error when contacting VirusTotal: {e}', 'error')
            return redirect(url_for('index'))
        except Exception:
            txt = (response.text[:500] + '...') if response and getattr(response, 'text', None) else '<empty response>'
            flash(f'Unexpected response from VirusTotal: {txt}', 'error')
            return redirect(url_for('index'))

    elif file_hash:
        if not API_KEY:
            flash('API key not set. Please set the API_KEY environment variable.', 'error')
            return redirect(url_for('index'))
        params = {'apikey': API_KEY, 'resource': file_hash}
        try:
            response = requests.get(VIRUSTOTAL_URL_FILE, params=params, timeout=30)
            result = response.json()
        except requests.RequestException as e:
            flash(f'Network error when contacting VirusTotal: {e}', 'error')
            return redirect(url_for('index'))
        except Exception:
            txt = (response.text[:500] + '...') if response and getattr(response, 'text', None) else '<empty response>'
            flash(f'Unexpected response from VirusTotal: {txt}', 'error')
            return redirect(url_for('index'))

    else:
        flash('No valid input provided.', 'error')
        return redirect(url_for('index'))

    if result.get('response_code') == 1:
        formatted_result = {
            'file_name': file.filename if file else url if url else file_hash,
            'scan_date': result.get('scan_date', 'N/A'),
            'positives': result.get('positives', 0),
            'total': result.get('total', 0),
            'detections': []
        }

        for engine, details in result.get('scans', {}).items():
            if details.get('detected'):
                formatted_result['detections'].append({
                    'engine': engine,
                    'result': details.get('result', 'N/A'),
                    'version': details.get('version', 'N/A'),
                    'update': details.get('update', 'N/A')
                })

        # Save the formatted result in the recent_results list
        recent_results.insert(0, formatted_result)
        if len(recent_results) > 30:
            recent_results.pop()

        # Count malware and clean detections based on the current scan result
        malware_count = formatted_result['positives']
        clean_count = formatted_result['total'] - malware_count
        
        chart_data = {
            'malware_count': malware_count,
            'clean_count': clean_count
        }
    else:
        flash('Not included in Database / Scan in Progress', 'error')
        return redirect(url_for('index'))

    return render_template('result.html', result=formatted_result, chart_data=chart_data)

if __name__ == '__main__':
    app.run(debug=True, threaded=True)

