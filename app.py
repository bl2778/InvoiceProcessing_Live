from flask import Flask, request, render_template, send_file, flash, redirect, url_for, jsonify, session
import os
import zipfile
import tempfile
import shutil
from werkzeug.utils import secure_filename
import pandas as pd
from extractor import Extractor
from datetime import datetime
import uuid
import re
import threading
import time
import json
from functools import wraps
import requests
import signal

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

ALLOWED_EXTENSIONS = {'pdf'}

# Storage for access logs, processing results, and progress tracking
access_logs = []
processing_results = {}
processing_progress = {}
ip_location_cache = {}

# Admin password
ADMIN_PASSWORD = "admin123"

# AI model configurations
AI_MODELS = {
    'gpt-4o': {
        'name': 'ChatGPT-4o',
        'api_type': 'openai'
    },
    'deepseek-v3': {
        'name': 'DeepSeek V3',
        'api_type': 'deepseek'
    },
    'deepseek-r1': {
        'name': 'DeepSeek R1',
        'api_type': 'deepseek'
    }
}

def extract_text_for_gpt(pdf_path: str) -> str:
    """Extract text from PDF for AI processing"""
    import pdfplumber
    full_text = ""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    full_text += page_text + "\n"
    except Exception as e:
        print(f"Failed to extract PDF text: {e}")
    return full_text

def call_ai_model(model_name, api_key, text_content, timeout=60):
    """Call AI model to process text with timeout control"""
    
    def timeout_handler(signum, frame):
        raise TimeoutError("AI processing timeout")
    
    # Set timeout signal
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)
    
    try:
        prompt = f"""以下是一份可能为收据或酒店账单的文本内容：
{text_content}

请帮我从中提取以下信息：
1）时间：xxxx年xx月xx日
2）总金额
3）酒店/餐厅名字

最后请按照以下格式返回：xxxx年xx月xx日_金额_酒店或餐厅名字
仅返回这一行，不需要额外解释。"""

        if model_name == 'gpt-4o':
            # OpenAI GPT-4o
            import openai
            client = openai.OpenAI(api_key=api_key)
            
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant that extracts invoice information."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0,
                max_tokens=100
            )
            
            result = response.choices[0].message.content.strip()
            
        elif model_name in ['deepseek-v3', 'deepseek-r1']:
            # DeepSeek API
            deepseek_model = 'deepseek-chat' if model_name == 'deepseek-v3' else 'deepseek-reasoner'
            
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'model': deepseek_model,
                'messages': [
                    {"role": "system", "content": "You are a helpful assistant that extracts invoice information."},
                    {"role": "user", "content": prompt}
                ],
                'temperature': 0,
                'max_tokens': 100
            }
            
            response = requests.post(
                'https://api.deepseek.com/chat/completions',
                headers=headers,
                json=data,
                timeout=50
            )
            
            if response.status_code == 200:
                result = response.json()['choices'][0]['message']['content'].strip()
            else:
                raise Exception(f"DeepSeek API error: {response.status_code}")
        
        else:
            raise Exception(f"Unsupported model: {model_name}")
        
        signal.alarm(0)  # Cancel timeout
        return result
        
    except TimeoutError:
        signal.alarm(0)
        raise Exception("AI processing timeout (60 seconds)")
    except Exception as e:
        signal.alarm(0)
        raise e

def get_ip_location(ip_address):
    """Query IP address geolocation"""
    if ip_address in ip_location_cache:
        return ip_location_cache[ip_address]
    
    if ip_address in ['unknown', '127.0.0.1', 'localhost'] or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
        location = "Local/Private"
        ip_location_cache[ip_address] = location
        return location
    
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}?lang=en', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                country = data.get('country', '')
                region = data.get('regionName', '')
                city = data.get('city', '')
                
                location_parts = []
                if country:
                    location_parts.append(country)
                if region and region != country:
                    location_parts.append(region)
                if city and city != region:
                    location_parts.append(city)
                
                location = ' - '.join(location_parts) if location_parts else 'Unknown'
                ip_location_cache[ip_address] = location
                return location
            else:
                location = "Query Failed"
        else:
            location = "API Error"
            
    except Exception as e:
        print(f"IP geolocation query failed: {e}")
        location = "Query Exception"
    
    ip_location_cache[ip_address] = location
    return location

def log_access(endpoint, extra_data=None):
    """Log user access"""
    try:
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
        
        location = get_ip_location(ip_address)
        
        log_entry = {
            'timestamp': (datetime.now() + pd.Timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S'),
            'ip': ip_address,
            'location': location,
            'user_agent': request.headers.get('User-Agent', 'unknown'),
            'endpoint': endpoint,
            'method': request.method,
            'referer': request.headers.get('Referer', 'direct'),
            'extra_data': extra_data or {}
        }
        
        access_logs.append(log_entry)
        
        if len(access_logs) > 1000:
            access_logs.pop(0)
            
        print(f"Access logged: {ip_address} ({location}) -> {endpoint}")
        
    except Exception as e:
        print(f"Access logging failed: {e}")

def require_admin(f):
    """Admin authentication decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_authenticated' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def schedule_cleanup(job_id, delay=3600):
    """Schedule cleanup of temporary files and data after specified delay"""
    def cleanup():
        time.sleep(delay)
        if job_id in processing_results:
            result = processing_results[job_id]
            temp_dir = result.get('temp_dir')
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            processing_results.pop(job_id, None)
            print(f"Auto-cleaned job: {job_id}")
        
        # Also clean up progress tracking
        if job_id in processing_progress:
            processing_progress.pop(job_id, None)
    
    threading.Thread(target=cleanup, daemon=True).start()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_pdf_file(file_path, results_list, use_ai=False, ai_model=None, api_key=None, job_id=None):
    """Process a single PDF file and return the new filename"""
    
    try:
        # Update progress
        if job_id and job_id in processing_progress:
            processing_progress[job_id]['current_file'] = os.path.basename(file_path)
            processing_progress[job_id]['status'] = 'OCR Processing...'
        
        # Try OCR extraction first
        data = Extractor(file_path).extract()
        
        if data.empty or ("开票日期" not in data.columns and "价税合计(小写)" not in data.columns):
            if not use_ai:
                raise ValueError("Not a standard invoice, OCR extraction failed.")
            else:
                # Mark for AI processing
                raise ValueError("OCR failed, will use AI")
        
        # Extract information for filename
        try:
            inv_value = data["价税合计(小写)"].to_list()[0]
        except:
            inv_value = "Error"
        
        try:
            _prov = data["销售方名称"].to_list()[0]
            inv_provider = _prov[3:] if "：" in _prov else _prov
        except:
            inv_provider = "Error"
        
        try:
            inv_date = data["开票日期"].to_list()[0]
        except:
            inv_date = "Error"
        
        new_filename = "_".join([inv_date, inv_value, inv_provider]) + ".pdf"
        
        # Store the extracted data for reporting
        results_list.append({
            'original_filename': os.path.basename(file_path),
            'new_filename': new_filename,
            'date': inv_date,
            'amount': inv_value,
            'issuer': inv_provider,
            'status': 'success',
            'method': 'OCR'
        })
        
        return new_filename
        
    except Exception as e:
        print(f"OCR failed for {os.path.basename(file_path)}: {e}")
        
        # If AI is enabled and OCR failed, try AI processing
        if use_ai and ai_model and api_key:
            try:
                # Update progress
                if job_id and job_id in processing_progress:
                    processing_progress[job_id]['status'] = f'AI Processing ({AI_MODELS[ai_model]["name"]})...'
                
                # Extract PDF text
                pdf_text = extract_text_for_gpt(file_path)
                if not pdf_text.strip():
                    raise Exception("Cannot extract PDF text")
                
                # Call AI model
                ai_result = call_ai_model(ai_model, api_key, pdf_text)
                
                # Parse AI result
                if ai_result and len(ai_result.split('_')) >= 3:
                    new_filename = ai_result + "_AI.pdf"
                    
                    # Try to parse date, amount, issuer
                    parts = ai_result.split('_')
                    ai_date = parts[0] if len(parts) > 0 else 'AI Parsed'
                    ai_amount = parts[1] if len(parts) > 1 else 'AI Parsed'
                    ai_issuer = '_'.join(parts[2:]) if len(parts) > 2 else 'AI Parsed'
                    
                    results_list.append({
                        'original_filename': os.path.basename(file_path),
                        'new_filename': new_filename,
                        'date': ai_date,
                        'amount': ai_amount,
                        'issuer': ai_issuer,
                        'status': 'success',
                        'method': f'AI ({AI_MODELS[ai_model]["name"]})'
                    })
                    
                    return new_filename
                else:
                    raise Exception("AI returned incorrect format")
                    
            except Exception as ai_e:
                print(f"AI processing failed for {os.path.basename(file_path)}: {ai_e}")
                # AI also failed, continue to failure handling
                pass
        
        # Both OCR and AI failed, or AI not enabled
        original_filename = os.path.basename(file_path)
        new_filename = f"ProcessingError_{original_filename}"
        
        # Store the failed result
        results_list.append({
            'original_filename': original_filename,
            'new_filename': new_filename,
            'date': 'N/A',
            'amount': 'N/A',
            'issuer': 'N/A',
            'status': 'failed',
            'method': 'Failed'
        })
        
        return new_filename

# ============ Main Routes ============

@app.route('/')
def index():
    log_access('Home Page Visit')
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_files():
    files = request.files.getlist('files')
    use_ai = request.form.get('use_ai') == 'true'
    ai_model = request.form.get('ai_model')
    api_key = request.form.get('api_key')
    
    file_count = len(files)
    log_access('File Upload', {'file_count': file_count, 'use_ai': use_ai, 'ai_model': ai_model})
    
    if not files or files[0].filename == '':
        return jsonify({'success': False, 'message': 'No files selected'})
    
    # Validate AI parameters
    if use_ai:
        if not ai_model or ai_model not in AI_MODELS:
            return jsonify({'success': False, 'message': 'Please select a valid AI model'})
        if not api_key or len(api_key.strip()) < 10:
            return jsonify({'success': False, 'message': 'Please enter a valid API Key'})
    
    job_id = str(uuid.uuid4())
    temp_dir = tempfile.mkdtemp()
    
    # Initialize progress tracking
    processing_progress[job_id] = {
        'total_files': file_count,
        'processed_files': 0,
        'current_file': '',
        'status': 'Preparing to process...',
        'phase': 'OCR',
        'completed': False
    }
    
    def process_files_async():
        processed_files = []
        results_list = []
        failed_files = []  # Store OCR failed files for AI processing
        
        try:
            # Phase 1: OCR process all files
            processing_progress[job_id]['phase'] = 'OCR'
            processing_progress[job_id]['status'] = 'OCR Processing...'
            
            for i, file in enumerate(files):
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(temp_dir, filename)
                    file.save(file_path)
                    
                    # Update progress
                    processing_progress[job_id]['processed_files'] = i
                    processing_progress[job_id]['current_file'] = filename
                    
                    # Try OCR first, without AI
                    new_filename = process_pdf_file(file_path, results_list, use_ai=False, job_id=job_id)
                    
                    # Check if successful
                    if results_list and results_list[-1]['status'] == 'failed':
                        # OCR failed, add to AI processing queue
                        if use_ai:
                            failed_files.append((file_path, results_list.pop()))  # Remove failed record, wait for AI processing
                        else:
                            # Not using AI, directly process failed file
                            new_file_path = os.path.join(temp_dir, new_filename)
                            shutil.move(file_path, new_file_path)
                            processed_files.append(new_file_path)
                    else:
                        # OCR successful
                        new_file_path = os.path.join(temp_dir, new_filename)
                        
                        # Handle duplicate filenames
                        counter = 1
                        while os.path.exists(new_file_path):
                            base, ext = os.path.splitext(new_filename)
                            new_filename = f"{base}_{counter}{ext}"
                            new_file_path = os.path.join(temp_dir, new_filename)
                            counter += 1
                        
                        shutil.move(file_path, new_file_path)
                        processed_files.append(new_file_path)
            
            # Phase 2: AI process failed files
            if use_ai and failed_files:
                processing_progress[job_id]['phase'] = 'AI'
                processing_progress[job_id]['status'] = f'AI Processing ({AI_MODELS[ai_model]["name"]})...'
                
                for i, (file_path, failed_record) in enumerate(failed_files):
                    processing_progress[job_id]['processed_files'] = len(files) - len(failed_files) + i
                    processing_progress[job_id]['current_file'] = os.path.basename(file_path)
                    
                    # Use AI processing
                    new_filename = process_pdf_file(file_path, results_list, use_ai=True, 
                                                 ai_model=ai_model, api_key=api_key, job_id=job_id)
                    
                    new_file_path = os.path.join(temp_dir, new_filename)
                    
                    # Handle duplicate filenames
                    counter = 1
                    while os.path.exists(new_file_path):
                        base, ext = os.path.splitext(new_filename)
                        new_filename = f"{base}_{counter}{ext}"
                        new_file_path = os.path.join(temp_dir, new_filename)
                        counter += 1
                    
                    shutil.move(file_path, new_file_path)
                    processed_files.append(new_file_path)
            
            # Create ZIP file
            processing_progress[job_id]['status'] = 'Creating ZIP file...'
            zip_path = os.path.join(temp_dir, 'processed_invoices.zip')
            with zipfile.ZipFile(zip_path, 'w') as zip_file:
                for file_path in processed_files:
                    zip_file.write(file_path, os.path.basename(file_path))
            
            # Save results
            processing_results[job_id] = {
                'zip_path': zip_path,
                'temp_dir': temp_dir,
                'results': results_list,
                'timestamp': (datetime.now() + pd.Timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S'),
                'use_ai': use_ai,
                'ai_model': ai_model if use_ai else None
            }
            
            # Complete processing
            processing_progress[job_id]['completed'] = True
            processing_progress[job_id]['processed_files'] = len(files)
            processing_progress[job_id]['status'] = 'Processing complete!'
            
            schedule_cleanup(job_id)
            
        except Exception as e:
            processing_progress[job_id]['status'] = f'Processing failed: {str(e)}'
            processing_progress[job_id]['completed'] = True
    
    # Start async processing
    threading.Thread(target=process_files_async, daemon=True).start()
    
    return jsonify({
        'success': True,
        'job_id': job_id,
        'message': 'Started processing files...'
    })

@app.route('/progress/<job_id>')
def get_progress(job_id):
    """Get processing progress"""
    if job_id not in processing_progress:
        return jsonify({'error': 'Job not found'}), 404
    
    progress = processing_progress[job_id]
    
    if progress['completed'] and job_id in processing_results:
        # Processing complete, return final results
        results = processing_results[job_id]['results']
        total_files = len(results)
        successful_files = len([r for r in results if r['status'] == 'success'])
        failed_files = total_files - successful_files
        
        return jsonify({
            'completed': True,
            'total_files': total_files,
            'successful_files': successful_files,
            'failed_files': failed_files,
            'progress_percent': 100,
            'status': 'Processing complete!'
        })
    
    # Calculate progress percentage
    progress_percent = int((progress['processed_files'] / progress['total_files']) * 100) if progress['total_files'] > 0 else 0
    
    return jsonify({
        'completed': False,
        'processed_files': progress['processed_files'],
        'total_files': progress['total_files'],
        'current_file': progress['current_file'],
        'status': progress['status'],
        'phase': progress['phase'],
        'progress_percent': progress_percent
    })

@app.route('/download/<job_id>')
def download_zip(job_id):
    log_access('File Download', {'job_id': job_id})
    if job_id not in processing_results:
        flash('Processing results not found or expired')
        return redirect(url_for('index'))
    
    zip_path = processing_results[job_id]['zip_path']
    return send_file(zip_path, as_attachment=True, download_name='processed_invoices.zip')

@app.route('/report/<job_id>')
def view_report(job_id):
    log_access('View Report', {'job_id': job_id})
    if job_id not in processing_results:
        flash('Processing results not found or expired')
        return redirect(url_for('index'))
    
    results = processing_results[job_id]['results']
    
    # Sort results: successful ones by date first, then failed ones at the end
    successful_results = [r for r in results if r['status'] == 'success']
    failed_results = [r for r in results if r['status'] == 'failed']
    
    # Sort successful results by date
    def parse_chinese_date(date_str):
        try:
            if date_str == 'Error' or date_str == 'N/A':
                return datetime(9999, 12, 31)
            
            match = re.match(r'(\d{4})年(\d{1,2})月(\d{1,2})日', date_str)
            if match:
                year, month, day = match.groups()
                return datetime(int(year), int(month), int(day))
            else:
                return datetime(9999, 12, 31)
        except:
            return datetime(9999, 12, 31)
    
    try:
        successful_results.sort(key=lambda x: parse_chinese_date(x['date']))
    except:
        pass
    
    sorted_results = successful_results + failed_results
    
    return render_template('report.html', 
                         results=sorted_results, 
                         timestamp=processing_results[job_id]['timestamp'],
                         job_id=job_id)

# ============ Admin Functions ============

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Incorrect password')
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_authenticated', None)
    return redirect(url_for('index'))

@app.route('/admin')
@require_admin
def admin_dashboard():
    # Statistics
    total_visits = len(access_logs)
    unique_ips = len(set(log['ip'] for log in access_logs))
    upload_count = len([log for log in access_logs if log['endpoint'] == 'File Upload'])
    download_count = len([log for log in access_logs if log['endpoint'] == 'File Download'])
    
    # Geographic statistics
    location_stats = {}
    for log in access_logs:
        location = log.get('location', 'Unknown')
        if location and location not in ['Querying...', 'Query Failed', 'API Error', 'Query Exception']:
            location_stats[location] = location_stats.get(location, 0) + 1
    
    # Get recent 50 records
    recent_logs = access_logs[-50:]
    
    stats = {
        'total_visits': total_visits,
        'unique_ips': unique_ips,
        'upload_count': upload_count,
        'download_count': download_count,
        'total_jobs': len(processing_results),
        'top_locations': sorted(location_stats.items(), key=lambda x: x[1], reverse=True)[:5]
    }
    
    return render_template('admin_dashboard.html', 
                         logs=recent_logs, 
                         stats=stats)

@app.route('/admin/logs/export')
@require_admin
def export_logs():
    """Export access logs as JSON file"""
    log_data = {
        'export_time': (datetime.now() + pd.Timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S'),
        'total_records': len(access_logs),
        'logs': access_logs
    }
    
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(log_data, temp_file, ensure_ascii=False, indent=2)
    temp_file.close()
    
    return send_file(temp_file.name, 
                    as_attachment=True, 
                    download_name=f'access_logs_{datetime.now().strftime("%Y%m%d_%H%M")}.json')

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
