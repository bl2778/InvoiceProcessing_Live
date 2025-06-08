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

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

ALLOWED_EXTENSIONS = {'pdf'}

# 存储访问记录和处理结果
access_logs = []
processing_results = {}

# IP地理位置缓存（避免重复查询相同IP）
ip_location_cache = {}

# 管理员密码
ADMIN_PASSWORD = "admin123"

def get_ip_location(ip_address):
    """查询IP地址的地理位置"""
    # 检查缓存
    if ip_address in ip_location_cache:
        return ip_location_cache[ip_address]
    
    # 跳过本地和内网IP
    if ip_address in ['unknown', '127.0.0.1', 'localhost'] or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
        location = "本地/内网"
        ip_location_cache[ip_address] = location
        return location
    
    try:
        # 使用免费的ip-api.com服务查询IP地理位置
        response = requests.get(f'http://ip-api.com/json/{ip_address}?lang=zh-CN', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                # 组合地理位置信息：国家 - 省/州 - 城市
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
                
                location = ' - '.join(location_parts) if location_parts else '未知'
                
                # 缓存结果
                ip_location_cache[ip_address] = location
                return location
            else:
                location = "查询失败"
        else:
            location = "API错误"
            
    except Exception as e:
        print(f"IP地理位置查询失败: {e}")
        location = "查询异常"
    
    # 缓存失败结果，避免重复查询
    ip_location_cache[ip_address] = location
    return location

def log_access(endpoint, extra_data=None):
    """记录用户访问"""
    try:
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
        
        # 获取IP地理位置（异步处理避免阻塞主请求）
        def get_location_async():
            location = get_ip_location(ip_address)
            # 更新已记录的日志条目
            for log in reversed(access_logs):
                if log.get('ip') == ip_address and 'location' not in log:
                    log['location'] = location
                    break
        
        log_entry = {
            'timestamp': (datetime.now() + pd.Timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S'),
            'ip': ip_address,
            'location': '查询中...',  # 先设置为查询中，异步更新
            'user_agent': request.headers.get('User-Agent', 'unknown'),
            'endpoint': endpoint,
            'method': request.method,
            'referer': request.headers.get('Referer', 'direct'),
            'extra_data': extra_data or {}
        }
        access_logs.append(log_entry)
        
        # 启动异步线程查询地理位置
        threading.Thread(target=get_location_async, daemon=True).start()
        
        # 只保留最近1000条记录
        if len(access_logs) > 1000:
            access_logs.pop(0)
            
        print(f"访问记录: {ip_address} -> {endpoint}")
    except Exception as e:
        print(f"记录访问日志失败: {e}")

def require_admin(f):
    """管理员验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_authenticated' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def schedule_cleanup(job_id, delay=3600):
    """安排在指定时间后清理临时文件和数据"""
    def cleanup():
        time.sleep(delay)
        if job_id in processing_results:
            result = processing_results[job_id]
            temp_dir = result.get('temp_dir')
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            processing_results.pop(job_id, None)
            print(f"Auto-cleaned job: {job_id}")
    
    threading.Thread(target=cleanup, daemon=True).start()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_pdf_file(file_path, results_list):
    """Process a single PDF file and return the new filename"""
    
    try:
        # Try OCR extraction first
        data = Extractor(file_path).extract()
        
        if data.empty or ("开票日期" not in data.columns and "价税合计(小写)" not in data.columns):
            raise ValueError("Not a standard invoice, OCR extraction failed.")
        
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
        
        # Instead of using GPT, rename as OCRError + number
        original_filename = os.path.basename(file_path)
        new_filename = f"OCRError_{original_filename}"
        
        # Store the failed result
        results_list.append({
            'original_filename': original_filename,
            'new_filename': new_filename,
            'date': 'N/A',
            'amount': 'N/A',
            'issuer': 'N/A',
            'status': 'failed',
            'method': 'OCR'
        })
        
        return new_filename

# ============ 主要路由 ============

@app.route('/')
def index():
    log_access('主页访问')
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_files():
    file_count = len(request.files.getlist('files'))
    log_access('文件上传', {'file_count': file_count})
    
    if 'files' not in request.files:
        return jsonify({'success': False, 'message': 'No files selected'})
    
    files = request.files.getlist('files')
    
    if not files or files[0].filename == '':
        return jsonify({'success': False, 'message': 'No files selected'})
    
    job_id = str(uuid.uuid4())
    temp_dir = tempfile.mkdtemp()
    processed_files = []
    results_list = []
    
    try:
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(temp_dir, filename)
                file.save(file_path)
                
                new_filename = process_pdf_file(file_path, results_list)
                new_file_path = os.path.join(temp_dir, new_filename)
                
                counter = 1
                while os.path.exists(new_file_path):
                    base, ext = os.path.splitext(new_filename)
                    new_filename = f"{base}_{counter}{ext}"
                    new_file_path = os.path.join(temp_dir, new_filename)
                    counter += 1
                
                shutil.move(file_path, new_file_path)
                processed_files.append(new_file_path)
        
        zip_path = os.path.join(temp_dir, 'processed_invoices.zip')
        with zipfile.ZipFile(zip_path, 'w') as zip_file:
            for file_path in processed_files:
                zip_file.write(file_path, os.path.basename(file_path))
        
        processing_results[job_id] = {
            'zip_path': zip_path,
            'temp_dir': temp_dir,
            'results': results_list,
            'timestamp': (datetime.now() + pd.Timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
        }
        
        schedule_cleanup(job_id)
        
        total_files = len(results_list)
        successful_files = len([r for r in results_list if r['status'] == 'success'])
        failed_files = total_files - successful_files
        
        return jsonify({
            'success': True,
            'job_id': job_id,
            'total_files': total_files,
            'successful_files': successful_files,
            'failed_files': failed_files,
            'message': f'Processing complete! {successful_files}/{total_files} files processed successfully.'
        })
        
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return jsonify({'success': False, 'message': f'Error processing files: {str(e)}'})

@app.route('/download/<job_id>')
def download_zip(job_id):
    log_access('文件下载', {'job_id': job_id})
    if job_id not in processing_results:
        flash('Processing results not found or expired')
        return redirect(url_for('index'))
    
    zip_path = processing_results[job_id]['zip_path']
    return send_file(zip_path, as_attachment=True, download_name='processed_invoices.zip')

@app.route('/report/<job_id>')
def view_report(job_id):
    log_access('查看报告', {'job_id': job_id})
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

# ============ 管理员功能 ============

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('密码错误')
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_authenticated', None)
    return redirect(url_for('index'))

@app.route('/admin')
@require_admin
def admin_dashboard():
    # 统计数据
    total_visits = len(access_logs)
    unique_ips = len(set(log['ip'] for log in access_logs))
    upload_count = len([log for log in access_logs if log['endpoint'] == '文件上传'])
    download_count = len([log for log in access_logs if log['endpoint'] == '文件下载'])
    
    # 地理位置统计
    location_stats = {}
    for log in access_logs:
        location = log.get('location', '未知')
        if location and location not in ['查询中...', '查询失败', 'API错误', '查询异常']:
            location_stats[location] = location_stats.get(location, 0) + 1
    
    # 获取最近50条记录，并确保地理位置已查询
    recent_logs = []
    for log in access_logs[-50:]:
        # 如果地理位置还在查询中，尝试立即查询一次
        if log.get('location') == '查询中...':
            log['location'] = get_ip_location(log['ip'])
        recent_logs.append(log)
    
    stats = {
        'total_visits': total_visits,
        'unique_ips': unique_ips,
        'upload_count': upload_count,
        'download_count': download_count,
        'total_jobs': len(processing_results),
        'top_locations': sorted(location_stats.items(), key=lambda x: x[1], reverse=True)[:5]  # 前5个地理位置
    }
    
    return render_template('admin_dashboard.html', 
                         logs=recent_logs, 
                         stats=stats)

@app.route('/admin/logs/export')
@require_admin
def export_logs():
    """导出访问日志为JSON文件"""
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
