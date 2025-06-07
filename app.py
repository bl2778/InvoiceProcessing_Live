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

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'  # Change this!
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

ALLOWED_EXTENSIONS = {'pdf'}

# In-memory storage for processing results (in production, use a database)
processing_results = {}

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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_files():
    if 'files' not in request.files:
        return jsonify({'success': False, 'message': 'No files selected'})
    
    files = request.files.getlist('files')
    
    if not files or files[0].filename == '':
        return jsonify({'success': False, 'message': 'No files selected'})
    
    # Generate unique session ID for this processing job
    job_id = str(uuid.uuid4())
    
    # Create temporary directory for processing
    temp_dir = tempfile.mkdtemp()
    processed_files = []
    results_list = []
    
    try:
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(temp_dir, filename)
                file.save(file_path)
                
                # Process the file
                new_filename = process_pdf_file(file_path, results_list)
                new_file_path = os.path.join(temp_dir, new_filename)
                
                # Handle duplicate filenames
                counter = 1
                while os.path.exists(new_file_path):
                    base, ext = os.path.splitext(new_filename)
                    new_filename = f"{base}_{counter}{ext}"
                    new_file_path = os.path.join(temp_dir, new_filename)
                    counter += 1
                
                # Rename the processed file
                shutil.move(file_path, new_file_path)
                processed_files.append(new_file_path)
        
        # Create ZIP file
        zip_path = os.path.join(temp_dir, 'processed_invoices.zip')
        with zipfile.ZipFile(zip_path, 'w') as zip_file:
            for file_path in processed_files:
                zip_file.write(file_path, os.path.basename(file_path))
        
        # Store results and zip path
        processing_results[job_id] = {
            'zip_path': zip_path,
            'temp_dir': temp_dir,
            'results': results_list,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Calculate statistics
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
        # Clean up on error
        shutil.rmtree(temp_dir, ignore_errors=True)
        return jsonify({'success': False, 'message': f'Error processing files: {str(e)}'})

@app.route('/download/<job_id>')
def download_zip(job_id):
    if job_id not in processing_results:
        flash('Processing results not found or expired')
        return redirect(url_for('index'))
    
    zip_path = processing_results[job_id]['zip_path']
    return send_file(zip_path, as_attachment=True, download_name='processed_invoices.zip')


@app.route('/report/<job_id>')
def view_report(job_id):
    if job_id not in processing_results:
        flash('Processing results not found or expired')
        return redirect(url_for('index'))
    
    results = processing_results[job_id]['results']
    
    # Separate successful and failed results
    successful_results = [r for r in results if r['status'] == 'success']
    failed_results = [r for r in results if r['status'] == 'failed']
    
    # Function to convert Chinese date format to datetime for sorting
    def parse_chinese_date(date_str):
        try:
            if date_str == 'Error' or date_str == 'N/A':
                return datetime(9999, 12, 31)  # Put errors at the end
            
            # Extract year, month, day from format like "2024年3月15日"
            import re
            match = re.match(r'(\d{4})年(\d{1,2})月(\d{1,2})日', date_str)
            if match:
                year, month, day = match.groups()
                return datetime(int(year), int(month), int(day))
            else:
                return datetime(9999, 12, 31)  # Put unparseable dates at the end
        except:
            return datetime(9999, 12, 31)  # Put any parsing errors at the end
    
    # Sort successful results by parsed date
    try:
        successful_results.sort(key=lambda x: parse_chinese_date(x['date']))
    except:
        # If sorting fails, keep original order
        pass
    
    # Combine: successful first (sorted by date), then failed
    sorted_results = successful_results + failed_results
    
    return render_template('report.html', 
                         results=sorted_results, 
                         timestamp=processing_results[job_id]['timestamp'],
                         job_id=job_id)


if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
