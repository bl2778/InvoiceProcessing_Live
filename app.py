from flask import Flask, request, render_template, send_file, flash, redirect, url_for
import os
import zipfile
import tempfile
import shutil
from werkzeug.utils import secure_filename
import pandas as pd
from extractor import Extractor

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this!
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

ALLOWED_EXTENSIONS = {'pdf'}
ocr_error_counter = 1  # Global counter for OCR error files

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_pdf_file(file_path):
    """Process a single PDF file and return the new filename"""
    global ocr_error_counter
    
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
        return new_filename
        
    except Exception as e:
        print(f"OCR failed for {os.path.basename(file_path)}: {e}")
        
        # Instead of using GPT, rename as OCRError + number
        new_filename = f"OCRError{ocr_error_counter}.pdf"
        ocr_error_counter += 1
        return new_filename

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_files():
    global ocr_error_counter
    ocr_error_counter = 1  # Reset counter for each batch
    
    if 'files' not in request.files:
        flash('No files selected')
        return redirect(request.url)
    
    files = request.files.getlist('files')
    
    if not files or files[0].filename == '':
        flash('No files selected')
        return redirect(request.url)
    
    # Create temporary directory for processing
    temp_dir = tempfile.mkdtemp()
    processed_files = []
    
    try:
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(temp_dir, filename)
                file.save(file_path)
                
                # Process the file
                new_filename = process_pdf_file(file_path)
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
        
        return send_file(zip_path, as_attachment=True, download_name='processed_invoices.zip')
        
    except Exception as e:
        flash(f'Error processing files: {str(e)}')
        return redirect(url_for('index'))
    
    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
