#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time
import base64
import shutil
import logging
import requests
import datetime
import sys

# Check for required dependencies
try:
    from tencentcloud.common import credential
    from tencentcloud.common.profile.client_profile import ClientProfile
    from tencentcloud.common.profile.http_profile import HttpProfile
    from tencentcloud.ssl.v20191205 import ssl_client, models
except ImportError:
    print("Error: Required Tencent Cloud SDK not found. Please install it using:")
    print("pip install tencentcloud-sdk-python")
    sys.exit(1)

try:
    import OpenSSL.crypto
except ImportError:
    print("Warning: pyOpenSSL not found. Certificate expiration checking will be disabled.")
    print("To enable it, install using: pip install pyOpenSSL")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ssl_cert_auto.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
SECRET_ID = ""  # Replace with your Tencent Cloud Secret ID
SECRET_KEY = ""  # Replace with your Tencent Cloud Secret Key

def apply_certificate(client, domain_name):
    """Apply for a free SSL certificate."""
    try:
        # Create request object
        req = models.ApplyCertificateRequest()
        
        # Set domain name for certificate
        params = {
            "DomainName": domain_name,
            "CertificateType": "2",  # DV SSL Certificate (Free)
            "ProductId": 11,         # Free certificate product ID
            "DomainValidateType": "DNS_AUTO",  # DNS validation
            "DvAuthMethod": "DNS_AUTO"  # Added missing required parameter
        }
        
        req.from_json_string(json.dumps(params))
        
        # Apply for certificate
        logger.info(f"Applying for certificate for {domain_name}")
        response = client.ApplyCertificate(req)
        
        return response
    except Exception as e:
        logger.error(f"Error applying for certificate: {str(e)}")
        raise

def check_certificate_status(client, certificate_id):
    """Check the status of a certificate application."""
    try:
        req = models.DescribeCertificateRequest()
        params = {"CertificateId": certificate_id}
        req.from_json_string(json.dumps(params))
        
        response = client.DescribeCertificate(req)
        return response
    except Exception as e:
        logger.error(f"Error checking certificate status: {str(e)}")
        raise

def download_certificate(client, certificate_id):
    """Download certificate and private key."""
    try:
        req = models.DownloadCertificateRequest()
        params = {"CertificateId": certificate_id}
        req.from_json_string(json.dumps(params))
        
        # Get the certificate package
        response = client.DownloadCertificate(req)
        
        # The response contains a base64 encoded ZIP file
        if hasattr(response, "Content") and response.Content:
            # Decode base64 content to get the ZIP file
            try:
                import base64
                import zipfile
                import io
                
                # Decode the base64 content
                zip_data = base64.b64decode(response.Content)
                
                # Create a BytesIO object from the decoded data
                zip_buffer = io.BytesIO(zip_data)
                
                # Extract certificate files from the ZIP file
                cert_files = {
                    'cert': None,  # For bundle.crt
                    'key': None,   # For .key
                    'pem': None,   # For bundle.pem
                    'csr': None    # For .csr
                }
                
                with zipfile.ZipFile(zip_buffer, 'r') as zip_file:
                    file_list = zip_file.namelist()
                    logger.info(f"Files in certificate ZIP: {file_list}")
                    
                    # Look for Nginx certificate files specifically
                    nginx_cert = None
                    nginx_key = None
                    csr_file = None
                    pem_file = None
                    
                    for file_name in file_list:
                        # Get Nginx bundle certificate
                        if 'Nginx/' in file_name and '_bundle.crt' in file_name:
                            nginx_cert = file_name
                        
                        # Get Nginx key file
                        elif 'Nginx/' in file_name and file_name.endswith('.key'):
                            nginx_key = file_name
                        
                        # Get CSR file
                        elif file_name.endswith('.csr'):
                            csr_file = file_name
                        
                        # Get PEM file
                        elif file_name.endswith('.pem'):
                            pem_file = file_name
                    
                    # Extract the files as binary data
                    if nginx_cert:
                        cert_files['cert'] = zip_file.read(nginx_cert)
                    
                    if nginx_key:
                        cert_files['key'] = zip_file.read(nginx_key)
                    
                    if csr_file:
                        cert_files['csr'] = zip_file.read(csr_file)
                    
                    if pem_file:
                        cert_files['pem'] = zip_file.read(pem_file)
                    
                    # If we couldn't find Nginx specific files, try to use alternatives
                    if not cert_files['cert']:
                        for file_name in file_list:
                            if file_name.endswith('.crt') and 'bundle' in file_name:
                                cert_files['cert'] = zip_file.read(file_name)
                                break
                    
                    if not cert_files['key'] and not nginx_key:
                        for file_name in file_list:
                            if file_name.endswith('.key'):
                                cert_files['key'] = zip_file.read(file_name)
                                break
                
                # Check if we have the minimum required files
                if cert_files['cert'] and cert_files['key']:
                    return cert_files
                else:
                    logger.error(f"Could not find required certificate files in the ZIP package")
                    return None
            except Exception as e:
                logger.error(f"Error extracting certificate from ZIP: {str(e)}")
                return None
        else:
            logger.error("No content in download certificate response")
            return None
    except Exception as e:
        logger.error(f"Error downloading certificate: {str(e)}")
        return None

def complete_certificate_verification(client, certificate_id):
    """Complete the certificate verification process."""
    try:
        req = models.CompleteCertificateRequest()
        params = {"CertificateId": certificate_id}
        req.from_json_string(json.dumps(params))
        
        response = client.CompleteCertificate(req)
        logger.info(f"Certificate verification completion triggered: {response}")
        return response
    except Exception as e:
        logger.error(f"Error completing certificate verification: {str(e)}")
        # Don't raise the exception, as this is an optional step
        return None

def get_dns_verification_details(client, certificate_id):
    """Get DNS verification details for a certificate."""
    try:
        req = models.DescribeCertificateRequest()
        params = {"CertificateId": certificate_id}
        req.from_json_string(json.dumps(params))
        
        response = client.DescribeCertificate(req)
        
        if hasattr(response, 'DvAuthDetail') and response.DvAuthDetail:
            auth_detail = response.DvAuthDetail
            if hasattr(auth_detail, 'DvAuthKey') and hasattr(auth_detail, 'DvAuthValue'):
                return {
                    'domain': auth_detail.DvAuthDomain if hasattr(auth_detail, 'DvAuthDomain') else None,
                    'key': auth_detail.DvAuthKey,
                    'value': auth_detail.DvAuthValue,
                    'type': 'TXT'
                }
        
        return None
    except Exception as e:
        logger.error(f"Error getting DNS verification details: {str(e)}")
        return None

def check_local_certificates(domain_info):
    """Check if certificates already exist in the specified paths."""
    cert_path = domain_info["cert_path"]
    key_path = domain_info["key_path"]
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        # Check certificate expiration
        try:
            with open(cert_path, 'rb') as f:  # Changed to binary mode
                cert_data = f.read()
            
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)
            expiry_date = datetime.datetime.strptime(
                cert.get_notAfter().decode('ascii'), 
                '%Y%m%d%H%M%SZ'
            )
            
            # Check if certificate is still valid for at least 30 days
            if expiry_date > datetime.datetime.now() + datetime.timedelta(days=30):
                logger.info(f"Existing certificate for {domain_info['domain']} is still valid until {expiry_date.strftime('%Y-%m-%d %H:%M:%S')}")
                return True
            else:
                logger.info(f"Certificate for {domain_info['domain']} expires soon: {expiry_date.strftime('%Y-%m-%d %H:%M:%S')}, will renew")
                return False
        except Exception as e:
            logger.warning(f"Error checking existing certificate: {str(e)}")
    
    return False

def check_existing_certificates(client, domain_name):
    """Check if certificates already exist in Tencent Cloud."""
    try:
        # 尝试不同的搜索方式
        search_methods = [
            {"SearchKey": domain_name},  # 精确搜索域名
            {"SearchKey": domain_name.split(".", 1)[1] if "." in domain_name else domain_name},  # 搜索主域名
            {}  # 不使用搜索条件，获取所有证书
        ]
        
        certificates = []
        
        for i, search_params in enumerate(search_methods):
            logger.info(f"Trying search method {i+1} for {domain_name}")
            
            # 添加通用参数
            search_params.update({
                "CertificateType": "2",  # DV SSL证书
                "Limit": 100  # 获取更多证书
            })
            
            req = models.DescribeCertificatesRequest()
            req.from_json_string(json.dumps(search_params))
            
            try:
                response = client.DescribeCertificates(req)
                
                if hasattr(response, 'Certificates') and response.Certificates:
                    logger.info(f"Search method {i+1}: Found {len(response.Certificates)} certificates")
                    
                    # 打印原始响应以进行调试
                    try:
                        logger.info(f"Raw response: {response}")
                    except:
                        logger.info("Could not log raw response")
                    
                    for cert in response.Certificates:
                        # 获取证书属性
                        cert_id = getattr(cert, 'CertificateId', 'Unknown')
                        cert_domain = getattr(cert, 'Domain', '')
                        alt_names = getattr(cert, 'SubjectAltName', '')
                        status = getattr(cert, 'Status', None)
                        status_name = getattr(cert, 'StatusName', '')
                        
                        # 打印证书详细信息
                        logger.info(f"Certificate ID: {cert_id}, Domain: {cert_domain}, Status: {status}({status_name}), AltNames: {alt_names}")
                        
                        # 获取证书的所有属性
                        cert_attrs = dir(cert)
                        logger.info(f"Certificate attributes: {cert_attrs}")
                        
                        # 检查域名是否匹配
                        domain_match = False
                        
                        # 精确匹配
                        if cert_domain == domain_name:
                            domain_match = True
                            logger.info(f"Exact domain match: {domain_name} == {cert_domain}")
                        
                        # 子域名匹配
                        elif domain_name.endswith('.' + cert_domain):
                            domain_match = True
                            logger.info(f"Subdomain match: {domain_name} is subdomain of {cert_domain}")
                        
                        # 通配符匹配
                        elif alt_names:
                            alt_names_list = alt_names.split(',')
                            for alt in alt_names_list:
                                alt = alt.strip()
                                if alt == domain_name:
                                    domain_match = True
                                    logger.info(f"Alt name exact match: {domain_name} == {alt}")
                                    break
                                elif alt.startswith('*.') and domain_name.endswith(alt[2:]):
                                    domain_match = True
                                    logger.info(f"Wildcard match: {domain_name} matches {alt}")
                                    break
                        
                        if domain_match:
                            logger.info(f"Adding certificate {cert_id} to matches for {domain_name}")
                            certificates.append(cert)
                            # 不立即退出，继续收集所有匹配的证书
                else:
                    logger.info(f"Search method {i+1}: No certificates found")
            except Exception as e:
                logger.warning(f"Error in search method {i+1}: {str(e)}")
        
        logger.info(f"Total matching certificates found: {len(certificates)}")
        return certificates
    except Exception as e:
        logger.warning(f"Error checking existing certificates: {str(e)}")
        return []

def wait_for_dns_verification(client, certificate_id, timeout_seconds):
    """Wait for DNS verification to complete."""
    start_time = time.time()
    check_interval = 20  # seconds
    
    while time.time() - start_time < timeout_seconds:
        try:
            status_response = check_certificate_status(client, certificate_id)
            status = getattr(status_response, 'Status', '')
            status_name = getattr(status_response, 'StatusName', '')
            
            logger.info(f"Certificate status: {status} ({status_name})")
            
            # Check if verification is complete
            if status == 1 or status_name == "已颁发" or status_name == "issued":
                logger.info("DNS verification completed successfully")
                return True
                
            # If still waiting for verification, wait and check again
            time.sleep(check_interval)
        except Exception as e:
            logger.warning(f"Error checking DNS verification status: {str(e)}")
            time.sleep(check_interval)
    
    return False

def wait_for_certificate_issuance(client, certificate_id, timeout_seconds):
    """Wait for certificate to be issued."""
    start_time = time.time()
    check_interval = 10  # seconds
    
    while time.time() - start_time < timeout_seconds:
        try:
            status_response = check_certificate_status(client, certificate_id)
            status = getattr(status_response, 'Status', '')
            status_name = getattr(status_response, 'StatusName', '')
            
            logger.info(f"Certificate issuance status: {status} ({status_name})")
            
            # Check if certificate is issued
            if status == 1 or status_name == "已颁发" or status_name == "issued":
                logger.info("Certificate has been issued successfully")
                return True
                
            # If still waiting for issuance, wait and check again
            time.sleep(check_interval)
        except Exception as e:
            logger.warning(f"Error checking certificate issuance status: {str(e)}")
            time.sleep(check_interval)
    
    return False

def process_domain(client, domain_info):
    """Process a domain to obtain and install its certificate."""
    domain_name = domain_info["domain"]
    cert_dir = domain_info["cert_dir"]
    cert_path = domain_info["cert_path"]
    key_path = domain_info["key_path"]
    pem_path = domain_info.get("pem_path")
    csr_path = domain_info.get("csr_path")
    
    logger.info(f"Processing domain: {domain_name}")
    
    # Flag to track if we need to apply for a new certificate
    need_new_certificate = True
    
    # First check if local certificates are valid
    if check_local_certificates(domain_info):
        logger.info(f"Valid local certificate found for {domain_name}. Skipping renewal.")
        return True
    else:
        logger.info(f"No valid local certificate found for {domain_name}. Will check Tencent Cloud.")
    
    # If local certificates aren't valid, check Tencent Cloud for valid certificates
    try:
        # 尝试检查腾讯云上的证书
        existing_certificates = check_existing_certificates(client, domain_name)
        valid_cert = None
        
        logger.info(f"Found {len(existing_certificates)} matching certificates for {domain_name} in Tencent Cloud")
        
        # Find a valid certificate with more than 30 days remaining
        for cert in existing_certificates:
            # 检查证书状态，1表示已颁发
            cert_status = None
            cert_id = getattr(cert, 'CertificateId', 'Unknown')
            
            # 尝试获取Status属性
            if hasattr(cert, 'Status'):
                cert_status = cert.Status
                logger.info(f"Certificate {cert_id} has Status: {cert_status}")
            # 如果没有Status属性，尝试检查StatusName
            elif hasattr(cert, 'StatusName'):
                status_name = cert.StatusName
                cert_status = 1 if status_name in ["已颁发", "issued"] else 0
                logger.info(f"Certificate {cert_id} has StatusName: {status_name}, interpreted as Status: {cert_status}")
            else:
                logger.info(f"Certificate {cert_id} has no status information")
            
            if cert_status == 1:  # 1 means issued
                # 确保CertEndTime属性存在
                if hasattr(cert, 'CertEndTime'):
                    try:
                        expiry_date = datetime.datetime.strptime(cert.CertEndTime, "%Y-%m-%d %H:%M:%S")
                        now = datetime.datetime.now()
                        days_remaining = (expiry_date - now).days
                        
                        logger.info(f"Found existing certificate {cert_id} for {domain_name}, valid until {expiry_date} ({days_remaining} days remaining)")
                        
                        # Check if certificate is still valid for at least 30 days
                        if days_remaining > 30:
                            valid_cert = cert
                            logger.info(f"Certificate {cert_id} for {domain_name} is still valid for more than 30 days. Will use existing certificate.")
                            break
                        else:
                            logger.info(f"Certificate {cert_id} for {domain_name} expires in {days_remaining} days. Will need renewal.")
                    except Exception as e:
                        logger.warning(f"Error parsing expiry date for certificate {cert_id}: {str(e)}")
                else:
                    logger.warning(f"Certificate {cert_id} for {domain_name} is missing expiry date information")
        
        # If we have a valid certificate, download and use it
        if valid_cert:
            cert_id = getattr(valid_cert, 'CertificateId', 'Unknown')
            logger.info(f"Downloading valid certificate {cert_id} from Tencent Cloud for {domain_name}")
            certificate_files = download_certificate(client, valid_cert.CertificateId)
            if certificate_files:
                # Ensure directory exists
                os.makedirs(cert_dir, exist_ok=True)
                
                # Save certificate files in binary mode
                with open(cert_path, 'wb') as f:
                    f.write(certificate_files["cert"])
                with open(key_path, 'wb') as f:
                    f.write(certificate_files["key"])
                
                # Save additional files if paths are provided
                if pem_path and certificate_files.get("pem"):
                    with open(pem_path, 'wb') as f:
                        f.write(certificate_files["pem"])
                
                if csr_path and certificate_files.get("csr"):
                    with open(csr_path, 'wb') as f:
                        f.write(certificate_files["csr"])
                
                logger.info(f"Successfully installed existing certificate from Tencent Cloud for {domain_name}")
                need_new_certificate = False
            else:
                logger.error(f"Failed to download existing certificate {cert_id} for {domain_name}. Will try to apply for a new one.")
        else:
            logger.info(f"No valid certificate found in Tencent Cloud for {domain_name}. Will apply for a new one.")
    except Exception as e:
        logger.warning(f"Error checking existing certificates: {str(e)}")
    
    # If we still need a new certificate, apply for one
    if need_new_certificate:
        logger.info(f"Applying for new certificate for {domain_name}")
        
        try:
            response = apply_certificate(client, domain_name)
            certificate_id = response.CertificateId
            logger.info(f"Successfully applied for certificate for {domain_name}, ID: {certificate_id}")
            
            # Get DNS verification details
            dns_details = get_dns_verification_details(client, certificate_id)
            if dns_details:
                logger.info(f"DNS verification required for {domain_name}:")
                logger.info(f"Add TXT record: {dns_details['domain']} with value: {dns_details['value']}")
                
                # Wait for DNS verification to complete
                if wait_for_dns_verification(client, certificate_id, 86400):  # 10 minutes timeout
                    # Complete the verification process
                    complete_certificate_verification(client, certificate_id)
                    
                    # Wait for certificate issuance
                    if wait_for_certificate_issuance(client, certificate_id, 300):  # 5 minutes timeout
                        # Download and install the certificate
                        certificate_files = download_certificate(client, certificate_id)
                        if certificate_files:
                            # Ensure directory exists
                            os.makedirs(cert_dir, exist_ok=True)
                            
                            # Save certificate files in binary mode
                            with open(cert_path, 'wb') as f:
                                f.write(certificate_files["cert"])
                            with open(key_path, 'wb') as f:
                                f.write(certificate_files["key"])
                            
                            # Save additional files if paths are provided
                            if pem_path and certificate_files.get("pem"):
                                with open(pem_path, 'wb') as f:
                                    f.write(certificate_files["pem"])
                            
                            if csr_path and certificate_files.get("csr"):
                                with open(csr_path, 'wb') as f:
                                    f.write(certificate_files["csr"])
                            
                            logger.info(f"Successfully installed new certificate for {domain_name}")
                            return True
                        else:
                            logger.error(f"Failed to download new certificate for {domain_name}")
                            return False
                else:
                    logger.error(f"DNS verification timed out for {domain_name}")
                    return False
            else:
                logger.error(f"Failed to get DNS verification details for {domain_name}")
                return False
        except Exception as e:
            logger.error(f"Error processing domain {domain_name}: {str(e)}")
            return False
    
    return not need_new_certificate  # Return True if we didn't need a new certificate

def reload_nginx():
    """Attempt to reload Nginx using various methods."""
    try:
        # Try different methods to reload Nginx
        methods = [
            "/path/to/nginx/binary -t && /path/to/nginx/binary -s reload"  # Replace with your Nginx path
        ]
        
        for method in methods:
            logger.info(f"Attempting to reload Nginx using: {method}")
            result = os.system(method)
            if result == 0:
                logger.info(f"Nginx reloaded successfully using: {method}")
                return True
        
        logger.warning("All Nginx reload methods failed")
        return False
    except Exception as e:
        logger.error(f"Error reloading Nginx: {str(e)}")
        return False

def main():
    """Main function to obtain and install certificates."""
    logger.info("Starting automatic SSL certificate renewal process")
    
    # Initialize Tencent Cloud client
    cred = credential.Credential(SECRET_ID, SECRET_KEY)
    http_profile = HttpProfile()
    http_profile.endpoint = "ssl.tencentcloudapi.com"
    
    client_profile = ClientProfile()
    client_profile.httpProfile = http_profile
    client = ssl_client.SslClient(cred, "your-region-here")  # Replace with your region
    
    # Define domains and certificate paths with the correct directory structure
    domains = [
        {
            "domain": "example.com",
            "cert_dir": "/etc/nginx/ssl/example.com_nginx",
            "cert_path": "/etc/nginx/ssl/example.com_nginx/example.com_bundle.crt",
            "key_path": "/etc/nginx/ssl/example.com_nginx/example.com.key",
            "pem_path": "/etc/nginx/ssl/example.com_nginx/example.com_bundle.pem",
            "csr_path": "/etc/nginx/ssl/example.com_nginx/example.com.csr"
        },
        {
            "domain": "blog.example.com",
            "cert_dir": "/etc/nginx/ssl/blog.example.com_nginx",
            "cert_path": "/etc/nginx/ssl/blog.example.com_nginx/blog.example.com_bundle.crt",
            "key_path": "/etc/nginx/ssl/blog.example.com_nginx/blog.example.com.key",
            "pem_path": "/etc/nginx/ssl/blog.example.com_nginx/blog.example.com_bundle.pem",
            "csr_path": "/etc/nginx/ssl/blog.example.com_nginx/blog.example.com.csr"
        },
        {
            "domain": "api.example.com",
            "cert_dir": "/etc/nginx/ssl/api.example.com_nginx",
            "cert_path": "/etc/nginx/ssl/api.example.com_nginx/api.example.com_bundle.crt",
            "key_path": "/etc/nginx/ssl/api.example.com_nginx/api.example.com.key",
            "pem_path": "/etc/nginx/ssl/api.example.com_nginx/api.example.com_bundle.pem",
            "csr_path": "/etc/nginx/ssl/api.example.com_nginx/api.example.com.csr"
        }
    ]
    
    # Process each domain
    updated_domains = []
    has_errors = False
    
    for domain_info in domains:
        try:
            success = process_domain(client, domain_info)
            if success:
                updated_domains.append(domain_info["domain"])
        except Exception as e:
            logger.error(f"Error processing domain {domain_info['domain']}: {str(e)}")
            has_errors = True
    
    # Reload Nginx if any certificates were updated
    if updated_domains:
        logger.info(f"Updated certificates for domains: {', '.join(updated_domains)}")
        if not reload_nginx():
            logger.warning("Failed to reload Nginx. You may need to reload it manually.")
            has_errors = True
    else:
        logger.info("No certificates were updated, no need to reload Nginx")
    
    if has_errors:
        logger.error("Certificate renewal process completed with errors")
    else:
        logger.info("Certificate renewal process completed successfully")

if __name__ == "__main__":
    main() 