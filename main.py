import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

def get_ip_from_domain(target):
    """แปลง domain เป็น IP"""
    try:
        ip = socket.gethostbyname(target)
        print(f"✓ Domain: {target} → IP: {ip}")
        return ip
    except socket.gaierror:
        # ถ้าเป็น IP อยู่แล้วให้ใช้เลย
        try:
            socket.inet_aton(target)
            return target
        except:
            print(f"❌ ไม่สามารถแปลง domain: {target}")
            return None

def scan_tcp_port(ip, port, timeout=1):
    """สแกน TCP port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def scan_udp_port(ip, port, timeout=1):
    """สแกน UDP port (ตรวจสอบแบบพื้นฐาน)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b'', (ip, port))
        try:
            data, addr = sock.recvfrom(1024)
            sock.close()
            return True
        except socket.timeout:
            sock.close()
            return True  # UDP อาจเปิดแต่ไม่ตอบกลับ
        except:
            sock.close()
            return False
    except:
        return False

def get_service_name(port, protocol='tcp'):
    """ดึงชื่อ service จาก port"""
    try:
        return socket.getservbyport(port, protocol)
    except:
        # Common services
        common_services = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
            587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
        return common_services.get(port, 'Unknown')

def scan_all_ports(ip, start_port=1, end_port=1024, protocol='tcp', max_workers=100):
    """สแกนทุก port ในช่วงที่กำหนด"""
    open_ports = []
    total_ports = end_port - start_port + 1
    scanned = 0
    
    print(f"\n🔍 กำลังสแกน {protocol.upper()} ports {start_port}-{end_port}...")
    print(f"Target: {ip}")
    print("-" * 70)
    
    scan_func = scan_tcp_port if protocol == 'tcp' else scan_udp_port
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_func, ip, port): port 
            for port in range(start_port, end_port + 1)
        }
        
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            scanned += 1
            
            # แสดง progress
            if scanned % 100 == 0 or scanned == total_ports:
                progress = (scanned / total_ports) * 100
                print(f"Progress: {progress:.1f}% ({scanned}/{total_ports})", end='\r')
            
            try:
                if future.result():
                    service = get_service_name(port, protocol)
                    open_ports.append((port, service))
                    print(f"\n✓ Port {port:5d}/{protocol.upper():3s} เปิด → {service}")
            except Exception as e:
                pass
    
    print("\n" + "-" * 70)
    return sorted(open_ports)

def full_scan(target, scan_common=True, scan_all=False):
    """สแกนแบบเต็มรูปแบบ"""
    print("=" * 70)
    print(f"    PORT SCANNER - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    # แปลง domain เป็น IP
    ip = get_ip_from_domain(target)
    if not ip:
        return
    
    all_open_ports = []
    
    if scan_common:
        # สแกน common ports ก่อน (เร็วกว่า)
        common_ports = [
            20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587,
            993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
        ]
        
        print(f"\n📋 [1] สแกน Common TCP Ports ({len(common_ports)} ports)")
        print("-" * 70)
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {
                executor.submit(scan_tcp_port, ip, port): port 
                for port in common_ports
            }
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                if future.result():
                    service = get_service_name(port, 'tcp')
                    all_open_ports.append(('tcp', port, service))
                    print(f"✓ Port {port:5d}/TCP เปิด → {service}")
    
    if scan_all:
        # สแกนทุก TCP port (1-65535)
        print(f"\n📋 [2] สแกนทุก TCP Ports (1-65535)")
        tcp_ports = scan_all_ports(ip, 1, 65535, 'tcp', max_workers=200)
        for port, service in tcp_ports:
            all_open_ports.append(('tcp', port, service))
        
        # สแกน UDP ports ที่สำคัญ
        print(f"\n📋 [3] สแกน Common UDP Ports")
        udp_common = [53, 67, 68, 69, 123, 161, 162, 514]
        udp_ports = scan_all_ports(ip, min(udp_common), max(udp_common), 'udp', max_workers=20)
        for port, service in udp_ports:
            all_open_ports.append(('udp', port, service))
    
    # สรุปผล
    print("\n" + "=" * 70)
    print("📊 สรุปผลการสแกน")
    print("=" * 70)
    print(f"Target: {target} ({ip})")
    print(f"เวลาที่สแกน: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\nพบ Ports ที่เปิด: {len(all_open_ports)} ports")
    print("-" * 70)
    
    if all_open_ports:
        print(f"{'Protocol':<10} {'Port':<10} {'Service':<20}")
        print("-" * 70)
        for protocol, port, service in sorted(all_open_ports, key=lambda x: x[1]):
            print(f"{protocol.upper():<10} {port:<10} {service:<20}")
    else:
        print("❌ ไม่พบ ports ที่เปิด")
    
    print("=" * 70)

# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    print("\n🔐 โปรแกรมสแกน Port")
    print("=" * 70)
    
    # รับ input จากผู้ใช้
    target = input("ใส่ Domain หรือ IP ที่ต้องการสแกน: ").strip()
    
    if not target:
        print("❌ กรุณาใส่ target")
        sys.exit(1)
    
    print("\nเลือกโหมดการสแกน:")
    print("[1] สแกนแค่ Common Ports (เร็ว)")
    print("[2] สแกนทุก Ports 1-65535 (ช้า, ใช้เวลานาน)")
    
    choice = input("\nเลือก (1/2): ").strip()
    
    if choice == "1":
        full_scan(target, scan_common=True, scan_all=False)
    elif choice == "2":
        print("\n⚠️  การสแกนทุก ports จะใช้เวลานาน (5-30 นาที)")
        confirm = input("ต้องการดำเนินการต่อ? (y/n): ").strip().lower()
        if confirm == 'y':
            full_scan(target, scan_common=False, scan_all=True)
        else:
            print("ยกเลิกการสแกน")
    else:
        print("❌ ตัวเลือกไม่ถูกต้อง")