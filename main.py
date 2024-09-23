from scapy.all import sniff, IP, TCP
import smtplib
import logging

# logging
logging.basicConfig(filename='ids_logs.log', level=logging.INFO, format='%(asctime)s - %(message)s')

SIGNATURES = {
	'port_scan': {
		'desc': 'Possible Port Scan'
		'tcp_flags': 'S'
	}
}

# проверка на соответствие
def detect_attack(packet):
	# TCP пакеты
	tcp_flags = packet.sprintf('%TCP.flags%')
	src_ip = packet[IP].src
	dst_ip = packet[IP].dst
	dst_port = packet[TCP].dport

	if tcp_flags == SIGNATURES['port_scan']['tcp_flags']:
		logging.info(f"ALERT: {SIGNATURES['port_scan']['desc']} detected from {src_ip} to {dst_ip}:{dst_port}")
		send_alert_email(src_ip, dst_ip, dst_port)


# email alert
def send_alert_email(src_ip, dst_ip, dst_port):
	sender = 'email@smth.com'
	recipient = 'admin@smth.com'
	subject = 'Обнаружена возможная атака'
	body = f"Обнаружена подозрительная активность от {src_ip} на {dst_ip}:{dst_port}"

	message = f"Тема: {subject}\n\n{body}"

	try:
		with smtplib.SMTP('smtp.gmail.com', 587) as server:
			server.starttls()
			server.login(sender, 'password')
			server.sendmail(sender, recipient, message)
			logging.info('Alert email send successfully')
	except Exception as e:
		logging.error(f'Failed to send alert email: {e}')


# перехват и анализ
def start_sniffing():
	sniff(filter='tcp', prn=detect_attack, store=0)

if __name__ == '__main__':
	print("Starting IDS")
	start_sniffing()