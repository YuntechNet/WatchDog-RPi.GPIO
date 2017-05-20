import RPi.GPIO as GPIO
import subprocess, shlex, time, logging, sys, traceback, smtplib, ConfigParser, ast, os
from datetime import datetime
from email.message import Message 

setup_path = os.getcwd() + '/setup.conf'
config = ConfigParser.RawConfigParser()
config.read(setup_path)

log_path = os.getcwd() + config.get('main', 'log_path').replace('\'', '') + datetime.strftime(datetime.now(), '%Y-%m-%d_%H:%M:%S.%f') + '.log'
log_format = config.get('main', 'log_format')
logging.basicConfig(filename=log_path, format=log_format)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

mail_user = config.get('mail', 'user')
mail_passwd = config.get('mail', 'passwd')
mail_to = ast.literal_eval(config.get('mail', 'to'))

ips = ast.literal_eval(config.get('service', 'ips'))
pins = ast.literal_eval(config.get('service', 'pins'))

def mail(service):
    smtpserver = smtplib.SMTP('webmail.yuntech.edu.tw', 25)
    smtpserver.login(mail_user, mail_passwd)
    
    info  = ''
    info += ('Service: %s has been reboot for three times and all fail.' % (service))
    for index, send_to in enumerate(mail_to):
        message = Message()
        message['Subject'] = 'YunNet MIS: Service Failed Boot'
        message['From'] = mail_user
        message['To'] = send_to
        message.set_payload('Service: %s has been reboot for three times and all failed' % (service))
        smtpserver.sendmail(mail_user, send_to, message.as_string())
    smtpserver.quit()

check_local_net = subprocess.call(shlex.split("ping -c 1 8.8.8.8"), stdout=subprocess.PIPE)
if check_local_net != 0:
    loggin.info('Watch dog is not connecting to internet, quit scan procedure.')
    sys.exit(0)

for index, ip in enumerate(ips):
    boot_count = 0
    boot_exit_code = None
    logging.info('Service %d Start Scan on Ip: %s' % (index + 1, ip))
    while boot_exit_code != 0 and boot_count != 3:
        boot_count += 1
        try:
            cmd = "ping -c 1 %s" %(ip)
            boot_exit_code = subprocess.check_call(shlex.split(cmd), stdout=subprocess.PIPE)
            logging.info('Scan Exit Code: %d.' % (boot_exit_code))
        except:
            try:
                logging.info('Detected Service %d is offline.' % (index + 1))
                logging.info('Start re-boot procedure.')
                logging.info('... Configure GPIO settup.')
                GPIO.setwarnings(False)
                logging.info('... Setup GPIO mode.')
                GPIO.setmode(GPIO.BOARD)
                logging.info('... Pin %d setted to OUT.' % (pins[index]))
                GPIO.setup(pins[index], GPIO.OUT)
                logging.info('... Pin %d signal HIGH sended.' % (pins[index]))
                GPIO.output(pins[index], GPIO.HIGH)
                logging.info('... Maintaining sinal.')
                time.sleep(2)
                logging.info('... Pin %d sinal LOW sended.' % (pins[index]))
                GPIO.output(pins[index], GPIO.LOW)
                boot_exit_code = subprocess.check_call(shlex.split(cmd), stdout=subprocess.PIPE)
                logging.info('Service %d Booted.' % (index + 1))
            except:
                logging.error('\n%s' % (traceback.format_exc()))
                logging.error('Retry %d more times will announce admin.' % (3 - boot_count))
            finally:
                GPIO.cleanup()
        if boot_exit_code != 0 and boot_count == 3:
            mail(ip)
logging.info('[ blank ]')
