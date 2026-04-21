content = open('config_loader.py', encoding='utf-8').read()
content = content.replace("version=eng.get('version', '4.0.0')", "version=eng.get('version', '4.1.0')")
open('config_loader.py', 'w', encoding='utf-8').write(content)
print('done')
