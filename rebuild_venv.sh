cd ~/www/python/
rm -rf venv
python3.7 -m virtualenv -p /usr/bin/python3.7 venv
source ~/www/python/venv/bin/activate
pip install -r ~/www/python/src/requirements.txt
