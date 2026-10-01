### Creating the Service for the server

```bash
useradd -m -s /bin/bash vaultuser

cd /home/vaultuser/password-manager
python3 -m venv .venv
source .venv/bin/activate
pip install -r server/requirements.txt

nano /etc/systemd/system/vault.service
```

```TOML
[Unit]
Description=Gunicorn instance to serve the Vault API
After=network.target

[Service]
User=vaultuser
Group=www-data
WorkingDirectory=/home/vaultuser/password-manager/server
Environment="PATH=/home/vaultuser/password-manager/.venv/bin"

# Gunicorn runs the app using Uvicorn workers for async support.
# -w 2: Two workers handles concurrent requests.
# -b 127.0.0.1:8000: Binds strictly to localhost for Nginx to proxy.
ExecStart=/home/vaultuser/PasswordManager/.venv/bin/gunicorn main:app -w 2 -k uvicorn.workers.UvicornWorker -b 127.0.0.1:8000

# Restart behavior
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
# Give vaultuser ownership over the directory
chown -R vaultuser:vaultuser /home/vaultuser/password-manager

systemctl daemon-reload
systemctl start vault
systemctl enable vault

systemctl status vault
```

### Adding nginx reverse Proxy to the server
```bash
apt update && apt install nginx -yqq

nano /etc/nginx/sites-available/vault
```
#### Write the configuration
```
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Enable and clean up
```bash
# Delete the default site link
rm /etc/nginx/sites-enabled/default

# Link your new vault configuration to enable it
ln -s /etc/nginx/sites-available/vault /etc/nginx/sites-enabled/

# Test the configuration's syntax
nginx -t

systemctl restart nginx
```
